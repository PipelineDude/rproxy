//! End-to-end tests against the real rproxy binary, real backends, and real sockets. These fill
//! the gap unit tests structurally can't: `proxy_l7_core`, `main.rs`'s prefork/supervisor loop and
//! `health.rs` (a separate forked process) all take a live socket and cannot run under a plain
//! `#[test]`. Several scenarios here are regression tests for specific bugs found during
//! hardening: a path-ACL bypass via un-normalized targets, an upstream-TLS cleartext leak on
//! `https://` backends, a partial-read bug on segmented request headers, and a stale pooled
//! backend connection retried instead of discarded.
//!
//! Ignored by default -- run explicitly:
//!   cargo test --release -- --ignored
//!
//! Each test binds its backend and its rproxy instance on dynamically chosen ports (`:0`) so
//! tests can run in parallel and never collide with each other, a fixed dev port, or the system
//! nginx that already squats :8082 on this box.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Reserve an ephemeral port by binding `:0` and dropping the listener. There is an inherent,
/// small TOCTOU race between this drop and rproxy's own bind; acceptable for a test harness (the
/// ephemeral port range is large and short-lived collisions are a rerun, not a design problem).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn unique_path(name: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("rproxy_e2e_{}_{}_{}", std::process::id(), id, name))
}

/// Kills rproxy's entire process group (master + every prefork worker) on drop, so a panicking
/// assertion still cleans up. `Child::kill()` alone only kills the master -- the forked workers
/// (spawned via `nix::unistd::fork`, not tracked by `std::process::Child`) would survive as
/// orphans holding the listen port, breaking every subsequent test run in a way that looks
/// unrelated to whatever actually failed.
struct RproxyGuard {
    child: Child,
    config_path: std::path::PathBuf,
}

impl Drop for RproxyGuard {
    fn drop(&mut self) {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        // Negative PID = whole process group (POSIX kill(2)). rproxy's master is the group
        // leader (spawned with process_group(0) below), so one call reaches every forked worker.
        let _ = kill(Pid::from_raw(-(self.child.id() as i32)), Signal::SIGKILL);
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config_path);
    }
}

fn spawn_rproxy(config_path: &std::path::Path) -> RproxyGuard {
    let bin = env!("CARGO_BIN_EXE_rproxy");
    let child = Command::new(bin)
        .arg("-c")
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0) // new process group, led by the master -- see RproxyGuard::drop
        .spawn()
        .expect("failed to spawn rproxy");
    RproxyGuard {
        child,
        config_path: config_path.to_path_buf(),
    }
}

fn wait_until_listening(addr: &str, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("rproxy never started listening on {addr} within {timeout:?}");
}

/// Read whatever is available until EOF or `timeout` elapses, without requiring the peer to
/// close cleanly first (a raw `read_to_end` would discard bytes already read on a timeout error).
fn read_available(stream: &mut TcpStream, timeout: Duration) -> Vec<u8> {
    stream.set_read_timeout(Some(timeout)).unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => break, // WouldBlock/TimedOut -- whatever we have so far is the answer
        }
    }
    out
}

/// Connect and send `segments` as separate `write()` calls with a short delay between each, to
/// discourage the kernel from coalescing them into a single `read()` on the server side -- the
/// mechanism a slow client or IP fragmentation produces in the wild, and the exact surface a
/// prior partial-read parsing bug lived on.
fn send_segmented(addr: &str, segments: &[&[u8]], read_timeout: Duration) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    for seg in segments {
        stream.write_all(seg).unwrap();
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(30));
    }
    read_available(&mut stream, read_timeout)
}

fn status_code(response: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(response);
    let line = text.lines().next()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// A backend that records the raw bytes of every connection it accepts (so tests can assert on
/// what did/didn't reach it -- e.g. proving the TLS-backend fix never lets a parseable HTTP
/// request through to a plaintext backend, rather than merely checking the client-visible status
/// code) and replies
/// with a fixed response, then closes the connection after one request. Returns immediately; the
/// listener runs on a
/// background thread for the life of the test process.
fn spawn_capture_backend(response: &'static [u8]) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_bg = captured.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let captured = captured_bg.clone();
            std::thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let got_any = !buf.is_empty();
                // Background thread, detached from any single test's stack: if the *test*
                // thread already panicked on an assertion, that poisons the mutex, but this
                // thread has nothing to do with that failure and shouldn't produce a second,
                // confusing panic on top of it -- recover the data and move on.
                captured.lock().unwrap_or_else(|e| e.into_inner()).push(buf);
                if got_any && !response.is_empty() {
                    let _ = stream.write_all(response);
                }
                // `stream` drops here: the socket closes immediately after one response, which is
                // exactly the "backend closed the keep-alive connection while it sat in the pool"
                // scenario the stale-pooled-connection retry test below relies on.
            });
        }
    });
    (port, captured)
}

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";

// Deliberately NO `Connection: close` here: rproxy's `backend_keep_alive` defaults to `true` and
// is only flipped by an explicit `Connection: close` on the *backend's* response (fast_proxy.rs,
// ~line 2063) -- using `OK_RESPONSE` (which sends one) for the stale-pool test would make rproxy
// never pool the connection at all, so request 2 would just open a fresh one and the test would
// pass without ever exercising the stale-*pooled*-connection retry path it claims to cover.
const OK_RESPONSE_KEEPALIVE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";

/// Owns the generated cert/key temp files and removes them on drop -- including on a panicking
/// assertion (confirmed by the mutation-testing pass on `backend_tls_connector`: a deliberately
/// broken build made this test fail, and without this guard the plain end-of-function
/// `remove_file` calls it replaced never ran, leaking the cert/key into `/tmp`).
struct SelfSignedCert {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

impl Drop for SelfSignedCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cert_path);
        let _ = std::fs::remove_file(&self.key_path);
    }
}

/// Generate a throwaway self-signed cert (via the `openssl` CLI -- no new Rust dependency, and
/// this is test-only) for the positive-path `tls_skip_verify` test below: it needs a backend that
/// actually terminates TLS with a certificate the OS root store would never trust, otherwise
/// there's nothing for `tls_skip_verify` to be doing.
fn generate_self_signed_cert() -> SelfSignedCert {
    let cert_path = unique_path("selfsigned.crt");
    let key_path = unique_path("selfsigned.key");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
        ])
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to run openssl (required for the tls_skip_verify positive-path test)");
    assert!(
        status.success(),
        "openssl req failed to generate a self-signed cert"
    );
    SelfSignedCert {
        cert_path,
        key_path,
    }
}

/// A backend that terminates TLS itself (synchronously, via `rustls::Stream` -- no async runtime
/// needed for a test-only single-threaded-per-connection server) using a throwaway self-signed
/// cert, and otherwise behaves like `spawn_capture_backend`: one fixed response per connection,
/// closes after. This is the only way to exercise `tls_skip_verify`'s actual positive path (self-
/// signed cert *accepted*, health probe stays UP) -- `spawn_capture_backend`'s plaintext listener
/// can only ever prove the negative (TLS attempted, then correctly rejected/failed).
fn spawn_tls_capture_backend(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    response: &'static [u8],
) -> u16 {
    use rustls::pki_types::PrivateKeyDer;

    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert_path).unwrap(),
    ))
    .collect::<Result<_, _>>()
    .unwrap();
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key_path).unwrap(),
    ))
    .unwrap()
    .expect("no private key found in generated cert file");
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("valid self-signed cert/key"),
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { continue };
            let server_config = server_config.clone();
            std::thread::spawn(move || {
                tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut conn = match rustls::ServerConnection::new(server_config) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let mut buf = [0u8; 4096];
                // Handshake + read the request head; ignore errors (a health probe or a proxied
                // GET both end up here, neither sends a body this server needs to parse further).
                let _ = tls.read(&mut buf);
                let _ = tls.write_all(response);
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

// ---------------------------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore]
fn smoke_plain_proxy_roundtrip() {
    let (backend_port, _captured) = spawn_capture_backend(OK_RESPONSE);
    let proxy_port = free_port();
    let cfg_path = unique_path("smoke.yml");
    std::fs::write(&cfg_path, format!(
        "listen:\n  - \"127.0.0.1:{proxy_port}\"\nworkers: 1\nconnect: 3\nresponse: 5\ndefault:\n  - host: \"127.0.0.1:{backend_port}\"\n"
    )).unwrap();
    let _guard = spawn_rproxy(&cfg_path);
    wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));

    let resp = send_segmented(
        &format!("127.0.0.1:{proxy_port}"),
        &[b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"],
        Duration::from_secs(3),
    );
    assert_eq!(
        status_code(&resp),
        Some(200),
        "resp: {}",
        String::from_utf8_lossy(&resp)
    );
}

/// Regression: a request whose headers arrive across multiple separate reads must be proxied
/// correctly, not RST. Uses both many headers (to make a single-syscall read less likely) and an
/// explicit mid-header write split.
#[test]
#[ignore]
fn segmented_request_headers_are_not_dropped() {
    let (backend_port, captured) = spawn_capture_backend(OK_RESPONSE);
    let proxy_port = free_port();
    let cfg_path = unique_path("segmented.yml");
    std::fs::write(&cfg_path, format!(
        "listen:\n  - \"127.0.0.1:{proxy_port}\"\nworkers: 1\nconnect: 3\nresponse: 5\ndefault:\n  - host: \"127.0.0.1:{backend_port}\"\n"
    )).unwrap();
    let _guard = spawn_rproxy(&cfg_path);
    wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));

    let mut head = String::from("GET /path HTTP/1.1\r\nHost: x\r\n");
    for i in 0..20 {
        head.push_str(&format!("X-Filler-{i}: {}\r\n", "v".repeat(20)));
    }
    let part_a = head.into_bytes();
    let part_b = b"Connection: close\r\n\r\n".to_vec();

    let resp = send_segmented(
        &format!("127.0.0.1:{proxy_port}"),
        &[&part_a, &part_b],
        Duration::from_secs(3),
    );
    assert_eq!(
        status_code(&resp),
        Some(200),
        "segmented request must not be dropped/RST -- resp: {} (backend saw {} connection(s))",
        String::from_utf8_lossy(&resp),
        captured.lock().unwrap().len()
    );
    assert_eq!(
        captured.lock().unwrap().len(),
        1,
        "backend must have received exactly one forwarded connection"
    );
}

/// Regression: a pooled keep-alive backend connection that went stale (backend closed it while
/// idle in the pool) must trigger a transparent reconnect-and-retry, not a visible failure for
/// the second request.
#[test]
#[ignore]
fn stale_pooled_backend_connection_retries_transparently() {
    // spawn_capture_backend closes the socket right after each response -- exactly "backend
    // closed the connection", which is what makes the *pooled* copy of it stale for request 2.
    // OK_RESPONSE_KEEPALIVE (no Connection: close) is required so rproxy actually pools it first.
    let (backend_port, captured) = spawn_capture_backend(OK_RESPONSE_KEEPALIVE);
    let proxy_port = free_port();
    let cfg_path = unique_path("stale_pool.yml");
    // workers: 1 is load-bearing here: the connection pool is per-worker thread-local, so with
    // more than one worker request 2 could land on a worker that never pooled request 1's
    // connection at all, which would prove nothing about the stale-retry path specifically.
    std::fs::write(&cfg_path, format!(
        "listen:\n  - \"127.0.0.1:{proxy_port}\"\nworkers: 1\nconnect: 3\nresponse: 5\nbackend_pool_size: 4\ndefault:\n  - host: \"127.0.0.1:{backend_port}\"\n"
    )).unwrap();
    let _guard = spawn_rproxy(&cfg_path);
    wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));

    let req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let resp1 = send_segmented(
        &format!("127.0.0.1:{proxy_port}"),
        &[req],
        Duration::from_secs(3),
    );
    assert_eq!(
        status_code(&resp1),
        Some(200),
        "request 1: {}",
        String::from_utf8_lossy(&resp1)
    );

    // Give the backend's handler thread time to actually close its socket after replying, so the
    // pooled connection on rproxy's side is genuinely dead (not a race against the FIN).
    std::thread::sleep(Duration::from_millis(200));

    let resp2 = send_segmented(
        &format!("127.0.0.1:{proxy_port}"),
        &[req],
        Duration::from_secs(3),
    );
    assert_eq!(
        status_code(&resp2), Some(200),
        "request 2 must succeed via transparent reconnect, not surface the stale pooled conn as a failure: {}",
        String::from_utf8_lossy(&resp2)
    );
    assert_eq!(
        captured.lock().unwrap().len(),
        2,
        "backend must have been connected to twice (fresh + reconnect)"
    );
}

/// Regression: a route-level `deny_ip` ACL on `match: /admin` must not be steppable-around via
/// dot-segments/empty-segments the backend would itself resolve back to `/admin`. Also proves
/// `normalize_path: false` reopens exactly this hole, so the test is actually exercising the
/// flag and not just "some" unrelated 403.
#[test]
#[ignore]
fn path_traversal_cannot_bypass_route_acl() {
    let (backend_port, _captured) = spawn_capture_backend(OK_RESPONSE);

    let config = |proxy_port: u16, normalize: bool| {
        format!(
        "listen:\n  - \"127.0.0.1:{proxy_port}\"\nworkers: 1\nconnect: 3\nresponse: 5\nnormalize_path: {normalize}\ndomains:\n  - match: \"testdomain\"\n    routes:\n      - match: \"/admin\"\n        deny_ip: [\"0.0.0.0/0\"]\n        backends:\n          - host: \"127.0.0.1:{backend_port}\"\n    default:\n      - host: \"127.0.0.1:{backend_port}\"\n"
    )
    };

    // --- normalize_path: true (the default; explicit here for clarity) ---
    {
        let proxy_port = free_port();
        let cfg_path = unique_path("path_acl_on.yml");
        std::fs::write(&cfg_path, config(proxy_port, true)).unwrap();
        let _guard = spawn_rproxy(&cfg_path);
        wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));

        let get = |target: &str| {
            send_segmented(
                &format!("127.0.0.1:{proxy_port}"),
                &[format!(
                    "GET {target} HTTP/1.1\r\nHost: testdomain\r\nConnection: close\r\n\r\n"
                )
                .as_bytes()],
                Duration::from_secs(3),
            )
        };
        let direct = get("/admin");
        assert_eq!(
            status_code(&direct),
            Some(403),
            "/admin direct: {}",
            String::from_utf8_lossy(&direct)
        );
        let traversal = get("/x/../admin");
        assert_eq!(
            status_code(&traversal),
            Some(403),
            "/x/../admin must be blocked like /admin: {}",
            String::from_utf8_lossy(&traversal)
        );
        let encoded = get("/%2e%2e/admin");
        assert_eq!(
            status_code(&encoded),
            Some(403),
            "percent-encoded traversal must be blocked: {}",
            String::from_utf8_lossy(&encoded)
        );
        let fragment = get("/pub#/../admin");
        assert_eq!(
            status_code(&fragment),
            Some(400),
            "'#' in the request-target must be rejected outright: {}",
            String::from_utf8_lossy(&fragment)
        );
    }

    // --- normalize_path: false must reopen the bypass (proves the flag is load-bearing) ---
    {
        let proxy_port = free_port();
        let cfg_path = unique_path("path_acl_off.yml");
        std::fs::write(&cfg_path, config(proxy_port, false)).unwrap();
        let _guard = spawn_rproxy(&cfg_path);
        wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));
        let resp = send_segmented(
            &format!("127.0.0.1:{proxy_port}"),
            &[b"GET /x/../admin HTTP/1.1\r\nHost: testdomain\r\nConnection: close\r\n\r\n"],
            Duration::from_secs(3),
        );
        assert_eq!(
            status_code(&resp), Some(200),
            "normalize_path: false must restore byte-exact matching (and thus the bypass) -- this failing means the flag stopped doing anything: {}",
            String::from_utf8_lossy(&resp)
        );
    }
}

/// Regression: an `https://` backend must get a real TLS handshake, never a cleartext request.
/// Points rproxy at a *plaintext* backend under an `https://` host -- this must fail closed
/// (502), and the backend must never see a parseable HTTP request (the pre-fix behavior: 200,
/// backend logs the request in the clear).
///
/// Note this is deliberately NOT "the backend receives zero bytes": rproxy's TLS *handshake
/// attempt* legitimately sends a ClientHello on the wire before discovering the plaintext peer
/// can't complete it (observed: ~1.4KB, consistent with a TLS 1.3 ClientHello carrying a
/// post-quantum hybrid key share -- rustls' default `prefer-post-quantum` feature). That is
/// correct, expected TLS behavior, not the cleartext leak. The actual security property is that
/// no *decodable HTTP request* ever reaches the backend.
fn assert_plaintext_backend_never_receives_cleartext(tls_skip_verify: bool, cfg_name: &str) {
    let (backend_port, captured) = spawn_capture_backend(OK_RESPONSE); // deliberately plaintext
    let proxy_port = free_port();
    let cfg_path = unique_path(cfg_name);
    let skip_verify_line = if tls_skip_verify {
        "    tls_skip_verify: true\n"
    } else {
        ""
    };
    // connect/response are generous (not the 2s/3s a single isolated run would need) because this
    // suite runs its 5 tests in parallel by default -- under a loaded box, a CPU-starved worker
    // can miss a tight deadline on the TLS handshake attempt itself and fail closed *before* the
    // ClientHello goes out, which would make the harness's own positive-control assertion below
    // ("did rproxy even attempt TLS") flaky for reasons that have nothing to do with whether the
    // backend TLS handshake itself is correct.
    std::fs::write(&cfg_path, format!(
        "listen:\n  - \"127.0.0.1:{proxy_port}\"\nworkers: 1\nconnect: 8\nresponse: 8\ndefault:\n  - host: \"https://127.0.0.1:{backend_port}\"\n{skip_verify_line}"
    )).unwrap();
    let _guard = spawn_rproxy(&cfg_path);
    wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));

    let resp = send_segmented(
        &format!("127.0.0.1:{proxy_port}"),
        &[b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"],
        Duration::from_secs(10),
    );
    assert_eq!(
        status_code(&resp),
        Some(502),
        "must fail closed, not proxy cleartext: {}",
        String::from_utf8_lossy(&resp)
    );

    let conns = captured.lock().unwrap();
    let http_methods: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    let leaked_http = conns
        .iter()
        .any(|c| http_methods.iter().any(|m| c.starts_with(m)));
    assert!(
        !leaked_http,
        "plaintext backend received a parseable HTTP request -- this is the cleartext leak F7 fixed: {:?}",
        conns.iter().map(|c| String::from_utf8_lossy(c)).collect::<Vec<_>>()
    );
    // Positive control on the harness itself: prove rproxy actually attempted TLS (rather than,
    // say, silently not connecting at all, which would make the assertion above vacuous).
    if let Some(first) = conns.iter().find(|c| !c.is_empty()) {
        assert_eq!(
            first[0],
            0x16,
            "expected a TLS handshake record (content type 0x16), got {:#04x} ({} bytes)",
            first[0],
            first.len()
        );
    } else {
        panic!("backend saw no connection attempt at all -- can't confirm rproxy tried TLS");
    }
}

#[test]
#[ignore]
fn https_backend_never_receives_cleartext() {
    assert_plaintext_backend_never_receives_cleartext(false, "f7.yml");
}

/// `tls_skip_verify` relaxes chain/hostname verification -- it must NOT relax the requirement
/// that the peer speak TLS at all. Same repro as `https_backend_never_receives_cleartext` but
/// with the flag on: still 502 (a plaintext peer can't complete *any* TLS handshake, verified or
/// not), still no parseable HTTP reaching the backend. Guards against a connector-selection bug
/// silently turning "skip cert checks" into "skip TLS entirely".
#[test]
#[ignore]
fn https_backend_skip_verify_still_requires_tls() {
    assert_plaintext_backend_never_receives_cleartext(true, "f7_skip_verify.yml");
}

/// The positive path `tls_skip_verify` exists for: a backend with a self-signed cert. Without the
/// flag it must be rejected (health probe fails cert verification -> DOWN -> 502). With the flag,
/// on the exact same backend, it must work end-to-end -- both the data-plane connect *and* the
/// health probe (health.rs has its own, separately-wired copy of the flag -- both paths need it,
/// not just one).
///
/// This is the scenario advisor flagged as most important to cover: `backend_tls_connector`
/// picks between two thread-local connectors (verify / no-verify), and a future refactor that
/// inverts that selection would fail silently -- every other test here still passes (they only
/// prove verification *isn't bypassed for plaintext*, not that skip-verify *works* when it
/// should). Only a real self-signed-accepted round trip catches that class of regression.
#[test]
#[ignore]
fn https_backend_skip_verify_accepts_self_signed_and_health_stays_up() {
    let cert = generate_self_signed_cert();
    let backend_port = spawn_tls_capture_backend(&cert.cert_path, &cert.key_path, OK_RESPONSE);
    let health = "health: \"path=/ interval=1 timeout=2 rise=1 fall=1\"\n";

    // --- WITHOUT tls_skip_verify: self-signed cert must still be rejected --------------------
    {
        let proxy_port = free_port();
        let cfg_path = unique_path("selfsigned_off.yml");
        std::fs::write(&cfg_path, format!(
            "listen:\n  - \"127.0.0.1:{proxy_port}\"\nworkers: 1\nconnect: 3\nresponse: 5\n{health}default:\n  - host: \"https://127.0.0.1:{backend_port}\"\n"
        )).unwrap();
        let _guard = spawn_rproxy(&cfg_path);
        wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));
        // Let at least one health-check interval elapse: the backend starts UP by default, so
        // the DOWN transition (real cert verification failing) needs time to happen.
        std::thread::sleep(Duration::from_millis(1800));
        let resp = send_segmented(
            &format!("127.0.0.1:{proxy_port}"),
            &[b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"],
            Duration::from_secs(3),
        );
        assert_eq!(
            status_code(&resp), Some(502),
            "self-signed cert must still be rejected without tls_skip_verify (health probe should have marked it DOWN): {}",
            String::from_utf8_lossy(&resp)
        );
    }

    // --- WITH tls_skip_verify: same backend, same cert, must work end-to-end -----------------
    {
        let proxy_port = free_port();
        let cfg_path = unique_path("selfsigned_on.yml");
        std::fs::write(&cfg_path, format!(
            "listen:\n  - \"127.0.0.1:{proxy_port}\"\nworkers: 1\nconnect: 3\nresponse: 5\n{health}default:\n  - host: \"https://127.0.0.1:{backend_port}\"\n    tls_skip_verify: true\n"
        )).unwrap();
        let _guard = spawn_rproxy(&cfg_path);
        wait_until_listening(&format!("127.0.0.1:{proxy_port}"), Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1800));
        let resp = send_segmented(
            &format!("127.0.0.1:{proxy_port}"),
            &[b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"],
            Duration::from_secs(3),
        );
        assert_eq!(
            status_code(&resp), Some(200),
            "tls_skip_verify must let a self-signed backend serve traffic (data plane + health.rs both wired to the flag): {}",
            String::from_utf8_lossy(&resp)
        );
    }
    // `cert` drops here, cleaning up its temp files (including on the panic-unwind path).
}
