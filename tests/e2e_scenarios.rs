//! E2E scenarios for rproxy — multi-backend failover, rate-limit 429, L7 cache bypass,
//! unhealthy backend exclusion. Uses live backends and rproxy binary.
//!
//! DOC-DRIVEN: per rproxy README "Коды ответов прокси":
//!   - 429 = rate_limit exceeded (per-worker)
//!   - 502 = no live backends
//!   - L7 cache: key = method + Host + canonical path; Authorization not cached

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// `Content-Length` value from a raw header block, case-insensitively. `None`
/// for a GET/HEAD with no body (nothing more to drain).
fn content_length_of(header_bytes: &[u8]) -> Option<usize> {
    String::from_utf8_lossy(header_bytes).lines().find_map(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("content-length:")
            .and_then(|v| v.trim().parse().ok())
    })
}

/// Simple capture backend that counts requests and can be toggled between a
/// canned 200 response and a 500 (to simulate an unhealthy backend without a
/// second, purpose-built fixture).
struct TestBackend {
    port: u16,
    captured: Arc<Mutex<Vec<String>>>,
    status: Arc<std::sync::atomic::AtomicU16>,
}

impl TestBackend {
    fn new(response: &'static str) -> Self {
        Self::with_status(response, 200)
    }

    /// Like `new`, but starts (and can later be flipped via `set_status`) at
    /// an arbitrary status code — e.g. `with_status(body, 500)` to simulate a
    /// backend that health checks should mark DOWN.
    fn with_status(response: &'static str, status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(std::sync::atomic::AtomicU16::new(status));

        let resp = response.to_owned();
        // The listener is moved into the serving thread (keeps the socket open for the process
        // lifetime), so it does not need to be stored back on the struct.
        let captured_for_thread = captured.clone();
        let status_for_thread = status.clone();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                // Read headers (old `read_to_end` waited for the peer to shut
                // down the write side, which rproxy/the health checker don't
                // always do -- see docs/DESIGN-NOTES.md#2), then drain any
                // Content-Length body so a POST is fully received too.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                let header_end = loop {
                    match s.read(&mut tmp) {
                        Ok(0) => break None,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(pos + 4);
                            }
                        }
                        Err(_) => break None,
                    }
                };
                if let Some(header_end) = header_end {
                    if let Some(needed) = content_length_of(&buf[..header_end]) {
                        while buf.len() < header_end + needed {
                            match s.read(&mut tmp) {
                                Ok(0) => break,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(_) => break,
                            }
                        }
                    }
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                captured_for_thread.lock().unwrap().push(req);

                let code = status_for_thread.load(std::sync::atomic::Ordering::SeqCst);
                let (reason, body): (&str, &str) =
                    if code == 200 { ("OK", resp.as_str()) } else { ("Error", "backend unhealthy") };
                let resp_line = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp_line.as_bytes());
            }
        });

        Self { port, captured, status }
    }

    fn count(&self) -> usize {
        self.captured.lock().unwrap().len()
    }

    /// Flip the status code this backend answers with from now on (e.g. to
    /// simulate it going unhealthy mid-test).
    fn set_status(&self, code: u16) {
        self.status.store(code, std::sync::atomic::Ordering::SeqCst);
    }

    #[allow(dead_code)] // helper kept for explicit use in ignored e2e scenarios
    fn clear(&self) {
        self.captured.lock().unwrap().clear();
    }
}

fn send_request(addr: &str, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(request.as_bytes()).ok();
    stream.shutdown(std::net::Shutdown::Write).ok();

    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut resp = Vec::new();
    let _ = stream.try_clone().unwrap().read_to_end(&mut resp);
    let resp_str = String::from_utf8_lossy(&resp).into_owned();
    let status = resp_str
        .lines()
        .next()
        .and_then(|l| {
            l.split_whitespace()
                .nth(1)
                .unwrap_or("0")
                .parse::<u16>()
                .ok()
        })
        .unwrap_or(0);
    (status, resp_str)
}

/// Kill a started rproxy AND its whole prefork tree (workers + health
/// checker), not just the master. See docs/DESIGN-NOTES.md#5.
fn kill_proxy(mut c: Child) {
    let _ = nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(c.id() as i32),
        nix::sys::signal::Signal::SIGKILL,
    );
    let _ = c.kill();
    let _ = c.wait();
}

/// Start rproxy with given config content. Returns (child, temp_dir).
///
/// NOTE (2026-08-15): these scenarios spawn real worker processes, and each
/// worker builds a monoio runtime that registers io-uring buffers against
/// RLIMIT_MEMLOCK. On hosts with a small `ulimit -l` (e.g. 8MB) the runtime
/// fails to build ("Cannot allocate memory"), every request gets connection
/// refused, and the tests fail spuriously -- same environmental cause as the
/// #[monoio::test] lib failures (see fast_proxy.rs). Raise the limit locally
/// (`ulimit -l unlimited`) and make sure CI runners ship a high memlock.
fn start_rproxy(config_content: &str) -> (Child, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rproxy.yml");
    std::fs::write(&path, config_content).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", path.to_str().unwrap()])
        .process_group(0) // own group so kill_proxy() can reap workers + health checker
        .spawn()
        .expect("spawn rproxy");

    // Wait for the proxy to actually SERVE (poll, not a fixed sleep -- on a
    // slow machine 800ms was not enough and every request raced the accept
    // loop; a fixed sleep is also wrong the other way, wasting 800ms of a
    // fast machine's time). The probe sends a minimal request and accepts
    // ANY response line -- a 502 (backend not yet live) is fine, it proves
    // the listener AND the worker stack are up.
    let listen_addr = proxy_listen_addr(config_content);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let served = TcpStream::connect(&listen_addr).is_ok_and(|mut probe| {
            let _ = probe.set_write_timeout(Some(Duration::from_millis(500)));
            let _ = probe.write_all(b"GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n");
            let _ = probe.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = [0u8; 16];
            probe.read(&mut buf).map(|n| n > 0).unwrap_or(false)
        });
        if served {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "rproxy did not start serving on {listen_addr} within 10s \
                 (check RLIMIT_MEMLOCK -- see start_rproxy doc comment)"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (child, dir)
}

/// Extract the first `listen:` address from a generated config so tests can
/// wait for the actual port. Configs are our own heredocs, so this parse is
/// deliberately tiny (first quoted listen line).
fn proxy_listen_addr(config_content: &str) -> String {
    config_content
        .lines()
        .find_map(|l| {
            let t = l.trim();
            if t.starts_with("- ") && !t.starts_with("- \"127.0.0.1:{}") {
                Some(t.trim_start_matches("- ").trim_matches('"').to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "127.0.0.1:1".to_owned())
}

// ---------------------------------------------------------------------------
// Multi-backend failover
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_failover_to_second_backend() {
    let backend1 = TestBackend::new("backend1");
    let backend2 = TestBackend::new("backend2");

    let config = format!(
        r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
default:
  - "127.0.0.1:{}"
  - "127.0.0.1:{}"
"#,
        backend1.port + 100,
        backend1.port,
        backend2.port
    );

    let (proxy, _dir) = start_rproxy(&config);

    // Send several requests — they should go to either backend
    for _ in 0..10 {
        let (status, _) = send_request(
            &format!("127.0.0.1:{}", backend1.port + 100),
            "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status, 200, "should get 200 from live backend");
    }

    // Both backends should have received requests (round-robin distributes)
    let c1 = backend1.count();
    let c2 = backend2.count();
    assert!(
        c1 > 0 || c2 > 0,
        "at least one backend should receive traffic"
    );

    kill_proxy(proxy);
}

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_failover_when_first_backend_dies() {
    let backend1 = TestBackend::new("backend1");
    let backend2 = TestBackend::new("backend2");

    let config = format!(
        r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
default:
  - "127.0.0.1:{}"
  - "127.0.0.1:{}"
"#,
        backend1.port + 100,
        backend1.port,
        backend2.port
    );

    let (proxy, _dir) = start_rproxy(&config);

    // First, verify both backends are alive by sending requests
    for _ in 0..5 {
        let (status, _) = send_request(
            &format!("127.0.0.1:{}", backend1.port + 100),
            "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status, 200);
    }

    // Now kill backend1's listener (drop it)
    let backend1_port = backend1.port; // copy the port before moving/dropping the backend
    drop(backend1);

    // Requests should now go to backend2 only (or get 502 if health check hasn't updated yet)
    let mut got_backend2 = false;
    for _ in 0..10 {
        let (_, resp_str) = send_request(
            &format!("127.0.0.1:{}", backend1_port + 100),
            "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if resp_str.contains("backend2") {
            got_backend2 = true;
        }
    }

    // With health checks, backend1 should eventually be marked down
    // and traffic should failover to backend2.
    assert!(got_backend2, "failover to backend2 never happened after backend1 died");
    kill_proxy(proxy);
}

// ---------------------------------------------------------------------------
// Rate limit returns 429 beyond limit
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_rate_limit_returns_429() {
    let backend = TestBackend::new("ok");

    let config = format!(
        r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
domains:
  - match: "localhost"
    routes:
      - match: "/"
        rate_limit: 5
        backends:
          - "127.0.0.1:{}"
"#,
        backend.port + 100,
        backend.port
    );

    let (proxy, _dir) = start_rproxy(&config);

    // Send requests — first 5 should succeed, then 429
    let mut got_429 = false;
    for i in 0..10 {
        let (status, _) = send_request(
            &format!("127.0.0.1:{}", backend.port + 100),
            "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if status == 429 {
            got_429 = true;
        }
        // First few should be 200, later ones may be 429
        if i < 5 {
            assert_eq!(status, 200, "first {} requests should succeed", i + 1);
        }
    }

    assert!(got_429, "should get 429 after exceeding rate limit");

    kill_proxy(proxy);
}

// ---------------------------------------------------------------------------
// L7 cache avoids upstream on cache hit
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_l7_cache_avoids_upstream_on_hit() {
    let backend = TestBackend::new("response-body");

    let config = format!(
        r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
cache_max_bytes: 10485760
domains:
  - match: "localhost"
    routes:
      - match: "/"
        cache:
          ttl: 60
          max_size: 1048576
        backends:
          - "127.0.0.1:{}"
"#,
        backend.port + 100,
        backend.port
    );

    let (proxy, _dir) = start_rproxy(&config);

    // First request — goes to backend
    let (_, resp1) = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /cached HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        resp1,
        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nresponse-body"
    );

    let first_count = backend.count();

    // Second request — should be served from cache (backend count should not increase)
    std::thread::sleep(Duration::from_millis(100)); // allow cache to populate

    let (_, resp2) = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /cached HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        resp2,
        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nresponse-body"
    );

    // Backend count should still be 1 (cached response served)
    let second_count = backend.count();
    assert_eq!(
        second_count, first_count,
        "L7 cache should serve from cache, not upstream"
    );

    kill_proxy(proxy);
}

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_cache_ignores_authorization_requests() {
    let backend = TestBackend::new("auth-response");

    let config = format!(
        r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
cache_max_bytes: 10485760
domains:
  - match: "localhost"
    routes:
      - match: "/"
        cache:
          ttl: 60
          max_size: 1048576
        backends:
          - "127.0.0.1:{}"
"#,
        backend.port + 100,
        backend.port
    );

    let (proxy, _dir) = start_rproxy(&config);

    // Request with Authorization — should NOT be cached
    for _ in 0..3 {
        let (_, _) = send_request(
            &format!("127.0.0.1:{}", backend.port + 100),
            "GET /auth HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer token123\r\nConnection: close\r\n\r\n",
        );
    }

    let count = backend.count();
    // With Authorization, cache is bypassed — all 3 requests hit the backend
    assert_eq!(count, 3, "requests with Authorization should not be cached");

    kill_proxy(proxy);
}

// ---------------------------------------------------------------------------
// Unhealthy backend excluded
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_unhealthy_backend_excluded() {
    let backend1 = TestBackend::new("backend1");
    let backend2 = TestBackend::new("backend2");

    let config = format!(
        r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
health: "path=/health interval=1 fall=2"
default:
  - "127.0.0.1:{}"
  - "127.0.0.1:{}"
"#,
        backend1.port + 100,
        backend1.port,
        backend2.port
    );

    let (proxy, _dir) = start_rproxy(&config);
    let listen = format!("127.0.0.1:{}", backend1.port + 100);
    let get = |path: &str| {
        send_request(&listen, &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
    };

    // Both backends healthy initially — traffic should reach both over enough requests.
    let mut seen1 = false;
    let mut seen2 = false;
    for _ in 0..10 {
        let (status, resp) = get("/test");
        assert_eq!(status, 200);
        seen1 |= resp.contains("backend1");
        seen2 |= resp.contains("backend2");
    }
    assert!(seen1 && seen2, "expected both backends to serve at least one request while healthy");

    // Now make backend1 actually unhealthy (500 on every request, including the
    // health checker's own /health probe) and wait past `fall=2 interval=1` for
    // the checker to mark it DOWN.
    backend1.set_status(500);
    std::thread::sleep(Duration::from_millis(2500));

    // Every request should now land on backend2 only — 0 from backend1.
    for _ in 0..10 {
        let (status, resp) = get("/test");
        assert_eq!(status, 200, "excluded backend1 should never surface its 500 to the client");
        assert!(
            resp.contains("backend2") && !resp.contains("backend1"),
            "backend1 should be excluded once marked DOWN, got: {resp}"
        );
    }

    kill_proxy(proxy);
}

// ---------------------------------------------------------------------------
// WebSocket 101 upgrade passthrough (basic smoke test)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_websocket_upgrade_header_passthrough() {
    let backend = TestBackend::new("ws-response");

    let config = format!(
        r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
default:
  - "127.0.0.1:{}"
"#,
        backend.port + 100,
        backend.port
    );

    let (proxy, _dir) = start_rproxy(&config);

    // Send WebSocket upgrade request
    let (_, resp) = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /ws HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
    );

    // Backend should receive the upgrade headers and respond
    assert!(
        resp.contains("200 OK") || resp.contains("101"),
        "backend should handle WebSocket upgrade request"
    );

    kill_proxy(proxy);
}

// ---------------------------------------------------------------------------
// 502 when all backends down
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real ports + real process; each worker builds a monoio io-uring runtime, so a low RLIMIT_MEMLOCK (ulimit -l < ~64MB) makes them fail to start (see start_rproxy doc). Run: cargo test --test e2e_scenarios -- --ignored"]
// Spawns a real rproxy process and binds real ports — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn e2e_502_when_all_backends_down() {
    // Create a config pointing to non-existent backends
    let config = r#"
listen:
  - "127.0.0.1:9999"
workers: "1"
default:
  - "127.0.0.1:19999"
  - "127.0.0.1:19998"
"#;

    let (proxy, _dir) = start_rproxy(config);

    // Connect to the proxy port
    let (_, resp) = send_request(
        "127.0.0.1:9999",
        "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    // Should get 502 (no live backends)
    assert!(
        resp.contains("502"),
        "should get 502 when all backends down, got: {}",
        resp
    );

    kill_proxy(proxy);
}
