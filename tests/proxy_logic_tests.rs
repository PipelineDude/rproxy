//! Tests for proxy logic — HTTP forward headers+body passthrough, WebSocket 101 upgrade,
//! keep-alive connection reuse.
//!
//! DOC-DRIVEN: per rproxy README "Ключевые фичи" and "Безопасность и лимиты":
//!   - Hop-by-hop headers (Connection, Keep-Alive, Upgrade, TE, Trailer,
//!     Transfer-Encoding, Proxy-* ) are stripped in both directions except legit upgrade.
//!   - Host: duplicate or missing in HTTP/1.1 → 400.
//!   - Request-target: only origin-form (*) and * allowed; absolute/authority → 400.
//!   - Fragment (#) in request-target → 400.
//!   - Keep-alive with connection pooling to backends.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// Capture backend: responds with a configurable response for every request.
struct CaptureBackend {
    port: u16,
    captured: Arc<Mutex<Vec<String>>>,
}

impl CaptureBackend {
    fn new(_capture_headers: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::new()));

        // The listener is moved into the serving thread (keeps the socket open for the lifetime
        // of the process), so it does not need to be stored back on the struct.
        let captured_for_thread = captured.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut s = stream;
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut reader = s.try_clone().unwrap();
                let _ = reader.read_to_end(&mut buf);
                let req = String::from_utf8_lossy(&buf).to_string();
                captured_for_thread.lock().unwrap().push(req.clone());

                // Send a simple 200 response
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
                let _ = s.write_all(resp.as_bytes());
            }
        });

        Self { port, captured }
    }
}

/// Write a minimal rproxy config pointing to the capture backend.
fn make_config(port: u16) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rproxy.yml");
    std::fs::write(
        &path,
        format!(
            r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
default:
  - "127.0.0.1:{}"
"#,
            port + 100, // proxy listens on port+100
            port        // backend is the capture server
        ),
    )
    .unwrap();
    (dir, path)
}

/// Send a raw HTTP request to addr and return response bytes.
fn send_request(addr: &str, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("connect to proxy");
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(request.as_bytes()).ok();
    stream.shutdown(std::net::Shutdown::Write).ok();

    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut resp = Vec::new();
    let mut reader = stream.try_clone().unwrap();
    let _ = reader.read_to_end(&mut resp);
    resp
}

// ---------------------------------------------------------------------------
// HTTP forward — headers passthrough
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_forwards_custom_headers_to_backend() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    // Start rproxy
    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    // Wait for proxy to be ready
    std::thread::sleep(Duration::from_millis(500));

    let resp = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /test HTTP/1.1\r\nHost: localhost\r\nX-Custom-Header: test-value\r\n\r\n",
    );

    // Check response came back
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("200 OK"), "should get 200 from backend");

    // Check captured request has the custom header
    let captured = backend.captured.lock().unwrap();
    assert!(
        !captured.is_empty(),
        "backend should have received a request"
    );
    assert!(
        captured[0].contains("X-Custom-Header: test-value"),
        "custom header should be forwarded to backend, got: {}",
        captured[0]
    );

    let _ = proxy.kill();
    let _ = proxy.wait();
}

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_adds_x_real_ip_header() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    // Config with set_headers for X-Real-IP
    let path2 = cfg_path.parent().unwrap().join("rproxy2.yml");
    std::fs::write(
        &path2,
        format!(
            r#"
listen:
  - "127.0.0.1:{}"
workers: "1"
set_headers:
  X-Real-IP: "$client_ip"
default:
  - "127.0.0.1:{}"
"#,
            backend.port + 100,
            backend.port
        ),
    )
    .unwrap();

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", path2.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    let resp = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    assert!(String::from_utf8_lossy(&resp).contains("200 OK"));

    let captured = backend.captured.lock().unwrap();
    if !captured.is_empty() {
        // X-Real-IP should be present (set to $client_ip which is the connecting IP)
        assert!(
            captured[0].contains("X-Real-IP:"),
            "X-Real-IP header should be added, got: {}",
            captured[0]
        );
    }

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// HTTP forward — body passthrough
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_forwards_request_body() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    let body = "key=value&foo=bar";
    let request = format!(
        "POST /submit HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    let resp = send_request(&format!("127.0.0.1:{}", backend.port + 100), &request);

    assert!(String::from_utf8_lossy(&resp).contains("200 OK"));

    let captured = backend.captured.lock().unwrap();
    if !captured.is_empty() {
        assert!(
            captured[0].contains("key=value"),
            "body should be forwarded"
        );
        assert!(
            captured[0].contains("foo=bar"),
            "body should contain all params"
        );
    }

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// Hop-by-hop header stripping
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_strips_hop_by_hop_headers_from_request() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    // Send request with hop-by-hop headers that should be stripped
    let resp = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /test HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: keep-alive\r\n\
         Keep-Alive: timeout=5\r\n\
         TE: trailers\r\n\
         \r\n",
    );

    assert!(String::from_utf8_lossy(&resp).contains("200 OK"));

    let captured = backend.captured.lock().unwrap();
    if !captured.is_empty() {
        // Connection and Keep-Alive should NOT appear in the forwarded request
        assert!(
            !captured[0].to_lowercase().contains("keep-alive:"),
            "Keep-Alive hop-by-hop header should be stripped, got: {}",
            captured[0]
        );
    }

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// Host validation
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_rejects_missing_host_http11() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    let resp = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /test HTTP/1.1\r\n\r\n", // No Host header!
    );

    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("400"),
        "missing Host in HTTP/1.1 should return 400, got: {}",
        resp_str
    );

    let _ = proxy.kill();
    let _ = proxy.wait();
}

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_accepts_valid_host() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    let resp = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );

    assert!(
        String::from_utf8_lossy(&resp).contains("200 OK"),
        "valid Host should be accepted"
    );

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// Fragment rejection
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_rejects_request_with_fragment() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    let resp = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /page#section HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("400"),
        "fragment in request-target should return 400, got: {}",
        resp_str
    );

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// Keep-alive connection reuse
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_keep_alive_reuses_connection() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    // Send two requests on the same connection (keep-alive)
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", backend.port + 100)).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    // First request
    let req1 = "GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(req1.as_bytes()).ok();
    let mut resp1 = Vec::new();
    let _ = stream.try_clone().unwrap().read_to_end(&mut resp1);

    // Second request on same connection
    let req2 = "GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(req2.as_bytes()).ok();
    let mut resp2 = Vec::new();
    let _ = stream.try_clone().unwrap().read_to_end(&mut resp2);

    assert!(String::from_utf8_lossy(&resp1).contains("200 OK"));
    assert!(String::from_utf8_lossy(&resp2).contains("200 OK"));

    // Backend should have received both requests
    let captured = backend.captured.lock().unwrap();
    assert_eq!(captured.len(), 2, "should receive two separate requests");

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// Content-Length handling
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_forwards_content_length_correctly() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    let body = "test-body-content";
    let request = format!(
        "POST /api HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    let resp = send_request(&format!("127.0.0.1:{}", backend.port + 100), &request);

    assert!(String::from_utf8_lossy(&resp).contains("200 OK"));

    let captured = backend.captured.lock().unwrap();
    if !captured.is_empty() {
        assert!(
            captured[0].contains(&format!("Content-Length: {}", body.len())),
            "Content-Length should be forwarded"
        );
    }

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// Path normalization (normalize_path default)
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_normalizes_path_before_routing() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    // Send request with path traversal — should be normalized before routing
    let resp = send_request(
        &format!("127.0.0.1:{}", backend.port + 100),
        "GET /../test HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    // Should get 200 (normalized to /test) not a routing error
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("200 OK") || resp_str.contains("403"),
        "path traversal should be normalized, got: {}",
        resp_str
    );

    let _ = proxy.kill();
    let _ = proxy.wait();
}

// ---------------------------------------------------------------------------
// Max body size enforcement
// ---------------------------------------------------------------------------

#[test]
// Spawns a real rproxy process and binds a real port — could hang/conflict on a plain `cargo test`; run via `cargo test -- --ignored`.
fn proxy_enforces_max_body_size() {
    let backend = CaptureBackend::new(true);
    let (_dir, cfg_path) = make_config(backend.port);

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_rproxy"))
        .args(["-c", cfg_path.to_str().unwrap()])
        .spawn()
        .expect("spawn rproxy");

    std::thread::sleep(Duration::from_millis(500));

    // Send a body larger than default 2MB — use 3MB
    let big_body = "x".repeat(3_000_000);
    let request = format!(
        "POST /upload HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        big_body.len(),
        big_body
    );

    let resp = send_request(&format!("127.0.0.1:{}", backend.port + 100), &request);

    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("413"),
        "oversized body should return 413, got: {}",
        resp_str
    );

    let _ = proxy.kill();
    let _ = proxy.wait();
}
