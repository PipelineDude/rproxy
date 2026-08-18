use crate::config::{Backend, Hspec};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::StatusCode;
use std::sync::atomic::Ordering;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

/// Constant-time byte comparison so the metrics-token check doesn't leak the token via timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn run_health_checker(
    checks: Vec<(Backend, Option<Hspec>)>,
    metrics_listen: Option<String>,
    metrics_path: Option<String>,
    metrics_token: Option<String>,
    metrics_basic_auth: Option<String>,
    workers: usize,
) {
    let mut tasks = Vec::new();

    let all_backends: Vec<Backend> = checks.iter().map(|(b, _)| b.clone()).collect();

    for (b, h_opt) in checks {
        if let Some(h) = h_opt {
            tasks.push(tokio::spawn(async move {
                // Mirror the data-plane's tls_skip_verify (fast_proxy.rs's connect_backend):
                // without this, a self-signed backend's health probe fails cert verification and
                // marks it DOWN even though the data plane (which also skips verification for
                // this backend) would happily proxy to it -- the flag would be a no-op whenever
                // health checks are configured, which is precisely when it's most likely to be.
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(h.timeout))
                    .no_proxy()
                    .danger_accept_invalid_certs(b.tls_skip_verify)
                    .build()
                    .unwrap();

                let scheme = if b.tls { "https" } else { "http" };
                let url = format!("{}://{}:{}{}", scheme, b.host, b.port, h.path);
                let mut up_count = 0;
                let mut down_count = 0;
                let mut is_currently_up = true; // start as UP

                loop {
                    sleep(Duration::from_secs(h.interval)).await;

                    let success = match client.get(&url).send().await {
                        Ok(res) => res.status() == StatusCode::OK,
                        Err(_) => false,
                    };

                    if success {
                        up_count += 1;
                        down_count = 0;
                        if !is_currently_up && up_count >= h.rise {
                            is_currently_up = true;
                            b.state.set_up(true);
                            info!("Backend {}:{} is UP", b.host, b.port);
                        }
                    } else {
                        down_count += 1;
                        up_count = 0;
                        if is_currently_up && down_count >= h.fall {
                            is_currently_up = false;
                            b.state.set_up(false);
                            info!("Backend {}:{} is DOWN", b.host, b.port);
                        }
                    }
                }
            }));
        }
    }

    if let Some(addr) = metrics_listen {
        let all_backends = all_backends.clone();
        let m_path = metrics_path.unwrap_or_else(|| "/metrics".to_string());
        tasks.push(tokio::spawn(async move {
            let listener = match TcpListener::bind(&addr).await {
                Ok(l) => {
                    info!("Metrics server listening on {}", addr);
                    l
                }
                Err(e) => {
                    error!("Failed to bind metrics server on {}: {}", addr, e);
                    return;
                }
            };

            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let backends_ref = all_backends.clone();
                    let path_ref = m_path.clone();
                    let token_for_task = metrics_token.clone();
                    let basic_for_task = metrics_basic_auth.clone();
                    tokio::task::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let svc = service_fn(move |req| {
                            let backends = backends_ref.clone();
                            let route_path = path_ref.clone();
                            let token_ref = token_for_task.clone();
                            let basic_ref = basic_for_task.clone();
                            async move {
                                if req.uri().path() == route_path {
                                    use bytes::Bytes;
                                    use http_body_util::Full;

                                    // Auth (default off): satisfied by either a configured Bearer
                                    // token OR configured Basic credentials. Both checks are
                                    // constant-time so neither leaks its secret via timing.
                                    if token_ref.is_some() || basic_ref.is_some() {
                                        let mut valid = false;
                                        if let Some(auth_val) = req.headers().get(hyper::header::AUTHORIZATION) {
                                            if let Ok(auth_str) = auth_val.to_str() {
                                                if let Some(ref expected_token) = token_ref {
                                                    if ct_eq(auth_str.as_bytes(), format!("Bearer {}", expected_token).as_bytes()) {
                                                        valid = true;
                                                    }
                                                }
                                                if let Some(ref creds) = basic_ref {
                                                    use base64::Engine as _;
                                                    let expected = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(creds.as_bytes()));
                                                    if ct_eq(auth_str.as_bytes(), expected.as_bytes()) {
                                                        valid = true;
                                                    }
                                                }
                                            }
                                        }
                                        if !valid {
                                            let mut resp = hyper::Response::builder().status(StatusCode::UNAUTHORIZED);
                                            if basic_ref.is_some() {
                                                resp = resp.header(hyper::header::WWW_AUTHENTICATE, "Basic realm=\"rproxy metrics\"");
                                            }
                                            return Ok(resp.body(Full::new(Bytes::from("Unauthorized\n"))).unwrap());
                                        }
                                    }

                                    let mut out = String::with_capacity(4096);
                                    let metrics = crate::shared::global_metrics();
                                    let cpu = match metrics {
                                        Some(m) => m.global_cpu_load.load(Ordering::Relaxed),
                                        None => 0,
                                    };
                                    out.push_str(&format!("# HELP rproxy_cpu_load CPU Load Percentage\n# TYPE rproxy_cpu_load gauge\nrproxy_cpu_load {}\n", cpu));

                                    if let Some(metrics) = metrics {
                                        let mut r_status = [0u64; 600];
                                        let mut rqos = 0; let mut rrl = 0; let mut rip = 0; let mut rjwt = 0; let mut rrule = 0;
                                        let mut rx = 0; let mut tx = 0; let mut active = 0;

                                        for i in 0..workers {
                                            for (s, dst) in (100..600).zip(r_status[100..600].iter_mut()) {
                                                *dst += metrics.workers[i].req_status[s].load(Ordering::Relaxed);
                                            }
                                            rqos += metrics.workers[i].req_qos_drop.load(Ordering::Relaxed);
                                            rrl += metrics.workers[i].req_rate_limit_drop.load(Ordering::Relaxed);
                                            rip += metrics.workers[i].req_ip_drop.load(Ordering::Relaxed);
                                            rjwt += metrics.workers[i].req_jwt_drop.load(Ordering::Relaxed);
                                            rrule += metrics.workers[i].req_rule_drop.load(Ordering::Relaxed);
                                            rx += metrics.workers[i].bytes_rx.load(Ordering::Relaxed);
                                            tx += metrics.workers[i].bytes_tx.load(Ordering::Relaxed);
                                            active += metrics.workers[i].active_connections.load(Ordering::Relaxed);
                                        }

                                        out.push_str("# HELP rproxy_requests_total Total Requests\n# TYPE rproxy_requests_total counter\n");
                                        for (s, &count) in (100..600).zip(&r_status[100..600]) {
                                            if count > 0 {
                                                out.push_str(&format!("rproxy_requests_total{{status=\"{}\"}} {}\n", s, count));
                                            }
                                        }
                                        out.push_str(&format!("rproxy_qos_dropped_total {}\n", rqos));
                                        out.push_str(&format!("rproxy_rate_limit_dropped_total {}\n", rrl));
                                        out.push_str(&format!("rproxy_ip_dropped_total {}\n", rip));
                                        out.push_str(&format!("rproxy_jwt_dropped_total {}\n", rjwt));
                                        out.push_str(&format!("rproxy_rule_dropped_total {}\n", rrule));

                                        out.push_str("# HELP rproxy_bytes_total Total Bytes\n# TYPE rproxy_bytes_total counter\n");
                                        out.push_str(&format!("rproxy_bytes_total{{dir=\"rx\"}} {}\n", rx));
                                        out.push_str(&format!("rproxy_bytes_total{{dir=\"tx\"}} {}\n", tx));

                                        out.push_str("# HELP rproxy_active_connections Total Active Connections\n# TYPE rproxy_active_connections gauge\n");
                                        out.push_str(&format!("rproxy_active_connections {}\n", active));
                                    }

                                    out.push_str("# HELP rproxy_backend_up Backend Up Status\n# TYPE rproxy_backend_up gauge\n");
                                    for b in &backends {
                                        let up = b.state.is_up();
                                        out.push_str(&format!("rproxy_backend_up{{host=\"{}:{}\"}} {}\n", b.host, b.port, if up { 1 } else { 0 }));
                                    }

                                    out.push_str("# HELP rproxy_backend_active_connections Backend Connections\n# TYPE rproxy_backend_active_connections gauge\n");
                                    for b in &backends {
                                        let c = b.state.active_conns();
                                        out.push_str(&format!("rproxy_backend_active_connections{{host=\"{}:{}\"}} {}\n", b.host, b.port, c));
                                    }

                                    Ok::<_, hyper::Error>(hyper::Response::builder()
                                        .status(StatusCode::OK)
                                        .header("Content-Type", "text/plain; version=0.0.4")
                                        .body(Full::new(Bytes::from(out)))
                                        .unwrap())
                                } else {
                                    Ok::<_, hyper::Error>(hyper::Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(http_body_util::Full::new(bytes::Bytes::from("Not Found")))
                                        .unwrap())
                                }
                            }
                        });

                        if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                            error!("Metrics server error: {}", e);
                        }
                    });
                }
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    // If there were no health checks configured, sleep forever so the process doesn't exit and fork bomb
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_basic_semantics() {
        // Same length + same bytes -> equal.
        assert!(ct_eq(b"Bearer secret", b"Bearer secret"));
        assert!(ct_eq(b"", b""));
        // Any byte difference (incl. the last one) -> not equal.
        assert!(!ct_eq(b"Bearer secret", b"Bearer secref"));
        assert!(!ct_eq(b"a", b"b"));
        // Length mismatch is an early-out (no byte comparison needed).
        assert!(!ct_eq(b"a", b"ab"));
        assert!(!ct_eq(b"ab", b"a"));
    }

    #[test]
    fn test_ct_eq_covers_the_full_auth_compare() {
        // The metrics OR-auth check compares the full wire value `Bearer <token>` / `Basic <b64>`
        // (health.rs). Assert the exact string forms so a future change to the comparison (e.g.
        // trimming, case-folding, or prefix matching that weakens it) fails here.
        assert!(ct_eq(b"Bearer tok", format!("Bearer {}", "tok").as_bytes()));
        assert!(!ct_eq(
            b"Bearer tok ",
            format!("Bearer {}", "tok").as_bytes()
        ));
        assert!(!ct_eq(
            b"Bearer tok",
            format!("Bearer {}", "tok2").as_bytes()
        ));
    }
}
