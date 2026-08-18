mod backend;
mod balancer;
mod buf_pool;
mod config;
mod fast_proxy;
mod header_util;
mod health;
mod jwt;
mod platform;
mod shared;
// Unconditional so `profile_cycles!` always resolves as a macro at every call site; everything
// inside beyond the macro itself is individually `#[cfg(feature = "cycle_profile")]`-gated, so a
// default build still links none of the profiling machinery. See src/cycles.rs.
mod cycles;

use config::ConfigLoader;
use nix::unistd::{fork, ForkResult};
use shared::SharedMemory;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

const MAX_BACKENDS: usize = 1024;

/// SNI cert resolver with a default fallback. rustls' `ResolvesServerCertUsingSni` returns
/// nothing when SNI is absent or unmatched; this wrapper falls back to a default cert so a
/// single global `tls_cert` (and clients without SNI) still complete the handshake.
#[derive(Debug)]
struct SniOrDefault {
    sni: rustls::server::ResolvesServerCertUsingSni,
    default: Option<Arc<rustls::sign::CertifiedKey>>,
}
impl rustls::server::ResolvesServerCert for SniOrDefault {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.sni.resolve(hello).or_else(|| self.default.clone())
    }
}

/// Best-effort literal hostname from a domain `match` pattern for SNI auto-registration. Strips
/// anchors (`^`/`$`) and regex escapes (`\`), then accepts the result only if it is a plain DNS
/// name (alphanumerics, `.`, `-`, `_`). A pattern with surviving regex metacharacters (e.g. `*`,
/// `+`, `[`) returns None — the operator must set `tls_sni:` explicitly. This means a literal
/// `^api\.example\.com$` correctly yields `api.example.com`.
fn derive_sni_from_match(pat: &str) -> Option<String> {
    let s = pat
        .trim_start_matches('^')
        .trim_end_matches('$')
        .replace('\\', "");
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Some(s)
    } else {
        None
    }
}

fn create_listener(addr: &str, port: &str, iface: Option<&String>) -> std::net::TcpListener {
    let full_addr = if addr.contains(':') && !addr.starts_with('[') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    };
    let socket_addr: SocketAddr = full_addr.parse().expect("Invalid listen address");

    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).unwrap();

    // SO_REUSEPORT for prefork
    #[cfg(unix)]
    socket.set_reuse_port(true).unwrap();
    socket.set_reuse_address(true).unwrap();

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        unsafe {
            let val: nix::libc::c_int = 1;
            nix::libc::setsockopt(
                fd,
                nix::libc::IPPROTO_TCP,
                nix::libc::TCP_DEFER_ACCEPT,
                &val as *const _ as *const nix::libc::c_void,
                std::mem::size_of_val(&val) as nix::libc::socklen_t,
            );
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(i) = iface {
        socket.bind_device(Some(i.as_bytes())).unwrap();
    }

    socket.bind(&socket_addr.into()).unwrap();
    socket.listen(1024).unwrap();

    socket.into()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = "rproxy.yml".to_string();
    let mut test_config = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-t" => test_config = true,
            "-c" => {
                if i + 1 < args.len() {
                    config_path = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("-c requires a path argument");
                    std::process::exit(1);
                }
            }
            _ => {
                println!("Usage: rproxy [-t] [-c config.yml]");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let shm = SharedMemory::new(MAX_BACKENDS);
    let mut loader = ConfigLoader::new(&shm);

    let (cfg, health_checks) = match loader.load(&config_path) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    let mut max_level = cfg.log_level;
    for d in &cfg.domains {
        if let Some(dl) = d.log_level {
            if dl > max_level {
                max_level = dl;
            }
        }
        for r in &d.routes {
            if let Some(rl) = r.log_level {
                if rl > max_level {
                    max_level = rl;
                }
            }
        }
    }

    let env_filter = match max_level {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    };
    // Structured events: fields render as key=value by
    // default; RUST_LOG_FORMAT=json switches to one JSON object per line for
    // log ingestion, mirroring the Python processes' LOG_FORMAT=json.
    let fmt = std::env::var("RUST_LOG_FORMAT").unwrap_or_default();
    if fmt == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(tracing_subscriber::EnvFilter::new(env_filter))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(env_filter))
            .init();
    }

    if let Some(ref m_listen) = cfg.metrics_listen {
        let m_port = m_listen.split(':').next_back().unwrap_or("");
        for lp in &cfg.listen {
            let lp_port = lp.split(':').next_back().unwrap_or("");
            if m_port == lp_port {
                error!("Fatal Error: metrics_listen port ({}) is identical to proxy listen port ({}). They must run on different ports.", m_port, lp);
                std::process::exit(1);
            }
        }
    }

    // A config with no `domains` but a global `default` backend list is a perfectly valid
    // "proxy everything to these upstreams" setup (it is what the shipped rproxy.yml does), so it
    // must not warn. The genuinely broken shape is having neither: nothing to route to at all.
    if cfg.domains.is_empty() && cfg.def.is_none() {
        tracing::warn!(
            "No domains and no global `default` backends configured — every request will get 502."
        );
    }

    // rate_limit counters are per-worker (thread-per-core, zero-lock), so the effective global
    // limit is rate_limit × workers. Warn at startup (but still start) so the multiplication isn't
    // a silent surprise; the operator can divide their intended limit by `workers` if they care.
    if cfg.workers > 1 {
        for d in &cfg.domains {
            for r in &d.routes {
                if let Some(limit) = r.rate_limit {
                    let effective = (limit as u64).saturating_mul(cfg.workers as u64);
                    tracing::warn!(
                        "rate_limit is per-worker: route '{}' (domain '{}') set to {}/s, but with {} workers the effective GLOBAL limit is ~{}/s. Divide by workers if you need a hard global cap.",
                        r.re.as_str(), d.re.as_str(), limit, cfg.workers, effective
                    );
                }
            }
        }
    }

    // tls_skip_verify disables certificate verification for that backend's TLS connections —
    // loud on purpose (parse_backend already refuses to load it without a real `https://` host,
    // but that only catches the no-op case, not "you did mean this, be aware of what it means").
    for (be, _) in &health_checks {
        if be.tls_skip_verify {
            tracing::warn!("backend {}:{} has tls_skip_verify=true — its TLS certificate will NOT be verified (any cert is accepted)", be.host, be.port);
        }
    }

    if test_config {
        println!(
            "rproxy: the configuration file {} syntax is ok",
            config_path
        );
        println!(
            "rproxy: configuration file {} test is successful",
            config_path
        );
        std::process::exit(0);
    }

    // Collect all unique ports for HTTP and HTTPS
    let mut http_ports: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut https_ports: std::collections::HashSet<String> = std::collections::HashSet::new();

    for port in &cfg.listen {
        http_ports.insert(port.clone());
    }
    for port in &cfg.tls_listen {
        https_ports.insert(port.clone());
    }

    for d in &cfg.domains {
        for port in &d.listen {
            http_ports.insert(port.clone());
        }
        for port in &d.tls_listen {
            https_ports.insert(port.clone());
        }
    }

    // Create listeners
    let mut std_listeners = Vec::new();
    let mut std_listeners_https = Vec::new();

    for addr_port in &http_ports {
        info!(addr = %addr_port, kind = "http", "Binding HTTP listener");
        let parts: Vec<&str> = addr_port.split(':').collect();
        let addr = if parts.len() == 2 {
            parts[0]
        } else {
            "0.0.0.0"
        };
        let port = if parts.len() == 2 { parts[1] } else { parts[0] };
        std_listeners.push(create_listener(addr, port, cfg.listen_iface.as_ref()));
    }
    for addr_port in &https_ports {
        info!(addr = %addr_port, kind = "https", "Binding HTTPS listener");
        let parts: Vec<&str> = addr_port.split(':').collect();
        let addr = if parts.len() == 2 {
            parts[0]
        } else {
            "0.0.0.0"
        };
        let port = if parts.len() == 2 { parts[1] } else { parts[0] };
        std_listeners_https.push(create_listener(addr, port, cfg.listen_iface.as_ref()));
    }

    // Fork Health Checker
    let mut hc_pid = None;
    if !health_checks.is_empty() || cfg.metrics_listen.is_some() {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                drop(std_listeners); // Prevent FD leak
                drop(std_listeners_https);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let metrics_clone = cfg.metrics_listen.clone();
                let metrics_path_clone = cfg.metrics_path.clone();
                let metrics_token_clone = cfg.metrics_token.clone();
                let metrics_basic_clone = cfg.metrics_basic_auth.clone();
                let workers = cfg.workers;
                rt.block_on(async {
                    info!("Started isolated Health Checker process");
                    crate::health::run_health_checker(
                        health_checks,
                        metrics_clone,
                        metrics_path_clone,
                        metrics_token_clone,
                        metrics_basic_clone,
                        workers,
                    )
                    .await;
                });
                std::process::exit(0);
            }
            Ok(ForkResult::Parent { child }) => {
                hc_pid = Some(child);
            }
            Err(_) => panic!("Fork failed"),
        }
    }

    // Prepare TLS Acceptor with SNI if configured
    let mut tls_acceptor = None;
    if !https_ports.is_empty() {
        use std::fs::File;
        use std::io::BufReader;
        let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
        let mut has_any_tls = false;

        let load_cert =
            |cert_path: &str, key_path: &str| -> Result<Arc<rustls::sign::CertifiedKey>, String> {
                let mut cert_file = BufReader::new(
                    File::open(cert_path)
                        .map_err(|e| format!("Failed to open cert file {}: {}", cert_path, e))?,
                );
                let certs = rustls_pemfile::certs(&mut cert_file)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("Failed to read certs from {}: {}", cert_path, e))?;
                if certs.is_empty() {
                    return Err(format!("No certificates found in {}", cert_path));
                }
                let mut key_file = BufReader::new(
                    File::open(key_path)
                        .map_err(|e| format!("Failed to open key file {}: {}", key_path, e))?,
                );
                let key = rustls_pemfile::private_key(&mut key_file)
                    .map_err(|e| format!("Failed to read key from {}: {}", key_path, e))?
                    .ok_or_else(|| format!("No private key found in {}", key_path))?;
                let pk = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
                    .map_err(|e| format!("Failed to parse key from {}: {}", key_path, e))?;
                Ok(Arc::new(rustls::sign::CertifiedKey::new(certs, pk)))
            };

        // Load default cert if any
        let mut default_cert = None;
        if let (Some(cert_path), Some(key_path)) = (&cfg.tls_cert, &cfg.tls_key) {
            match load_cert(cert_path, key_path) {
                Ok(ck) => {
                    default_cert = Some(ck.clone());
                    has_any_tls = true;
                }
                Err(e) => error!("TLS: failed to load default cert: {}", e),
            }
        }

        // Load domain certs. SNI names come from the explicit `tls_sni:` list when present;
        // otherwise we auto-derive a single hostname from the `match` pattern, but ONLY when it is a
        // literal hostname (anchors/escapes stripped, then validated as a DNS name). A real regex
        // `match` (e.g. `.*\.example\.com`) yields no valid SNI — the old code blindly registered the
        // mangled regex string, which silently failed; now we require `tls_sni:` and say so loudly.
        for d in &cfg.domains {
            if let (Some(cert_path), Some(key_path)) = (&d.tls_cert, &d.tls_key) {
                match load_cert(cert_path, key_path) {
                    Ok(ck) => {
                        let snis: Vec<String> = match &d.tls_sni {
                            Some(names) if !names.is_empty() => names.clone(),
                            _ => derive_sni_from_match(d.re.as_str()).into_iter().collect(),
                        };
                        if snis.is_empty() {
                            error!("TLS: domain match '{}' is a regex with no literal hostname — set `tls_sni:` \
                                    to the hostname(s) this cert serves. Cert NOT SNI-registered; clients for \
                                    this domain will get the default cert (or fail if none).", d.re.as_str());
                            continue;
                        }
                        for host in &snis {
                            if let Err(e) = resolver.add(host, (*ck).clone()) {
                                error!(
                                    "TLS: could not register cert for SNI '{}' (domain '{}'): {}",
                                    host,
                                    d.re.as_str(),
                                    e
                                );
                            } else {
                                has_any_tls = true;
                            }
                        }
                    }
                    Err(e) => error!("TLS: failed to load domain cert for '{}': {}", d.re, e),
                }
            }
        }

        if has_any_tls {
            // Wrap the SNI resolver so an unmatched/absent SNI falls back to the default cert
            let resolver = SniOrDefault {
                sni: resolver,
                default: default_cert,
            };
            let server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));
            tls_acceptor = Some(monoio_rustls::TlsAcceptor::from(Arc::new(server_config)));
        }
    }

    // TLS listeners are configured but no certificate could be loaded (tls_cert/tls_key missing,
    // unreadable, or an empty/parse-failed cert file — the load paths above only log). Without an
    // acceptor the HTTPS accept loops are never spawned and the bound TLS ports silently serve
    // nothing. That is a service outage dressed as a healthy process — refuse to start instead.
    if !https_ports.is_empty() && tls_acceptor.is_none() {
        error!(
            "Fatal Error: tls_listen ports ({:?}) are configured but no TLS certificate could be \
             loaded (set tls_cert/tls_key globally or per-domain). Refusing to start — TLS \
             listeners would accept no connections.",
            https_ports
        );
        std::process::exit(1);
    }

    // Fork Workers
    let num_workers = cfg.workers;
    let mut children = Vec::new();

    // Detect the environment ONCE in the master (children inherit it across fork) and
    // resolve the adaptive placement policy. One log line records facts + decision.
    let env = platform::detect(&cfg, num_workers);
    platform::log_summary(&env);

    for i in 0..num_workers {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                platform::run_worker_blocking(
                    &env,
                    i,
                    cfg.clone(),
                    &std_listeners,
                    &std_listeners_https,
                    &tls_acceptor,
                );
                std::process::exit(0);
            }
            Ok(ForkResult::Parent { child }) => {
                children.push((i, child));
            }
            Err(_) => panic!("Fork failed"),
        }
    }

    // Master process waits for signals and respawns dead workers
    use nix::sys::wait::WaitStatus;
    loop {
        let dead_pid = match nix::sys::wait::wait() {
            Ok(WaitStatus::Exited(pid, code)) => {
                if Some(pid) == hc_pid {
                    error!(
                        pid = %pid, exit_code = %code, component = "health_checker",
                        "health checker exited, respawning"
                    );
                } else {
                    error!(
                        pid = %pid, exit_code = %code, component = "worker",
                        "worker exited, respawning"
                    );
                }
                pid
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                error!(
                    pid = %pid, signal = ?sig, component = "worker",
                    "process killed by signal, respawning"
                );
                pid
            }
            Ok(_) => continue,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(e) => {
                if e == nix::errno::Errno::EINTR {
                    continue;
                }
                error!(error = %e, "wait failed");
                break;
            }
        };

        // Check if it was the health checker
        if Some(dead_pid) == hc_pid {
            let hc_clone = health_checks.clone();
            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    let metrics_clone = cfg.metrics_listen.clone();
                    let metrics_path_clone = cfg.metrics_path.clone();
                    let workers = cfg.workers;
                    rt.block_on(async {
                        info!("Started respawned Health Checker process");
                        crate::health::run_health_checker(
                            hc_clone,
                            metrics_clone,
                            metrics_path_clone,
                            cfg.metrics_token.clone(),
                            cfg.metrics_basic_auth.clone(),
                            workers,
                        )
                        .await;
                    });
                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child }) => {
                    hc_pid = Some(child);
                }
                Err(_) => error!("Fork failed during HC respawn"),
            }
        } else if let Some(idx) = children.iter().position(|&(_, p)| p == dead_pid) {
            // It was a worker
            let worker_id = children[idx].0;
            children.remove(idx);
            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    platform::run_worker_blocking(
                        &env,
                        worker_id,
                        cfg.clone(),
                        &std_listeners,
                        &std_listeners_https,
                        &tls_acceptor,
                    );
                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child }) => {
                    children.push((worker_id, child));
                }
                Err(_) => error!("Fork failed during worker respawn"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::derive_sni_from_match;

    #[test]
    fn test_derive_sni_from_match() {
        // Anchored literal -> clean hostname (escapes + anchors stripped).
        assert_eq!(
            derive_sni_from_match(r"^api\.example\.com$").as_deref(),
            Some("api.example.com")
        );
        // Bare literal hostname.
        assert_eq!(
            derive_sni_from_match("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            derive_sni_from_match("host-1_a.local").as_deref(),
            Some("host-1_a.local")
        );
        // Real regex metacharacters -> no auto SNI (operator must set tls_sni).
        assert_eq!(derive_sni_from_match(r".*\.example\.com"), None);
        assert_eq!(derive_sni_from_match(r"(a|b)\.example\.com"), None);
        assert_eq!(derive_sni_from_match(r"v[0-9]\.example\.com"), None);
        assert_eq!(derive_sni_from_match("^$"), None); // empty after stripping
    }
}
