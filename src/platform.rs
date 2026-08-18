//! Runtime environment detection + adaptive worker placement (affinity, SQPOLL).
//!
//! Philosophy: decisions are driven by *cpuset facts* — the
//! effective allowed CPU set, whether a CPU quota oversubscribes us, and CAP_SYS_NICE — NOT by a
//! fuzzy container/VM/baremetal *label* (which is only logged for humans). Every adaptive step is
//! **fail-soft**: with `panic = "abort"` + the master respawn loop, an `unwrap()` on a refused
//! SQPOLL ring or a bad `sched_setaffinity` would become a crash loop that takes the proxy down.
//! So we attempt-and-degrade (log a warning, fall back to the safe default), never gate on parsing
//! kernel versions and never panic on the placement path.

use nix::sched::{sched_getaffinity, sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use tracing::{info, warn};

/// Tri-state knob shared by `cpu_affinity` and `sqpoll`: `auto` lets the policy below decide from
/// the detected environment; `on`/`off` force it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    Auto,
    On,
    Off,
}

/// Parse a tri-state knob, warning on an unrecognized value so a typo like `cpu_affinity: onn`
/// doesn't silently degrade to auto.
fn parse_policy(field: &str, raw: Option<&str>) -> Policy {
    match raw.map(|x| x.trim().to_ascii_lowercase()).as_deref() {
        Some("on") | Some("true") | Some("1") | Some("yes") => Policy::On,
        Some("off") | Some("false") | Some("0") | Some("no") => Policy::Off,
        Some("auto") | None | Some("") => Policy::Auto,
        Some(other) => {
            warn!("config: unrecognized {field}='{other}', defaulting to auto");
            Policy::Auto
        }
    }
}

/// Detected runtime environment + the resolved placement policy for this process.
#[derive(Clone, Debug)]
pub struct RuntimeEnv {
    /// Effective allowed CPUs (`sched_getaffinity`) — the source of truth, honors cgroup cpuset.
    pub allowed_cpus: Vec<usize>,
    /// Host parallelism (informational only; ignores cgroup limits).
    pub host_cpus: usize,
    /// Informational label; the policy does NOT branch on this.
    pub is_container: bool,
    /// A CPU quota (cgroup `cpu.max` / cfs) limits us below the allowed-set breadth.
    pub oversubscribed: bool,
    /// CAP_SYS_NICE present — required for SQPOLL on most kernels.
    pub cap_sys_nice: bool,
    pub num_workers: usize,

    // ---- resolved policy ----
    /// Pin worker `i` to `allowed_cpus[i % len]` when true.
    pub affinity_on: bool,
    /// `Some(idle_ms)` => build each worker's io_uring with `IORING_SETUP_SQPOLL`.
    pub sqpoll_idle: Option<u32>,
    /// Build each worker's io_uring with `IORING_SETUP_SINGLE_ISSUER` +
    /// `IORING_SETUP_COOP_TASKRUN` + `IORING_SETUP_TASKRUN_FLAG` when true.
    pub uring_flags_on: bool,
}

fn read_allowed_cpus() -> Vec<usize> {
    match sched_getaffinity(Pid::from_raw(0)) {
        Ok(set) => {
            let v: Vec<usize> = (0..CpuSet::count())
                .filter(|&i| set.is_set(i).unwrap_or(false))
                .collect();
            if v.is_empty() {
                vec![0]
            } else {
                v
            }
        }
        Err(_) => {
            let n = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            (0..n).collect()
        }
    }
}

fn detect_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return true;
    }
    if let Ok(s) = std::fs::read_to_string("/proc/1/cgroup") {
        if s.contains("docker")
            || s.contains("kubepods")
            || s.contains("containerd")
            || s.contains("/lxc")
        {
            return true;
        }
    }
    // systemd-nspawn and most OCI runtimes export `container=` in PID 1's environ.
    if let Ok(s) = std::fs::read("/proc/1/environ") {
        if env_has_container(&s) {
            return true;
        }
    }
    false
}

/// `/proc/1/environ` is a NUL-separated `KEY=value` list. Match only an entry whose *key*
/// is exactly `container` (with a non-empty value) — a bare substring search over the raw bytes
/// would also fire on `FOO=container=...` inside an unrelated value, a false positive that
/// exists today. Impact is limited to the informational `is_container` label (the placement
/// policy never branches on it), but the parse is cheap and correct.
fn env_has_container(environ: &[u8]) -> bool {
    const KEY: &[u8] = b"container=";
    environ
        .split(|&b| b == 0)
        .any(|e| e.starts_with(KEY) && e.len() > KEY.len())
}

/// CPU budget in cores granted by a cgroup quota, if any (`None` => unlimited / no quota).
fn detect_quota_cpus() -> Option<f64> {
    // cgroup v2: "<quota> <period>" or "max <period>"
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        let mut it = s.split_whitespace();
        if let (Some(q), Some(p)) = (it.next(), it.next()) {
            if q == "max" {
                return None;
            }
            if let (Ok(q), Ok(p)) = (q.parse::<f64>(), p.parse::<f64>()) {
                if p > 0.0 {
                    return Some(q / p);
                }
            }
        }
        return None;
    }
    // cgroup v1
    if let (Ok(q), Ok(p)) = (
        std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"),
        std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us"),
    ) {
        if let (Ok(q), Ok(p)) = (q.trim().parse::<i64>(), p.trim().parse::<f64>()) {
            if q > 0 && p > 0.0 {
                return Some(q as f64 / p);
            }
        }
    }
    None
}

fn detect_cap_sys_nice() -> bool {
    const CAP_SYS_NICE: u32 = 23;
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                if let Ok(bits) = u64::from_str_radix(hex.trim(), 16) {
                    return (bits >> CAP_SYS_NICE) & 1 == 1;
                }
            }
        }
    }
    false
}

/// Probe the environment and resolve the placement policy. Call once in the master before forking;
/// children inherit the result across `fork()`.
pub fn detect(cfg: &crate::config::Config, num_workers: usize) -> RuntimeEnv {
    let allowed_cpus = read_allowed_cpus();
    let host_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or_else(|_| allowed_cpus.len().max(1));
    let is_container = detect_container();
    let quota = detect_quota_cpus();
    // Oversubscribed when a quota grants fewer whole cores than the allowed set is wide, or fewer
    // than the workers we intend to pin (CFS throttling would fight per-core pinning).
    let oversubscribed = quota
        .is_some_and(|q| q + 0.01 < allowed_cpus.len() as f64 || (q + 0.01) < num_workers as f64);
    let cap_sys_nice = detect_cap_sys_nice();

    let aff_pol = parse_policy("cpu_affinity", cfg.cpu_affinity.as_deref());
    let sq_pol = parse_policy("sqpoll", cfg.sqpoll.as_deref());
    let uf_pol = parse_policy("uring_flags", cfg.uring_flags.as_deref());

    // --- affinity ---
    // Strict spare-core: auto-pin only when there are MORE allowed cores than workers, so a
    // co-located load generator / the system still has a core. With workers==cores (the common
    // `workers: "auto"` case) auto stays OFF — pinning every core would starve other tenants and
    // could manufacture a bench regression. Also off under an oversubscribed cgroup quota, where
    // per-core pinning just fights CFS throttling. Operators force full thread-per-core pinning
    // with `cpu_affinity: on`.
    let affinity_on = match aff_pol {
        Policy::On => true,
        Policy::Off => false,
        Policy::Auto => allowed_cpus.len() > num_workers && !oversubscribed,
    };

    // --- SQPOLL ---
    // Auto = OFF (opt-in). A local `strace` showed NO `io_uring_enter` reduction under sequential
    // load with monoio 0.2.4 (its driver waits per-op), while SQPOLL spins a dedicated poller core
    // — so we do not auto-enable a core-costly feature whose benefit we can't demonstrate. Whether
    // submit-batching SQPOLL wins under container + high concurrency is untested here.
    // `is_container`/`cap_sys_nice` are detected for the log/eligibility, not to auto-enable. Force
    // `sqpoll: on` to A/B test it in a real deployment.
    let want_sqpoll = match sq_pol {
        Policy::On => true,
        Policy::Off => false,
        Policy::Auto => false,
    };
    let sqpoll_idle = if want_sqpoll {
        Some(cfg.sqpoll_idle_ms.unwrap_or(1000))
    } else {
        None
    };

    // --- single_issuer + coop_taskrun + taskrun_flag ---
    // Auto = OFF, same reasoning as SQPOLL above: these flags are cheap and (per their io-uring
    // docs) should reduce IPI/kernel-transition overhead on the completion path, but profiling
    // measured `UringInner::poll_op` at only 0.71% self — the io_uring machinery itself is not what
    // dominates this proxy's kernel time (TCP stack/conntrack/AppArmor/memcg are), so the
    // real-world win here is unproven, not just theoretically small. Don't auto-enable an unproven
    // feature. Force `uring_flags: on` to A/B test it in a real deployment.
    //
    // `setup_defer_taskrun` is deliberately NOT included even under `on`: unlike the other three
    // (which only change how/whether the kernel interrupts userspace — safe to toggle), it changes
    // *when* the kernel processes submitted work, requires the app to periodically trigger it, and
    // monoio's driver was not written expecting that contract. Getting it wrong doesn't panic —
    // it silently stalls completions. Not a one-line toggle worth the risk for an unmeasured gain.
    let uring_flags_on = match uf_pol {
        Policy::On => true,
        Policy::Off => false,
        Policy::Auto => false,
    };

    RuntimeEnv {
        allowed_cpus,
        host_cpus,
        is_container,
        oversubscribed,
        cap_sys_nice,
        num_workers,
        affinity_on,
        sqpoll_idle,
        uring_flags_on,
    }
}

/// One human-readable startup line: detected facts + chosen policy. This is the audit surface.
pub fn log_summary(env: &RuntimeEnv) {
    info!(
        "runtime env: cpus_allowed={:?} (n={}), host_cpus={}, container={}, oversubscribed={}, cap_sys_nice={}, workers={}, shm_layout={} => affinity={}, sqpoll={}, uring_flags={}",
        env.allowed_cpus,
        env.allowed_cpus.len(),
        env.host_cpus,
        env.is_container,
        env.oversubscribed,
        env.cap_sys_nice,
        env.num_workers,
        crate::shared::SHM_LAYOUT_VERSION,
        if env.affinity_on { "on" } else { "off" },
        match env.sqpoll_idle {
            Some(idle) => format!("on(idle={idle}ms)"),
            None => "off".to_string(),
        },
        if env.uring_flags_on { "on" } else { "off" },
    );
}

/// Pin the calling worker to its core. Fail-soft — a refusal logs and runs unpinned.
fn pin_worker(env: &RuntimeEnv, worker_id: usize) {
    if !env.affinity_on || env.allowed_cpus.is_empty() {
        return;
    }
    let cpu = env.allowed_cpus[worker_id % env.allowed_cpus.len()];
    let mut set = CpuSet::new();
    if set.set(cpu).is_err() {
        warn!("worker {worker_id}: cpu {cpu} out of CpuSet range; running unpinned");
        return;
    }
    match sched_setaffinity(Pid::from_raw(0), &set) {
        Ok(()) => info!("worker {worker_id}: pinned to cpu {cpu}"),
        Err(e) => {
            warn!("worker {worker_id}: sched_setaffinity(cpu {cpu}) failed ({e}); running unpinned")
        }
    }
}

/// Build this worker's monoio runtime, pin it, and run `run_worker` to completion on it.
/// Used by BOTH fork sites (initial spawn + respawn) so their placement logic can't drift.
///
/// The monoio runtime type is never named — it stays a local, inferred from the shared
/// `build_plain` closure so the SQPOLL and fallback paths unify.
pub fn run_worker_blocking(
    env: &RuntimeEnv,
    worker_id: usize,
    cfg: crate::config::Config,
    http_listeners: &[std::net::TcpListener],
    https_listeners: &[std::net::TcpListener],
    tls_acceptor: &Option<monoio_rustls::TlsAcceptor>,
) {
    pin_worker(env, worker_id);

    let http_c: Vec<_> = http_listeners
        .iter()
        .map(|l| l.try_clone().expect("listener clone"))
        .collect();
    let https_c: Vec<_> = https_listeners
        .iter()
        .map(|l| l.try_clone().expect("listener clone"))
        .collect();
    let tls_c = tls_acceptor.clone();

    crate::shared::WORKER_ID.store(worker_id, std::sync::atomic::Ordering::Relaxed);
    if cfg.has_qos {
        crate::shared::start_cpu_monitor();
    }

    let build_plain = || {
        monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
            .enable_timer()
            .with_entries(2048)
            .build()
            .expect("failed to build monoio runtime")
    };

    // sqpoll and uring_flags both need a custom `io_uring::Builder` handed to monoio via
    // `.uring_builder(...)` — composed into ONE ring-build attempt (not two independent branches)
    // so both can be active together (their io-uring docs describe them as compatible: SINGLE_ISSUER
    // explicitly documents SQPOLL interaction) and so there is exactly one fail-soft fallback path.
    let mut rt = if env.sqpoll_idle.is_some() || env.uring_flags_on {
        let mut b = io_uring::IoUring::builder();
        if let Some(idle) = env.sqpoll_idle {
            b.setup_sqpoll(idle);
        }
        if env.uring_flags_on {
            // Cheap completion-path flags — see the comment in detect() for why DEFER_TASKRUN
            // is deliberately excluded. SINGLE_ISSUER is kernel-enforced (a violation fails the op
            // with -EEXIST, not silent corruption), matching thread-per-core's one-submitter-per-ring
            // reality exactly.
            b.setup_single_issuer();
            b.setup_coop_taskrun();
            b.setup_taskrun_flag();
        }
        match monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
            .enable_timer()
            .with_entries(2048)
            .uring_builder(b)
            .build()
        {
            Ok(rt) => {
                info!(
                    "worker {worker_id}: custom io_uring ring active (sqpoll={}, uring_flags={})",
                    match env.sqpoll_idle {
                        Some(idle) => format!("on(idle={idle}ms)"),
                        None => "off".to_string(),
                    },
                    if env.uring_flags_on { "on" } else { "off" },
                );
                rt
            }
            // Fail-soft: a kernel that refuses these setup flags (too old, no CAP_SYS_NICE for
            // SQPOLL, etc.) must NOT abort the worker — that would crash-loop via the respawn
            // supervisor.
            Err(e) => {
                warn!("worker {worker_id}: custom io_uring ring setup rejected ({e}); falling back to default ring");
                build_plain()
            }
        }
    } else {
        build_plain()
    };

    rt.block_on(async move {
        info!("Started Worker process {worker_id} with monoio backend");
        crate::fast_proxy::run_worker(cfg, http_c, https_c, tls_c).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_policy_on() {
        assert_eq!(parse_policy("x", Some("on")), Policy::On);
        assert_eq!(parse_policy("x", Some("true")), Policy::On);
        assert_eq!(parse_policy("x", Some("1")), Policy::On);
        assert_eq!(parse_policy("x", Some("yes")), Policy::On);
    }

    #[test]
    fn test_parse_policy_off() {
        assert_eq!(parse_policy("x", Some("off")), Policy::Off);
        assert_eq!(parse_policy("x", Some("false")), Policy::Off);
        assert_eq!(parse_policy("x", Some("0")), Policy::Off);
        assert_eq!(parse_policy("x", Some("no")), Policy::Off);
    }

    #[test]
    fn test_parse_policy_auto_and_defaults() {
        assert_eq!(parse_policy("x", Some("auto")), Policy::Auto);
        assert_eq!(parse_policy("x", None), Policy::Auto);
        assert_eq!(parse_policy("x", Some("")), Policy::Auto);
        assert_eq!(parse_policy("x", Some("bogus")), Policy::Auto);
    }

    #[test]
    fn test_read_allowed_cpus_smoke() {
        let cpus = read_allowed_cpus();
        assert!(!cpus.is_empty());
    }

    #[test]
    fn smoke_detect_container() {
        let _ = detect_container();
    }

    #[test]
    fn test_env_has_container_parses_key_value() {
        // Only an entry whose KEY is exactly `container` (with a value) counts.
        assert!(env_has_container(
            b"PATH=/usr/bin\0container=systemd-nspawn\0TERM=xterm"
        ));
        assert!(env_has_container(b"container=docker\0"));
        // `container=` inside a VALUE of another key is not the runtime marker.
        assert!(!env_has_container(b"FOO=container=docker\0"));
        assert!(!env_has_container(b"FOO=bar\0container"));
        // A value may legitimately contain `=` of its own; the key is still `container`.
        assert!(env_has_container(b"container=something=else"));
        // Empty value (`container=` alone) is ambiguous — ignore it.
        assert!(!env_has_container(b"container=\0"));
        assert!(!env_has_container(b""));
        assert!(!env_has_container(b"PATH=/bin\0"));
        // No trailing NUL (as read() may return) still parses.
        assert!(env_has_container(b"container=lxc"));
    }

    #[test]
    fn smoke_detect_quota_cpus() {
        let _ = detect_quota_cpus();
    }

    #[test]
    fn smoke_detect_cap_sys_nice() {
        let _ = detect_cap_sys_nice();
    }

    #[test]
    fn test_detect_forced_off() {
        let cfg = crate::config::Config {
            allow_ip: None,
            deny_ip: None,
            jwt_secret: None,
            cache: None,
            listen: vec!["127.0.0.1:8080".to_string()],
            tls_listen: vec![],
            listen_iface: None,
            tls_cert: None,
            tls_key: None,
            metrics_listen: None,
            metrics_path: None,
            metrics_token: None,
            metrics_basic_auth: None,
            cache_max_bytes: 104857600,
            domains: vec![],
            def: None,
            set_headers: None,
            client_timeout: 60,
            max_body_size: 2097152,
            max_headers_size: 8192,
            has_qos: false,
            max_active_requests: 10000,
            normalize_path: true,
            reject_encoded_slash: false,
            log_level: 3,
            workers: 4,
            backend_pool_size: 0,
            cpu_affinity: Some("off".into()),
            sqpoll: Some("off".into()),
            sqpoll_idle_ms: None,
            uring_flags: Some("off".into()),
            worker_lifetime: None,
            worker_max_requests: None,
            worker_drain: 30,
        };
        let env = detect(&cfg, 4);
        assert!(!env.affinity_on, "forced off must not pin");
        assert_eq!(env.sqpoll_idle, None, "forced off must disable sqpoll");
        assert!(!env.uring_flags_on, "forced off must disable uring_flags");
    }

    #[test]
    fn test_detect_forced_on() {
        let cfg = crate::config::Config {
            allow_ip: None,
            deny_ip: None,
            jwt_secret: None,
            cache: None,
            listen: vec!["127.0.0.1:8080".to_string()],
            tls_listen: vec![],
            listen_iface: None,
            tls_cert: None,
            tls_key: None,
            metrics_listen: None,
            metrics_path: None,
            metrics_token: None,
            metrics_basic_auth: None,
            cache_max_bytes: 104857600,
            domains: vec![],
            def: None,
            set_headers: None,
            client_timeout: 60,
            max_body_size: 2097152,
            max_headers_size: 8192,
            has_qos: false,
            max_active_requests: 10000,
            normalize_path: true,
            reject_encoded_slash: false,
            log_level: 3,
            workers: 4,
            backend_pool_size: 0,
            cpu_affinity: Some("on".into()),
            sqpoll: Some("on".into()),
            sqpoll_idle_ms: None,
            uring_flags: Some("on".into()),
            worker_lifetime: None,
            worker_max_requests: None,
            worker_drain: 30,
        };
        let env = detect(&cfg, 4);
        assert!(env.affinity_on, "forced on must pin");
        assert_eq!(
            env.sqpoll_idle,
            Some(1000),
            "forced on must set sqpoll idle=1000"
        );
        assert!(env.uring_flags_on, "forced on must enable uring_flags");
    }

    #[test]
    fn test_uring_flags_auto_defaults_off() {
        // Unlike affinity (which can auto-enable with spare cores), uring_flags follows
        // sqpoll's conservative convention — auto never turns it on, since profiling found
        // io_uring's own machinery isn't what dominates this proxy's kernel time (see the comment
        // in detect()). Only an explicit "on" enables it.
        let cfg = crate::config::Config {
            allow_ip: None,
            deny_ip: None,
            jwt_secret: None,
            cache: None,
            listen: vec!["127.0.0.1:8080".to_string()],
            tls_listen: vec![],
            listen_iface: None,
            tls_cert: None,
            tls_key: None,
            metrics_listen: None,
            metrics_path: None,
            metrics_token: None,
            metrics_basic_auth: None,
            cache_max_bytes: 104857600,
            domains: vec![],
            def: None,
            set_headers: None,
            client_timeout: 60,
            max_body_size: 2097152,
            max_headers_size: 8192,
            has_qos: false,
            max_active_requests: 10000,
            normalize_path: true,
            reject_encoded_slash: false,
            log_level: 3,
            workers: 4,
            backend_pool_size: 0,
            cpu_affinity: None,
            sqpoll: None,
            sqpoll_idle_ms: None,
            uring_flags: None,
            worker_lifetime: None,
            worker_max_requests: None,
            worker_drain: 30,
        };
        let env = detect(&cfg, 4);
        assert!(
            !env.uring_flags_on,
            "auto (unset) must default uring_flags off"
        );
    }
}
