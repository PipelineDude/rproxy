use crate::shared::{SharedMemory, SharedState};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ValidateType {
    Header,
    Cookie,
    Query,
    Post,
}

#[derive(Deserialize, Debug, Clone)]
pub struct YamlValidateFail {
    pub status: Option<u16>,
    pub body: Option<String>,
    pub backends: Option<Vec<YamlBackend>>,
}

fn parse_log_level(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "error" => 1,
        "warn" => 2,
        "info" => 3,
        "debug" => 4,
        "trace" => 5,
        "none" | "off" => 0,
        _ => 3,
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct YamlValidateRule {
    #[serde(rename = "type")]
    pub rule_type: ValidateType,
    pub name: String,
    pub regex: Option<String>,
    #[serde(default)]
    pub invert: bool,
    #[serde(default)]
    pub on_fail: Option<YamlValidateFail>,
}

#[derive(Debug, Clone)]
pub struct ValidateFail {
    pub status: u16,
    pub body: String,
    pub backends: Option<BackendList>,
}

#[derive(Clone, Debug)]
pub struct ValidateRule {
    pub rule_type: ValidateType,
    pub name: String,
    pub regex: Option<Regex>,
    pub invert: bool,
    pub on_fail: ValidateFail,
}

#[derive(Deserialize, Debug, Clone)]
pub struct YamlConfig {
    pub listen: Option<Vec<String>>,
    pub tls_listen: Option<Vec<String>>,
    pub listen_iface: Option<String>,
    pub balance: Option<String>,
    pub health: Option<String>,
    pub default: Option<Vec<YamlBackend>>,
    pub set_headers: Option<HashMap<String, String>>,
    pub metrics_listen: Option<String>,
    pub metrics_path: Option<String>,
    pub metrics_token: Option<String>,
    // Optional HTTP Basic auth for /metrics ("user:password"); default off.
    pub metrics_basic_auth: Option<String>,
    // Per-worker response-cache budget in bytes (LRU eviction). Default 100 MiB. Total RAM under
    // cache ≈ this × workers.
    pub cache_max_bytes: Option<usize>,
    pub domains: Option<Vec<YamlDomain>>,
    pub client_timeout: Option<u64>,
    pub max_body_size: Option<u64>,
    pub max_headers_size: Option<u64>,
    pub max_active_requests: Option<usize>,
    // Canonicalise the request target (unreserved percent-escapes, dot-segments, empty
    // segments) before routing/filtering and forward the canonical form upstream. Default on —
    // turning it off restores byte-exact forwarding and reopens the ACL-bypass differential.
    pub normalize_path: Option<bool>,
    // Opt-in, default off: answer 400 when the PATH part of the request-target carries a
    // percent-encoded path separator (`%2F`/`%5C`). Only for deployments whose upstream decodes
    // those before resolving dot-segments — it breaks legitimate encoded-slash users (S3 keys,
    // registry/git refs), which is why it is not on by default.
    pub reject_encoded_slash: Option<bool>,
    pub connect: Option<u64>,
    pub response: Option<u64>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub log_level: Option<String>,
    pub allow_ip: Option<Vec<String>>,
    pub deny_ip: Option<Vec<String>>,
    pub jwt_secret: Option<String>,
    pub cache: Option<YamlRouteCache>,

    pub workers: Option<String>,
    pub backend_pool_size: Option<usize>,
    // Adaptive worker placement (affinity + SQPOLL). All default "auto": the runtime detects the
    // environment (effective cpuset, cgroup quota, CAP_SYS_NICE) and decides. Force with "on"/"off".
    pub cpu_affinity: Option<String>,
    pub sqpoll: Option<String>,
    pub sqpoll_idle_ms: Option<u32>,
    // Cheap io_uring completion-path flags (single_issuer + coop_taskrun + taskrun_flag) via
    // the uring_builder hook already used by sqpoll — no monoio fork needed. Same tri-state
    // convention, same conservative "auto"=off default (unproven benefit, see platform.rs).
    pub uring_flags: Option<String>,
    // Worker recycling (opt-in; both default off). A worker exits after living `worker_lifetime`
    // seconds and/or after serving `worker_max_requests` requests, then the supervisor respawns
    // it. `worker_drain` bounds the graceful drain before exit (seconds, default 30).
    pub worker_lifetime: Option<u64>,
    pub worker_max_requests: Option<u64>,
    pub worker_drain: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum YamlBackend {
    Simple(String),
    Detailed {
        host: Option<String>,
        connect: Option<u64>,
        response: Option<u64>,
        weight: Option<u32>,
        // Skip TLS certificate verification for this backend (self-signed/private-CA cert).
        // Only meaningful with an `https://` host; default off (fail closed, verify by default).
        // Only available in the detailed form -- a bare string host can't carry it.
        tls_skip_verify: Option<bool>,
    },
}

#[derive(Deserialize, Debug, Clone)]
pub struct YamlRouteCache {
    pub ttl: u64,
    pub max_size: Option<usize>,
    pub respect_headers: Option<bool>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct YamlRoute {
    #[serde(rename = "match")]
    pub match_: String,
    pub backends: Option<Vec<YamlBackend>>,
    pub method: Option<String>,
    pub header: Option<String>,
    pub absent_header: Option<String>,
    pub query: Option<String>,

    pub cookie: Option<String>,
    pub balance: Option<String>,
    pub connect: Option<u64>,
    pub response: Option<u64>,
    pub set_headers: Option<HashMap<String, String>>,
    pub validate: Option<Vec<YamlValidateRule>>,
    pub client_timeout: Option<u64>,
    pub max_body_size: Option<u64>,
    pub drop_threshold: Option<u8>,
    pub rate_limit: Option<u32>,
    pub allow_ip: Option<Vec<String>>,
    pub deny_ip: Option<Vec<String>>,
    pub jwt_secret: Option<String>,
    pub cache: Option<YamlRouteCache>,

    pub post: Option<String>,

    pub log_level: Option<String>,
    pub backend_pool_size: Option<usize>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct YamlDomain {
    #[serde(rename = "match")]
    pub match_: String,
    #[serde(default)]
    pub routes: Vec<YamlRoute>,
    pub default: Option<Vec<YamlBackend>>,
    pub balance: Option<String>,
    pub health: Option<String>,
    pub connect: Option<u64>,
    pub response: Option<u64>,
    pub set_headers: Option<HashMap<String, String>>,
    pub client_timeout: Option<u64>,
    pub max_body_size: Option<u64>,
    pub allow_ip: Option<Vec<String>>,
    pub deny_ip: Option<Vec<String>>,
    pub jwt_secret: Option<String>,

    pub cache: Option<YamlRouteCache>,

    pub log_level: Option<String>,
    pub backend_pool_size: Option<usize>,
    pub listen: Option<Vec<String>>,
    pub tls_listen: Option<Vec<String>>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    // Explicit SNI hostname(s) for this domain's cert. Needed when `match` is a real regex (from
    // which a literal hostname can't be derived); for a literal `match` it is auto-derived.
    pub tls_sni: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Balance {
    RoundRobin,
    Random,
    First,
    Leastconn,
    Weighted,
    Iphash,
    Urlhash,
}

#[derive(Debug, Clone)]
pub struct Hspec {
    pub path: String,
    pub interval: u64,
    pub timeout: u64,
    pub rise: i32,
    pub fall: i32,
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub response_to: u64,
    pub host: String,
    pub port: u16,
    pub addr: String,
    pub connect_to: u64,

    pub weight: u32,
    pub id: usize,
    pub tls: bool,
    /// Skip certificate verification for this backend's TLS connections (default false).
    pub tls_skip_verify: bool,
    pub state: SharedState,
}

#[derive(Debug, Clone)]
pub struct BackendList {
    pub backends: Vec<Backend>,
    pub balance: Balance,
}

#[derive(Debug, Clone)]
pub struct RouteCache {
    pub ttl: u64,
    pub max_size: usize,
    pub respect_headers: bool,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub allow_ip: Option<Vec<ipnet::IpNet>>,
    pub deny_ip: Option<Vec<ipnet::IpNet>>,
    pub jwt_secret: Option<String>,
    pub cache: Option<RouteCache>,
    pub post: Option<String>,

    pub re: Regex,
    pub bl: Option<BackendList>,
    pub method: Option<Vec<String>>,
    pub header: Option<Vec<String>>,
    pub absent_header: Option<Vec<String>>,
    pub query: Option<String>,

    pub cookie: Option<Vec<String>>,
    pub set_headers: Option<HashMap<String, String>>,
    pub validate: Vec<ValidateRule>,
    pub client_timeout: u64,
    pub max_body_size: u64,
    pub drop_threshold: Option<u8>,
    pub rate_limit: Option<u32>,

    pub log_level: Option<u8>,
    pub backend_pool_size: usize,
    pub id: usize, // Unique ID for rate limiting
}

#[derive(Debug, Clone)]
pub struct Domain {
    pub allow_ip: Option<Vec<ipnet::IpNet>>,
    pub deny_ip: Option<Vec<ipnet::IpNet>>,
    pub jwt_secret: Option<String>,
    #[allow(dead_code)]
    // domain cache is inherited into routes at load; not read directly at runtime
    pub cache: Option<RouteCache>,

    pub re: Regex,
    pub routes: Vec<Route>,
    pub def: Option<BackendList>,
    pub set_headers: Option<HashMap<String, String>>,
    pub client_timeout: u64,
    pub max_body_size: u64,

    pub log_level: Option<u8>,
    pub backend_pool_size: Option<usize>,
    pub listen: Vec<String>,
    pub tls_listen: Vec<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_sni: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub allow_ip: Option<Vec<ipnet::IpNet>>,
    pub deny_ip: Option<Vec<ipnet::IpNet>>,
    pub jwt_secret: Option<String>,
    pub cache: Option<RouteCache>,

    pub listen: Vec<String>,
    pub tls_listen: Vec<String>,
    pub listen_iface: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub metrics_listen: Option<String>,
    pub metrics_path: Option<String>,
    pub metrics_token: Option<String>,
    pub metrics_basic_auth: Option<String>,
    pub cache_max_bytes: usize,
    pub domains: Vec<Domain>,
    pub def: Option<BackendList>,
    pub set_headers: Option<HashMap<String, String>>,
    pub client_timeout: u64,
    pub max_body_size: u64,
    pub max_headers_size: u64,
    pub has_qos: bool,
    pub max_active_requests: usize,
    /// Canonicalise the request target before routing and forward the canonical form (default on).
    pub normalize_path: bool,
    /// Reject a percent-encoded path separator in the request-target with 400 (default off).
    pub reject_encoded_slash: bool,
    pub log_level: u8,

    pub workers: usize,
    pub backend_pool_size: usize,
    pub cpu_affinity: Option<String>,
    pub sqpoll: Option<String>,
    pub sqpoll_idle_ms: Option<u32>,
    pub uring_flags: Option<String>,
    pub worker_lifetime: Option<u64>,
    pub worker_max_requests: Option<u64>,
    pub worker_drain: u64,
}

/// Safety margin added on top of the max backend `response` timeout when auto-deriving the
/// recycle drain ceiling, so a request reading its last chunk right at the timeout still finishes.
const WORKER_DRAIN_MARGIN_SECS: u64 = 5;

pub struct ConfigLoader<'a> {
    next_backend_id: usize,
    shm: &'a SharedMemory,
    /// Largest backend `response` timeout seen across the whole config (global→domain→route→backend
    /// cascade). Used to auto-size the worker-recycle drain ceiling so in-flight requests within
    /// their allowed response time aren't cut mid-stream.
    max_response_to: u64,
}

impl<'a> ConfigLoader<'a> {
    pub fn new(shm: &'a SharedMemory) -> Self {
        Self {
            next_backend_id: 0,
            shm,
            max_response_to: 0,
        }
    }

    pub fn load(&mut self, path: &str) -> Result<(Config, Vec<(Backend, Option<Hspec>)>), String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;

        let env_re =
            Regex::new(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}|\$([a-zA-Z_][a-zA-Z0-9_]+)").unwrap();
        let expanded_content = env_re
            .replace_all(&content, |caps: &regex::Captures| {
                let var_name = caps.get(1).or_else(|| caps.get(2)).unwrap().as_str();
                // `$client_ip` (and its braced `${client_ip}`) is a per-request runtime macro
                // (expanded in set_headers), not an environment variable — leave the exact written
                // form intact so the braced spelling isn't silently resolved to an empty string.
                if var_name == "client_ip" {
                    return caps.get(0).unwrap().as_str().to_string();
                }
                std::env::var(var_name).unwrap_or_else(|_| "".to_string())
            })
            .to_string();

        let yc: YamlConfig = serde_yaml::from_str(&expanded_content).map_err(|e| e.to_string())?;

        let mut health_checks = Vec::new();
        let global_balance = match yc.balance.as_deref() {
            Some(s) => parse_balance(s)?,
            None => Balance::RoundRobin,
        };
        let global_health = yc.health.as_deref().and_then(parse_hspec);

        let workers_str = yc.workers.clone().unwrap_or_else(|| "auto".to_string());
        let mut workers = if workers_str == "auto" {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            workers_str.parse::<usize>().unwrap_or_else(|_| {
                eprintln!(
                    "Warning: Invalid workers value '{}', defaulting to auto",
                    workers_str
                );
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
            })
        };
        if workers > 256 {
            workers = 256;
        }
        // A numeric 0 parses fine and would silently start ZERO data-plane workers (master binds
        // listeners, forks nothing, serves nothing) — clamp to 1 with a warning instead.
        if workers == 0 {
            eprintln!("Warning: workers=0 would start no workers; clamping to 1");
            workers = 1;
        }

        let mut cfg = Config {
            listen: yc
                .listen
                .clone()
                .unwrap_or_else(|| vec!["0.0.0.0:80".to_string()]),
            tls_listen: yc.tls_listen.clone().unwrap_or_default(),
            listen_iface: yc.listen_iface.clone(),
            metrics_listen: yc.metrics_listen.clone(),
            metrics_path: yc
                .metrics_path
                .clone()
                .or_else(|| Some("/metrics".to_string())),
            metrics_token: yc.metrics_token.clone(),
            metrics_basic_auth: yc.metrics_basic_auth.clone(),
            cache_max_bytes: yc.cache_max_bytes.unwrap_or(100 * 1024 * 1024),
            tls_cert: yc
                .tls_cert
                .clone()
                .or_else(|| std::env::var("TLS_CERT_PATH").ok()),
            tls_key: yc
                .tls_key
                .clone()
                .or_else(|| std::env::var("TLS_KEY_PATH").ok()),
            log_level: parse_log_level(yc.log_level.as_deref().unwrap_or("info")),
            def: None,
            domains: Vec::new(),
            set_headers: yc.set_headers.clone(),
            client_timeout: yc.client_timeout.unwrap_or(60),
            max_body_size: yc.max_body_size.unwrap_or(2 * 1024 * 1024),
            max_headers_size: yc.max_headers_size.unwrap_or(8192),
            has_qos: false,
            max_active_requests: yc.max_active_requests.unwrap_or(10000),
            normalize_path: yc.normalize_path.unwrap_or(true),
            reject_encoded_slash: yc.reject_encoded_slash.unwrap_or(false),
            allow_ip: yc
                .allow_ip
                .map(|ips| parse_acl("allow_ip", ips))
                .transpose()?,
            deny_ip: yc
                .deny_ip
                .map(|ips| parse_acl("deny_ip", ips))
                .transpose()?,
            jwt_secret: yc.jwt_secret.clone(),
            cache: yc.cache.map(|c| RouteCache {
                ttl: c.ttl,
                max_size: c.max_size.unwrap_or(1048576), // 1MB default
                respect_headers: c.respect_headers.unwrap_or(false),
            }),
            workers,
            backend_pool_size: yc.backend_pool_size.unwrap_or(16),
            cpu_affinity: yc.cpu_affinity.clone(),
            sqpoll: yc.sqpoll.clone(),
            sqpoll_idle_ms: yc.sqpoll_idle_ms,
            uring_flags: yc.uring_flags.clone(),
            // Worker recycling: treat a 0 budget as "disabled" so it can never cause a fork storm.
            worker_lifetime: yc.worker_lifetime.filter(|&s| s > 0),
            worker_max_requests: yc.worker_max_requests.filter(|&n| n > 0),
            worker_drain: 0, // placeholder — resolved below from max backend `response` timeout
        };

        let g_connect = yc.connect.unwrap_or(5);
        let g_response = yc.response.unwrap_or(30);

        if let Some(def_backends) = yc.default {
            if let Some(bl) =
                self.parse_backend_list(&def_backends, global_balance, g_connect, g_response)?
            {
                for be in &bl.backends {
                    health_checks.push((be.clone(), global_health.clone()));
                }
                cfg.def = Some(bl);
            }
        }

        let mut route_id = 0;
        if let Some(yc_domains) = yc.domains {
            for yd in yc_domains {
                let d_balance = match yd.balance.as_deref() {
                    Some(s) => parse_balance(s)?,
                    None => global_balance,
                };
                let d_health = yd
                    .health
                    .as_deref()
                    .and_then(parse_hspec)
                    .or_else(|| global_health.clone());
                let d_client_timeout = yd.client_timeout.unwrap_or(cfg.client_timeout);
                let d_max_body_size = yd.max_body_size.unwrap_or(cfg.max_body_size);
                let d_connect = yd.connect.unwrap_or(g_connect);
                let d_response = yd.response.unwrap_or(g_response);
                let d_allow_ip = match yd.allow_ip {
                    Some(ips) => Some(parse_acl("allow_ip", ips)?),
                    None => cfg.allow_ip.clone(),
                };
                let d_deny_ip = match yd.deny_ip {
                    Some(ips) => Some(parse_acl("deny_ip", ips)?),
                    None => cfg.deny_ip.clone(),
                };
                let d_jwt_secret = yd.jwt_secret.clone().or_else(|| cfg.jwt_secret.clone());
                let d_cache = yd
                    .cache
                    .as_ref()
                    .map(|c| RouteCache {
                        ttl: c.ttl,
                        max_size: c.max_size.unwrap_or(1048576),
                        respect_headers: c.respect_headers.unwrap_or(false),
                    })
                    .or_else(|| cfg.cache.clone());

                let d_backend_pool_size = yd.backend_pool_size.or(Some(cfg.backend_pool_size));

                let mut domain = Domain {
                    re: Regex::new(&yd.match_).map_err(|_| format!("Bad regex: {}", yd.match_))?,
                    routes: Vec::new(),
                    def: None,
                    set_headers: yd.set_headers.clone(),
                    client_timeout: d_client_timeout,
                    max_body_size: d_max_body_size,
                    allow_ip: d_allow_ip.clone(),
                    deny_ip: d_deny_ip.clone(),
                    jwt_secret: d_jwt_secret.clone(),
                    cache: d_cache.clone(),
                    log_level: yd.log_level.as_deref().map(parse_log_level),
                    backend_pool_size: d_backend_pool_size,
                    listen: yd.listen.clone().unwrap_or_else(|| cfg.listen.clone()),
                    tls_listen: yd
                        .tls_listen
                        .clone()
                        .unwrap_or_else(|| cfg.tls_listen.clone()),
                    tls_cert: yd.tls_cert.clone(),
                    tls_key: yd.tls_key.clone(),
                    tls_sni: yd.tls_sni.clone(),
                };

                if let Some(def_str) = yd.default {
                    if let Some(bl) =
                        self.parse_backend_list(&def_str, d_balance, d_connect, d_response)?
                    {
                        for be in &bl.backends {
                            health_checks.push((be.clone(), d_health.clone()));
                        }
                        domain.def = Some(bl);
                    }
                }

                for yr in yd.routes {
                    let r_balance = match yr.balance.as_deref() {
                        Some(s) => parse_balance(s)?,
                        None => d_balance,
                    };
                    let r_connect = yr.connect.unwrap_or(d_connect);
                    let r_response = yr.response.unwrap_or(d_response);

                    let bl = if let Some(b_list) = yr.backends {
                        let parsed_bl =
                            self.parse_backend_list(&b_list, r_balance, r_connect, r_response)?;
                        if let Some(ref pbl) = parsed_bl {
                            for be in &pbl.backends {
                                health_checks.push((be.clone(), d_health.clone()));
                            }
                        }
                        parsed_bl
                    } else {
                        None
                    };

                    let mut validate = Vec::new();
                    if let Some(v_list) = yr.validate {
                        for v in v_list {
                            // `on_fail` itself is optional (defaults to reject-with-403) — only its
                            // inner fields used to have defaults, forcing an empty `on_fail: {}` to
                            // be written even when every default was wanted.
                            let on_fail = v.on_fail.unwrap_or(YamlValidateFail {
                                status: None,
                                body: None,
                                backends: None,
                            });
                            let mut fail_backends = Vec::new();
                            if let Some(fb) = on_fail.backends {
                                for yb in fb {
                                    fail_backends
                                        .push(self.parse_backend(&yb, r_connect, r_response)?);
                                }
                            }
                            let fail_bl = if fail_backends.is_empty() {
                                None
                            } else {
                                Some(BackendList {
                                    backends: fail_backends,
                                    balance: r_balance,
                                })
                            };

                            let v_regex = match v.regex.as_ref() {
                                Some(r) => Some(
                                    Regex::new(r)
                                        .map_err(|_| format!("Bad validate regex: {}", r))?,
                                ),
                                None => None,
                            };
                            validate.push(ValidateRule {
                                rule_type: v.rule_type,
                                name: v.name,
                                regex: v_regex,
                                invert: v.invert,
                                on_fail: ValidateFail {
                                    status: on_fail.status.unwrap_or(403),
                                    body: on_fail.body.unwrap_or_else(|| "Forbidden\n".to_string()),
                                    backends: fail_bl,
                                },
                            });
                        }
                    }

                    domain.routes.push(Route {
                        re: Regex::new(&yr.match_)
                            .map_err(|_| format!("Bad regex: {}", yr.match_))?,
                        bl,
                        method: yr
                            .method
                            .map(|s| s.split(',').map(|x| x.trim().to_uppercase()).collect()),
                        header: yr
                            .header
                            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect()),
                        absent_header: yr
                            .absent_header
                            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect()),
                        query: yr.query,
                        post: yr.post,
                        cookie: yr
                            .cookie
                            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect()),
                        set_headers: yr.set_headers.clone(),
                        validate,
                        client_timeout: yr.client_timeout.unwrap_or(d_client_timeout),
                        max_body_size: yr.max_body_size.unwrap_or(d_max_body_size),
                        drop_threshold: yr.drop_threshold.map(|pct| {
                            cfg.has_qos = true;
                            if pct > 100 {
                                100
                            } else {
                                pct
                            }
                        }),
                        rate_limit: yr.rate_limit,
                        allow_ip: match yr.allow_ip {
                            Some(ips) => Some(parse_acl("allow_ip", ips)?),
                            None => d_allow_ip.clone(),
                        },
                        deny_ip: match yr.deny_ip {
                            Some(ips) => Some(parse_acl("deny_ip", ips)?),
                            None => d_deny_ip.clone(),
                        },
                        jwt_secret: yr.jwt_secret.clone().or_else(|| d_jwt_secret.clone()),
                        cache: yr
                            .cache
                            .map(|c| RouteCache {
                                ttl: c.ttl,
                                max_size: c.max_size.unwrap_or(1048576),
                                respect_headers: c.respect_headers.unwrap_or(false),
                            })
                            .or_else(|| d_cache.clone()),

                        log_level: yr.log_level.as_deref().map(parse_log_level),
                        backend_pool_size: yr
                            .backend_pool_size
                            .unwrap_or(d_backend_pool_size.unwrap_or(cfg.backend_pool_size)),
                        id: route_id,
                    });
                    route_id += 1;
                }
                cfg.domains.push(domain);
            }
        }

        // Recycle drain ceiling: an explicit `worker_drain` wins; otherwise derive it from the
        // longest configured backend `response` timeout (+ margin), floored at 30s. This makes the
        // recycle wait long enough for a normal in-flight response to finish instead of cutting it
        // at an arbitrary flat timeout. Truly unbounded streams (websocket/SSE) can still exceed
        // it — raise `worker_drain` explicitly for those.
        cfg.worker_drain = yc.worker_drain.unwrap_or_else(|| {
            self.max_response_to
                .max(30)
                .saturating_add(WORKER_DRAIN_MARGIN_SECS)
        });

        Ok((cfg, health_checks))
    }

    fn parse_backend_list(
        &mut self,
        yb_list: &[YamlBackend],
        balance: Balance,
        default_conn: u64,
        default_resp: u64,
    ) -> Result<Option<BackendList>, String> {
        let mut backends = Vec::new();
        for yb in yb_list {
            backends.push(self.parse_backend(yb, default_conn, default_resp)?);
        }
        if backends.is_empty() {
            Ok(None)
        } else {
            Ok(Some(BackendList { backends, balance }))
        }
    }

    fn parse_backend(
        &mut self,
        yb: &YamlBackend,
        default_conn: u64,
        default_resp: u64,
    ) -> Result<Backend, String> {
        let (host_str, c, r, w, skip_verify) = match yb {
            YamlBackend::Simple(s) => (s.clone(), default_conn, default_resp, 1, false),
            YamlBackend::Detailed {
                host,
                connect,
                response,
                weight,
                tls_skip_verify,
            } => {
                if let Some(h) = host {
                    (
                        h.clone(),
                        connect.unwrap_or(default_conn),
                        response.unwrap_or(default_resp),
                        weight.unwrap_or(1),
                        tls_skip_verify.unwrap_or(false),
                    )
                } else {
                    return Err("Backend missing 'host' field".to_string());
                }
            }
        };

        let mut tls = false;
        let mut h_str = host_str.clone();
        if h_str.starts_with("https://") {
            tls = true;
            h_str = h_str.trim_start_matches("https://").to_string();
        } else if h_str.starts_with("http://") {
            h_str = h_str.trim_start_matches("http://").to_string();
        }

        let parts: Vec<&str> = h_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid backend format: {}", host_str));
        }
        let port = parts[1]
            .parse()
            .map_err(|_| format!("Invalid port in backend: {}", host_str))?;

        if skip_verify && !tls {
            return Err(format!("Backend '{}' sets tls_skip_verify but has no 'https://' host prefix — the flag would be a no-op", host_str));
        }

        self.max_response_to = self.max_response_to.max(r);
        let be = Backend {
            host: parts[0].to_string(),
            port,
            addr: format!("{}:{}", parts[0], port),
            connect_to: c,
            response_to: r,
            weight: w,
            id: self.next_backend_id,
            tls,
            tls_skip_verify: skip_verify,
            state: self.shm.get_state(self.next_backend_id),
        };
        self.next_backend_id += 1;
        Ok(be)
    }
}

fn parse_balance(s: &str) -> Result<Balance, String> {
    match s.to_lowercase().as_str() {
        "roundrobin" | "round_robin" | "rr" => Ok(Balance::RoundRobin),
        "random" => Ok(Balance::Random),
        "first" => Ok(Balance::First),
        "leastconn" => Ok(Balance::Leastconn),
        "weighted" => Ok(Balance::Weighted),
        "iphash" => Ok(Balance::Iphash),
        "urlhash" => Ok(Balance::Urlhash),
        _ => Err(format!("Unknown balance algorithm: {}", s)),
    }
}

/// Parse an `allow_ip`/`deny_ip` list, failing loudly on any malformed entry. ACL lists are
/// security-sensitive: silently dropping a typo'd `allow_ip` entry (`.filter_map(...ok())`) makes
/// the allowlist *more permissive* — exactly the wrong direction to fail open. Same
/// fail-loud-at-startup philosophy as the `tls_skip_verify`-without-`https://` rejection.
fn parse_acl(kind: &str, ips: Vec<String>) -> Result<Vec<ipnet::IpNet>, String> {
    let mut out = Vec::with_capacity(ips.len());
    for s in ips {
        out.push(
            s.parse::<ipnet::IpNet>()
                .map_err(|e| format!("Invalid network in {kind}: {s:?} ({e})"))?,
        );
    }
    Ok(out)
}

fn parse_hspec(s: &str) -> Option<Hspec> {
    let mut h = Hspec {
        path: "/".to_string(),
        interval: 5,
        timeout: 2,
        rise: 2,
        fall: 3,
    };
    for t in s.split_whitespace() {
        let parts: Vec<&str> = t.splitn(2, '=').collect();
        if parts.len() == 2 {
            match parts[0] {
                "path" => h.path = parts[1].to_string(),
                "interval" => h.interval = parts[1].parse().unwrap_or(5),
                "timeout" => h.timeout = parts[1].parse().unwrap_or(2),
                "rise" => h.rise = parts[1].parse().unwrap_or(2),
                "fall" => h.fall = parts[1].parse().unwrap_or(3),
                _ => {}
            }
        }
    }
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_yaml_helper(contents: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("rproxy_test_{}_{}.yml", std::process::id(), id));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn test_parse_hspec() {
        let h1 = parse_hspec("path=/health interval=10 timeout=5 rise=3 fall=4").unwrap();
        assert_eq!(h1.path, "/health");
        assert_eq!(h1.interval, 10);
        assert_eq!(h1.timeout, 5);
        assert_eq!(h1.rise, 3);
        assert_eq!(h1.fall, 4);

        let h2 = parse_hspec("path=/").unwrap();
        assert_eq!(h2.path, "/");
        assert_eq!(h2.interval, 5);
        assert_eq!(h2.timeout, 2);
        assert_eq!(h2.rise, 2);
        assert_eq!(h2.fall, 3);

        let h3 = parse_hspec("invalid=yes").unwrap();
        assert_eq!(h3.path, "/");
    }

    #[test]
    fn test_parse_hspec_defaults_and_garbage() {
        let h = parse_hspec("").unwrap();
        assert_eq!(h.path, "/");
        assert_eq!(h.interval, 5);
        assert_eq!(h.timeout, 2);
        assert_eq!(h.rise, 2);
        assert_eq!(h.fall, 3);

        let h2 = parse_hspec("garbage").unwrap();
        assert_eq!(h2.path, "/");
        assert_eq!(h2.interval, 5);
    }

    #[test]
    fn test_parse_log_level() {
        assert_eq!(parse_log_level("error"), 1);
        assert_eq!(parse_log_level("warn"), 2);
        assert_eq!(parse_log_level("info"), 3);
        assert_eq!(parse_log_level("debug"), 4);
        assert_eq!(parse_log_level("trace"), 5);
        assert_eq!(parse_log_level("none"), 0);
        assert_eq!(parse_log_level("off"), 0);
        assert_eq!(parse_log_level("bogus"), 3);
        assert_eq!(parse_log_level("ERROR"), 1);
        assert_eq!(parse_log_level("NONE"), 0);
    }

    #[test]
    fn test_parse_balance() {
        assert_eq!(parse_balance("roundrobin").unwrap(), Balance::RoundRobin);
        assert_eq!(parse_balance("round_robin").unwrap(), Balance::RoundRobin);
        assert_eq!(parse_balance("rr").unwrap(), Balance::RoundRobin);
        assert_eq!(parse_balance("ROUNDROBIN").unwrap(), Balance::RoundRobin);
        assert_eq!(parse_balance("RR").unwrap(), Balance::RoundRobin);
        assert_eq!(parse_balance("random").unwrap(), Balance::Random);
        assert_eq!(parse_balance("first").unwrap(), Balance::First);
        assert_eq!(parse_balance("leastconn").unwrap(), Balance::Leastconn);
        assert_eq!(parse_balance("weighted").unwrap(), Balance::Weighted);
        assert_eq!(parse_balance("iphash").unwrap(), Balance::Iphash);
        assert_eq!(parse_balance("urlhash").unwrap(), Balance::Urlhash);
        assert!(parse_balance("totally_invalid").is_err());
    }

    #[test]
    fn test_load_minimal() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path =
            write_temp_yaml_helper("listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\n");
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.client_timeout, 60);
        assert_eq!(cfg.max_body_size, 2097152);
        assert_eq!(cfg.max_headers_size, 8192);
        assert_eq!(cfg.max_active_requests, 10000);
        assert!(cfg.normalize_path);
        assert!(!cfg.reject_encoded_slash);
        assert_eq!(cfg.cache_max_bytes, 104857600);
    }

    #[test]
    fn test_load_workers_clamp() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nworkers: \"999\"\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.workers, 256);
    }

    #[test]
    fn test_load_workers_invalid() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nworkers: \"not_a_number\"\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert!(cfg.workers >= 1 && cfg.workers <= 256);
    }

    #[test]
    fn test_load_workers_zero_clamped_to_one() {
        // A numeric 0 must not silently start zero data-plane workers.
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nworkers: \"0\"\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.workers, 1);
    }

    #[test]
    fn test_load_acl_invalid_entry_fails_loud() {
        // A typo'd allow_ip entry must fail the load, not be silently dropped (dropping widens
        // the allowlist = fails open).
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nallow_ip:\n  - \"10.0.0.0/8\"\n  - \"not-an-ip\"\n",
        );
        let result = loader.load(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("allow_ip"));
    }

    #[test]
    fn test_load_acl_invalid_domain_entry_fails_loud() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\ndomains:\n  - match: \"x.example.com\"\n    allow_ip: [\"10.0.0.0/33\"]\n",
        );
        let result = loader.load(path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_backend_missing_host() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - addr: \"127.0.0.1:2\"\n",
        );
        let result = loader.load(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("host"));
    }

    #[test]
    fn test_load_tls_skip_verify_without_https_is_rejected() {
        // The flag would silently be a no-op on a plain (non-TLS) backend -- parse_backend must
        // refuse this at load time rather than accept a config that looks like it does something
        // it doesn't (fail-loud-at-startup, matching the missing-host case just above).
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - host: \"127.0.0.1:2\"\n    tls_skip_verify: true\n",
        );
        let result = loader.load(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tls_skip_verify"));
    }

    #[test]
    fn test_load_tls_skip_verify_with_https_is_accepted() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - host: \"https://127.0.0.1:2\"\n    tls_skip_verify: true\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        let be = &cfg.def.unwrap().backends[0];
        assert!(be.tls);
        assert!(be.tls_skip_verify);
    }

    #[test]
    fn test_load_tls_skip_verify_defaults_false() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - host: \"https://127.0.0.1:2\"\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert!(!cfg.def.unwrap().backends[0].tls_skip_verify);
    }

    #[test]
    fn test_load_tls_skip_verify_simple_string_form_defaults_false() {
        // YamlBackend::Simple(String) (the bare "host:port" form) can't carry the flag at all --
        // confirm it parses to false rather than erroring or inheriting some other default.
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"https://127.0.0.1:2\"\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        let be = &cfg.def.unwrap().backends[0];
        assert!(be.tls);
        assert!(!be.tls_skip_verify);
    }

    #[test]
    fn test_load_unknown_top_level_key() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nbogus_key: 123\n",
        );
        let result = loader.load(path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_invalid_balance() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nbalance: \"totally_invalid\"\n",
        );
        let result = loader.load(path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_env_var_substitution() {
        let env_name = "RPROXY_TEST_ENV_SUBST_A";
        let env_val = "hello_from_env";
        std::env::set_var(env_name, env_val);
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let yaml = format!(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nset_headers:\n  X-Custom: \"${{{}}}\"\n",
            env_name
        );
        let path = write_temp_yaml_helper(&yaml);
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        let headers = cfg.set_headers.as_ref().unwrap();
        assert_eq!(headers.get("X-Custom").unwrap(), env_val);
    }

    #[test]
    fn test_load_client_ip_not_substituted() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nset_headers:\n  X-Forwarded-For: $client_ip\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        let headers = cfg.set_headers.as_ref().unwrap();
        assert_eq!(headers.get("X-Forwarded-For").unwrap(), "$client_ip");
    }

    #[test]
    fn test_load_braced_client_ip_not_substituted() {
        // The braced spelling `${client_ip}` is the same runtime macro — it must not be resolved
        // as an env var (which would silently become an empty string).
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nset_headers:\n  X-Forwarded-For: ${client_ip}\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        let headers = cfg.set_headers.as_ref().unwrap();
        assert_eq!(headers.get("X-Forwarded-For").unwrap(), "${client_ip}");
    }

    #[test]
    fn test_load_worker_lifetime_zero() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nworker_lifetime: 0\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.worker_lifetime, None);
    }

    #[test]
    fn test_load_worker_drain_from_response() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\nresponse: 45\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.worker_drain, 50);
    }

    #[test]
    fn test_load_domain_client_timeout_cascade() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\ndomains:\n  - match: \"x.example.com\"\n    client_timeout: 10\n    routes:\n      - match: \"/api\"\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.domains[0].routes[0].client_timeout, 10);
    }

    #[test]
    fn test_load_validate_defaults() {
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\ndomains:\n  - match: \"x.example.com\"\n    routes:\n      - match: \"/api\"\n        validate:\n          - type: header\n            name: X-Token\n            on_fail: {}\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.domains[0].routes[0].validate[0].on_fail.status, 403);
        assert_eq!(
            cfg.domains[0].routes[0].validate[0].on_fail.body,
            "Forbidden\n"
        );
    }

    #[test]
    fn test_load_validate_on_fail_fully_omitted() {
        // `on_fail` itself must now be omittable entirely (not just `on_fail: {}`) — this is the
        // fix for the SUSPECT item found during the coverage pass.
        let shm = crate::shared::SharedMemory::new(16);
        let mut loader = ConfigLoader::new(&shm);
        let path = write_temp_yaml_helper(
            "listen: [\"127.0.0.1:1\"]\ndefault:\n  - \"127.0.0.1:2\"\ndomains:\n  - match: \"x.example.com\"\n    routes:\n      - match: \"/api\"\n        validate:\n          - type: header\n            name: X-Token\n",
        );
        let (cfg, _) = loader.load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.domains[0].routes[0].validate[0].on_fail.status, 403);
        assert_eq!(
            cfg.domains[0].routes[0].validate[0].on_fail.body,
            "Forbidden\n"
        );
    }
}
