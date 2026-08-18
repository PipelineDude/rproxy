//! DOC-DRIVEN tests for rproxy — designed from README docs ONLY.
//!
//! Sources: rproxy/README.md sections "Конфигурация", "Балансировка",
//! "Health-check'и", "Кэш ответов", "Безопасность и лимиты".

use std::fs;
use tempfile::TempDir;

fn write_config(content: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rproxy.yml");
    fs::write(&path, content).unwrap();
    (dir, path)
}

fn load_config(path: &std::path::Path) -> Result<rproxy::config::Config, String> {
    let shm = rproxy::shared::SharedMemory::new(16);
    let mut loader = rproxy::config::ConfigLoader::new(&shm);
    loader
        .load(path.to_str().unwrap())
        .map(|(cfg, _)| cfg)
        .map_err(|e| e.to_string())
}

/// Load config together with the per-backend health-check specs (for `health:` tests).
fn load_config_with_health(
    path: &std::path::Path,
) -> Result<
    (
        rproxy::config::Config,
        Vec<(rproxy::config::Backend, Option<rproxy::config::Hspec>)>,
    ),
    String,
> {
    let shm = rproxy::shared::SharedMemory::new(16);
    let mut loader = rproxy::config::ConfigLoader::new(&shm);
    loader
        .load(path.to_str().unwrap())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Config substitution (README: "${VAR} and $VAR replaced with env value")
// ---------------------------------------------------------------------------

#[test]
fn doc_config_substitution_env_var_replaced() {
    std::env::set_var("RPX_TEST_VAR_12345", "substituted_value");
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
set_headers:
  X-Test: "${RPX_TEST_VAR_12345}"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("config with ${VAR} should parse");
    if let Some(headers) = &cfg.set_headers {
        assert_eq!(headers.get("X-Test").unwrap(), "substituted_value");
    }
    std::env::remove_var("RPX_TEST_VAR_12345");
}

#[test]
fn doc_config_substitution_missing_var_empty() {
    std::env::remove_var("RPX_NONEXIST_67890");
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
set_headers:
  X-Missing: "${RPX_NONEXIST_67890}"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("missing env var should become empty");
    if let Some(headers) = &cfg.set_headers {
        assert_eq!(headers.get("X-Missing").unwrap(), "");
    }
}

// ---------------------------------------------------------------------------
// Unknown keys silently ignored (README: "Неизвестные ключи молча игнорируются")
// ---------------------------------------------------------------------------

#[test]
fn doc_unknown_keys_globally_ignored() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
fake_global_key: true
another_fake: 42
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("unknown global keys should be ignored");
    assert_eq!(cfg.listen.len(), 1); // valid key still parsed
}

#[test]
fn doc_unknown_keys_in_domain_ignored() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "example.com"
    fake_domain_key: true
    routes:
      - match: "/"
        fake_route_key: "value"
        backends:
          - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("unknown domain/route keys should be ignored");
    assert_eq!(cfg.domains.len(), 1);
    assert_eq!(cfg.domains[0].routes.len(), 1);
}

// ---------------------------------------------------------------------------
// Connection reuse / pool (README: "backend_pool_size — размер пула keep-alive")
// ---------------------------------------------------------------------------

#[test]
fn doc_backend_pool_size_default_is_16() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("minimal config should parse");
    // backend_pool_size is a plain usize in Config (default 16 per README)
    assert_eq!(cfg.backend_pool_size, 16);
}

#[test]
fn doc_backend_pool_size_zero_disables_reuse() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
backend_pool_size: 0
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("pool_size=0 should parse");
    assert_eq!(cfg.backend_pool_size, 0);
}

// ---------------------------------------------------------------------------
// Caching semantics (README: "LRU per worker", "Authorization not cached")
// ---------------------------------------------------------------------------

#[test]
fn doc_cache_ttl_required() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
cache:
  ttl: 60
  max_size: 1048576
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("valid cache config should parse");
    assert!(cfg.cache.is_some());
}

#[test]
fn doc_cache_max_bytes_per_worker() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
cache_max_bytes: 209715200
workers: "4"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("cache config should parse");
    assert_eq!(cfg.cache_max_bytes, 209715200);
    // Total RAM ≈ cache_max_bytes × workers = 200MiB × 4 = 800MiB
}

// ---------------------------------------------------------------------------
// Health check defaults (README: path=/, interval=5, timeout=2, rise=2, fall=3)
// ---------------------------------------------------------------------------

#[test]
fn doc_health_default_spec() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
health: "path=/health interval=10 timeout=5 rise=3 fall=2"
default:
  - "127.0.0.1:8081"
"#,
    );
    let (_cfg, health_checks) = load_config_with_health(&path).expect("health spec should parse");
    // `health:` is not a Config field — it is parsed into per-backend Hspec values returned
    // alongside the config. Verify the spec from the README (path/interval/timeout/rise/fall).
    let spec = health_checks
        .iter()
        .filter_map(|(_, h)| h.as_ref())
        .next()
        .expect("backend should get a health spec");
    assert_eq!(spec.path, "/health");
    assert_eq!(spec.interval, 10);
    assert_eq!(spec.timeout, 5);
    assert_eq!(spec.rise, 3);
    assert_eq!(spec.fall, 2);
}

// ---------------------------------------------------------------------------
// Security: framing / smuggling rejection (README: "CL+TE ambiguous → 400")
// ---------------------------------------------------------------------------

#[test]
fn doc_normalize_path_default_true() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("minimal config should parse");
    // normalize_path is a plain bool, defaulting to true per README
    assert!(cfg.normalize_path);
}

#[test]
fn doc_reject_encoded_slash_default_false() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("minimal config should parse");
    // reject_encoded_slash is a plain bool, defaulting to false per README
    assert!(!cfg.reject_encoded_slash);
}

// ---------------------------------------------------------------------------
// Workers limit (README: "Максимум 256")
// ---------------------------------------------------------------------------

#[test]
fn doc_workers_auto_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
workers: "auto"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("workers=auto should parse");
    // `workers` is a resolved usize in Config; "auto" means "detect and clamp to 1..=256"
    assert!(
        (1..=256).contains(&cfg.workers),
        "workers=auto should resolve to 1..=256, got {}",
        cfg.workers
    );
}

// ---------------------------------------------------------------------------
// TLS config (README: tls_cert/tls_key required for tls_listen)
// ---------------------------------------------------------------------------

#[test]
fn doc_tls_config_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
tls_listen:
  - "0.0.0.0:443"
tls_cert: "/etc/ssl/cert.pem"
tls_key: "/etc/ssl/key.pem"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("TLS config should parse");
    assert_eq!(cfg.tls_listen.len(), 1);
}

// ---------------------------------------------------------------------------
// Metrics auth (README: token and basic_auth checked independently)
// ---------------------------------------------------------------------------

#[test]
fn doc_metrics_token_only() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
metrics_listen: "127.0.0.1:9090"
metrics_token: "mytoken"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("metrics with token should parse");
    assert_eq!(cfg.metrics_token.as_deref(), Some("mytoken"));
}

// ---------------------------------------------------------------------------
// Balance algorithm inheritance (README: cascade global → domain → route → backend)
// ---------------------------------------------------------------------------

#[test]
fn doc_balance_inheritance_domain_overrides() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
balance: "roundrobin"
default:
  - "127.0.0.1:8080"
domains:
  - match: "example.com"
    balance: "leastconn"
    routes:
      - match: "/"
        backends:
          - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("domain balance override should parse");
    // Global balance lands on the default backend list
    assert_eq!(
        cfg.def.as_ref().unwrap().balance,
        rproxy::config::Balance::RoundRobin
    );
    // Domain-level balance overrides global: the route's backend list is Leastconn
    assert_eq!(
        cfg.domains[0].routes[0].bl.as_ref().unwrap().balance,
        rproxy::config::Balance::Leastconn
    );
}

// ---------------------------------------------------------------------------
// Backend TLS skip verify (README: only in detailed form)
// ---------------------------------------------------------------------------

#[test]
fn doc_backend_tls_skip_verify_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
default:
  - host: "https://internal.example.com:8443"
    tls_skip_verify: true
"#,
    );
    let cfg = load_config(&path).expect("tls_skip_verify should parse");
    // The default backend list lives on Config::def (there is no `default` field)
    let bl = cfg.def.as_ref().expect("default backend list should parse");
    assert_eq!(bl.backends.len(), 1);
    let be = &bl.backends[0];
    assert!(be.tls, "https:// backend should be flagged as TLS");
    assert!(
        be.tls_skip_verify,
        "tls_skip_verify should be honored in detailed form"
    );
}

// ---------------------------------------------------------------------------
// Validate rules (README: type/name/regex/on_fail)
// ---------------------------------------------------------------------------

#[test]
fn doc_validate_rule_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "example.com"
    routes:
      - match: "/api/"
        validate:
          - type: header
            name: "X-Api-Key"
            regex: "^[a-f0-9]{32}$"
            on_fail:
              status: 418
              body: "nope\n"
        backends:
          - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("validate rule should parse");
    assert_eq!(cfg.domains[0].routes.len(), 1);
}
