//! Tests for config parsing — YAML valid/invalid, ${VAR} env substitution,
//! unknown keys silently ignored, route matching, ACL limits.
//!
//! DOC-DRIVEN: per rproxy README "Конфигурация → Как читается файл":
//!   - YAML format; ${VAR} and $VAR replaced with env value (empty if missing)
//!   - Unknown keys silently ignored (no deny_unknown_fields)
//!   - Balance unknown value = load error

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper: write a YAML config to a temp file and return its path.
fn write_config(content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rproxy.yml");
    fs::write(&path, content).unwrap();
    (dir, path)
}

/// Helper: load config via ConfigLoader and return Ok or Err.
/// `ConfigLoader::load` returns `(Config, Vec<(Backend, Option<Hspec>)>)`; tests that only
/// care about the config discard the health-check list.
fn load_config(path: &std::path::Path) -> Result<rproxy::config::Config, String> {
    let shm = rproxy::shared::SharedMemory::new(16);
    let mut loader = rproxy::config::ConfigLoader::new(&shm);
    loader
        .load(path.to_str().unwrap())
        .map(|(cfg, _)| cfg)
        .map_err(|e| e.to_string())
}

/// Helper: load config AND the per-backend health-check specs, for tests that verify `health:`.
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
// YAML parsing — valid configs
// ---------------------------------------------------------------------------

#[test]
fn config_minimal_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
workers: "auto"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("minimal config should parse");
    assert_eq!(cfg.listen.len(), 1);
    assert_eq!(cfg.listen[0], "0.0.0.0:80");
}

#[test]
fn config_domains_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "api.example.com"
    routes:
      - match: "/v1/"
        method: "GET,POST"
        backends:
          - "10.0.0.5:8080"
"#,
    );
    let cfg = load_config(&path).expect("domains config should parse");
    assert_eq!(cfg.domains.len(), 1);
    assert_eq!(cfg.domains[0].re.as_str(), "api.example.com");
}

#[test]
fn config_balance_weighted_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
balance: "weighted"
default:
  - host: "10.0.0.5:8080"
    weight: 3
  - host: "10.0.0.6:8080"
    weight: 1
"#,
    );
    let cfg = load_config(&path).expect("weighted config should parse");
    // Top-level `balance:` lands on the default backend list (Config has no bare `balance` field).
    assert_eq!(
        cfg.def.as_ref().unwrap().balance,
        rproxy::config::Balance::Weighted
    );
}

#[test]
fn config_health_spec_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
health: "path=/healthz interval=5 fall=2"
default:
  - "127.0.0.1:8081"
"#,
    );
    let (cfg, health_checks) = load_config_with_health(&path).expect("health spec should parse");
    // `health:` doesn't live on Config — it is materialised as per-backend health-check specs
    // returned alongside the config by ConfigLoader::load.
    assert_eq!(cfg.def.as_ref().unwrap().backends.len(), 1);
    assert!(
        health_checks.iter().any(|(_, h)| h.is_some()),
        "backend should get a health spec"
    );
}

#[test]
fn config_metrics_auth_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
metrics_listen: "127.0.0.1:9090"
metrics_token: "secret-token"
metrics_basic_auth: "admin:pass123"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("metrics auth config should parse");
    assert_eq!(cfg.metrics_token.as_deref(), Some("secret-token"));
    assert_eq!(cfg.metrics_basic_auth.as_deref(), Some("admin:pass123"));
}

// ---------------------------------------------------------------------------
// YAML parsing — invalid configs (should fail)
// ---------------------------------------------------------------------------

#[test]
fn config_invalid_yaml_syntax() {
    let (_dir, path) = write_config(
        r#"
listen: [invalid yaml {{{
default:
  - "127.0.0.1:8081"
"#,
    );
    let result = load_config(&path);
    assert!(result.is_err(), "invalid YAML should fail to parse");
}

#[test]
fn config_unknown_balance_fails() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
balance: "nonexistent_algorithm"
default:
  - "127.0.0.1:8081"
"#,
    );
    let result = load_config(&path);
    assert!(result.is_err(), "unknown balance algorithm should fail");
}

#[test]
fn config_backend_missing_host_fails() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
default:
  - weight: 1
"#,
    );
    let result = load_config(&path);
    assert!(result.is_err(), "backend without host should fail");
}

#[test]
fn config_missing_required_listen_fails() {
    let (_dir, path) = write_config(
        r#"
default:
  - "127.0.0.1:8081"
"#,
    );
    // listen is optional in YAML (defaults to ["0.0.0.0:80"]), so this should parse
    let cfg = load_config(&path);
    assert!(cfg.is_ok(), "missing listen should use default");
}

// ---------------------------------------------------------------------------
// ${VAR} env substitution
// ---------------------------------------------------------------------------

#[test]
fn config_env_substitution_replaces_value() {
    std::env::set_var("RPX_DEPLOY_ENV", "production");
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
set_headers:
  X-Env: "${RPX_DEPLOY_ENV}"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("config with env var should parse");
    if let Some(headers) = &cfg.set_headers {
        assert_eq!(headers.get("X-Env").unwrap(), "production");
    }
    std::env::remove_var("RPX_DEPLOY_ENV");
}

#[test]
fn config_env_substitution_missing_var_becomes_empty() {
    // Ensure the var does NOT exist
    std::env::remove_var("NONEXISTENT_VAR_RPX_TEST");
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
set_headers:
  X-Missing: "${NONEXISTENT_VAR_RPX_TEST}"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("missing env var should become empty string");
    if let Some(headers) = &cfg.set_headers {
        assert_eq!(headers.get("X-Missing").unwrap(), "");
    }
}

#[test]
fn config_env_dollar_var_syntax() {
    std::env::set_var("RPX_HOST", "prod.example.com");
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
set_headers:
  X-Host: "$RPX_HOST"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("$VAR syntax should also substitute");
    if let Some(headers) = &cfg.set_headers {
        assert_eq!(headers.get("X-Host").unwrap(), "prod.example.com");
    }
    std::env::remove_var("RPX_HOST");
}

// ---------------------------------------------------------------------------
// Unknown keys silently ignored
// ---------------------------------------------------------------------------

#[test]
fn config_unknown_keys_ignored() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
totally_unknown_key: "should be ignored"
another_weird_field: 12345
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("unknown keys should be silently ignored");
    assert_eq!(cfg.listen.len(), 1); // still parsed correctly
}

#[test]
fn config_unknown_route_keys_ignored() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "example.com"
    routes:
      - match: "/api/"
        method: "GET"
        backends:
          - "127.0.0.1:8081"
        some_fake_route_key: true
"#,
    );
    let cfg = load_config(&path).expect("unknown route keys should be ignored");
    assert_eq!(cfg.domains.len(), 1);
    assert_eq!(cfg.domains[0].routes.len(), 1);
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

#[test]
fn config_literal_match_exact() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "api.example.com"
    routes:
      - match: "/v1/"
        backends:
          - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("literal domain match should parse");
    assert_eq!(cfg.domains[0].re.as_str(), "api.example.com");
}

#[test]
fn config_regex_match_parsed() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "^api.*\\.example\\.com$"
    routes:
      - match: "/v1/"
        backends:
          - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("regex domain match should parse");
    // Regex matches contain metacharacters — the loader compiles them into Domain.re as-is
    assert!(cfg.domains[0].re.as_str().contains('.'));
}

#[test]
fn config_route_prefix_match() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "example.com"
    routes:
      - match: "/api/"
        backends:
          - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("prefix route match should parse");
    assert_eq!(cfg.domains[0].routes[0].re.as_str(), "/api/");
}

// ---------------------------------------------------------------------------
// ACL limits
// ---------------------------------------------------------------------------

#[test]
fn config_acl_allow_ip_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
allow_ip:
  - "10.0.0.0/8"
  - "192.168.0.0/16"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("allow_ip ACL should parse");
    assert_eq!(cfg.allow_ip.as_ref().unwrap().len(), 2);
}

#[test]
fn config_acl_deny_ip_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
deny_ip:
  - "0.0.0.0/0"
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("deny_ip ACL should parse");
    assert_eq!(cfg.deny_ip.as_ref().unwrap().len(), 1);
}

#[test]
fn config_rate_limit_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
domains:
  - match: "example.com"
    routes:
      - match: "/"
        rate_limit: 5000
        backends:
          - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("rate_limit should parse");
    assert_eq!(cfg.domains[0].routes[0].rate_limit.unwrap(), 5000);
}

#[test]
fn config_max_body_size_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
max_body_size: 10485760
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("max_body_size should parse");
    assert_eq!(cfg.max_body_size, 10485760);
}

#[test]
fn config_max_headers_size_valid() {
    let (_dir, path) = write_config(
        r#"
listen:
  - "0.0.0.0:80"
max_headers_size: 16384
default:
  - "127.0.0.1:8081"
"#,
    );
    let cfg = load_config(&path).expect("max_headers_size should parse");
    assert_eq!(cfg.max_headers_size, 16384);
}

// ---------------------------------------------------------------------------
// Balance algorithm variants
// ---------------------------------------------------------------------------

#[test]
fn config_balance_roundrobin_aliases() {
    for alias in &["roundrobin", "round_robin", "rr"] {
        let (_dir, path) = write_config(&format!(
            r#"
listen:
  - "0.0.0.0:80"
balance: "{}"
default:
  - "127.0.0.1:8081"
"#,
            alias
        ));
        let cfg =
            load_config(&path).unwrap_or_else(|_| panic!("balance alias '{}' should work", alias));
        assert_eq!(
            cfg.def.as_ref().unwrap().balance,
            rproxy::config::Balance::RoundRobin
        );
    }
}

#[test]
fn config_balance_all_algorithms_valid() {
    for alg in &[
        "roundrobin",
        "random",
        "first",
        "leastconn",
        "weighted",
        "iphash",
        "urlhash",
    ] {
        let (_dir, path) = write_config(&format!(
            r#"
listen:
  - "0.0.0.0:80"
balance: "{}"
default:
  - "127.0.0.1:8081"
"#,
            alg
        ));
        let result = load_config(&path);
        assert!(result.is_ok(), "balance '{}' should be valid", alg);
    }
}
