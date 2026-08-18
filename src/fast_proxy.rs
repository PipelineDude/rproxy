use crate::backend::{connect_backend, BackendStream};
use crate::balancer::BalancerState;
use crate::buf_pool::{get_buf, put_buf, PooledBuf, BUF_SIZE};
use crate::config::{Config, Route};
use crate::jwt::jwt_claim_u64;
use monoio::buf::{Slice, SliceMut};
use monoio::io::AsyncWriteRentExt;
use monoio::net::TcpListener;
use monoio_rustls::TlsAcceptor;
use std::sync::Arc;
use tracing::debug;

// Pure header/path helpers live in src/header_util.rs (2026-08-15, review
// follow-up: this file was 4400+ lines). The `pub use` ones are the value
// types / compiled-header helpers the public interface exposes (the binary
// crate references `rproxy::fast_proxy::HeaderFragment` etc.); the
// `pub(crate) use` ones are hot-path helpers used only within this module.
pub(crate) use crate::header_util::{
    buf_put, contains_ci, eval_field_conditions, find_ci, host_without_port, needs_path_normalize,
    normalize_path_into, path_has_separator_evasion, te_is_chunked,
};
// Only the unit tests reference this one directly now (its production caller,
// Matcher::exact_or_re/prefix_or_re, lives inside header_util).
#[cfg(test)]
pub(crate) use crate::header_util::is_plain_literal;
pub use crate::header_util::{compile_header_names, compile_headers, HeaderFragment, Matcher};

// --- Tunables (formerly magic numbers) ---
const JWT_CACHE_MAX: usize = 10_000;
const JWT_CACHE_TTL_SECS: u64 = 300;
const RATE_LIMIT_MAP_MAX: usize = 100_000;
const RESPONSE_CACHE_MAX_BYTES: usize = 100 * 1024 * 1024;
const MAX_BACKEND_TRIES: usize = 3;

/// A backend connection, either plain TCP or TLS-over-TCP. Fixes a bug where `https://` backends
/// were health-checked over TLS but proxied data in cleartext — `be.tls` was read only by
/// health.rs, the data plane always did a raw `TcpStream::connect`). One enum keeps the pool
/// (`BACKEND_POOL`) and the generic `read_fast`/`write_all_fast`/`pipe_body` helpers unchanged;
/// they only require `AsyncReadRent`/`AsyncWriteRent`, which both variants implement below.
struct CacheEntry {
    data: bytes::Bytes,
    expires_at: std::time::Instant,
    etag: Option<String>,
    last_modified: Option<String>,
}

struct SizedCache {
    lru: lru::LruCache<u64, CacheEntry>,
    total_bytes: usize,
    max_bytes: usize,
}

impl SizedCache {
    fn new(max_bytes: usize) -> Self {
        SizedCache {
            lru: lru::LruCache::unbounded(),
            total_bytes: 0,
            max_bytes,
        }
    }

    fn put(&mut self, key: u64, entry: CacheEntry) {
        let size = entry.data.len();
        if let Some(old) = self.lru.put(key, entry) {
            self.total_bytes -= old.data.len();
        }
        self.total_bytes += size;

        while self.total_bytes > self.max_bytes && !self.lru.is_empty() {
            if let Some((_, old)) = self.lru.pop_lru() {
                self.total_bytes -= old.data.len();
            }
        }
    }

    fn get(&mut self, key: &u64) -> Option<&CacheEntry> {
        self.lru.get(key)
    }

    fn remove(&mut self, key: &u64) {
        if let Some(old) = self.lru.pop(key) {
            self.total_bytes -= old.data.len();
        }
    }
}

thread_local! {
    // `const {}` init: these are touched on every request, so const-initialization removes the
    // per-access lazy-init guard (slightly faster hot path) on top of being lock-free thread-per-core.
    static ACTIVE_REQUESTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    // Worker-recycling counters (opt-in via worker_max_requests / worker_lifetime). REQUESTS_SERVED
    // is a monotonic per-worker count of handled requests; RECYCLE_SHUTDOWN is set by the recycle
    // monitor task to start a graceful drain. Both are single-thread (thread-per-core), no locks.
    static REQUESTS_SERVED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static RECYCLE_SHUTDOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static RATE_LIMITS: std::cell::RefCell<std::collections::HashMap<(usize, std::net::IpAddr), (u64, u32)>> = std::cell::RefCell::new(std::collections::HashMap::new());
    // Per-worker response-cache byte budget. Set once at worker start from `cache_max_bytes`
    // (run_worker) BEFORE any request touches RESPONSE_CACHE, so the cache is built with the
    // configured budget rather than the compile-time default.
    static CACHE_MAX_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(RESPONSE_CACHE_MAX_BYTES) };
    static RESPONSE_CACHE: std::cell::RefCell<SizedCache> = std::cell::RefCell::new(SizedCache::new(CACHE_MAX_BYTES.with(|c| c.get())));
    // Maps token -> (expiry, secret_hash). The secret_hash binds a cached validation to the
    // specific `jwt_secret` it passed, so a token cached for one domain/route cannot satisfy a
    // different route that uses a different secret (cross-secret auth bypass).
    static JWT_CACHE: std::cell::RefCell<std::collections::HashMap<String, (std::time::Instant, [u8; 16])>> = std::cell::RefCell::new(std::collections::HashMap::new());
    static BACKEND_POOL: std::cell::RefCell<std::collections::HashMap<usize, std::collections::VecDeque<BackendStream>>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Build the upstream request head into `x`.
/// Emits a valid `HTTP/1.1` request line, strips hop-by-hop headers (unless tunnelling an
/// upgrade), drops Content-Length under chunked / collapses duplicates, removes client copies
/// of injected headers, and forwards header values as raw bytes (no lossy UTF-8). Returns length.
fn build_upstream_head(
    x: &mut Vec<u8>,
    req: &httparse::Request,
    path: &str,
    set_frags: &[HeaderFragment],
    inject_names: &[Vec<u8>],
    client_ip: &std::net::IpAddr,
    is_chunked: bool,
    upstream_keepalive: bool,
    want_upgrade: bool,
) -> usize {
    let mut pos = 0;
    buf_put(x, &mut pos, req.method.unwrap_or("GET").as_bytes());
    buf_put(x, &mut pos, b" ");
    // Forward the SAME target the routing/filter decisions were taken on (already normalized by
    // the caller), so the backend cannot resolve it into a different path than the one we evaluated.
    buf_put(x, &mut pos, path.as_bytes());
    buf_put(x, &mut pos, b" HTTP/1.1\r\n");

    let mut seen_clen = false;
    for h in req.headers.iter() {
        if h.name.is_empty() {
            continue;
        }
        let len = h.name.len();
        if (2..=19).contains(&len) {
            let c = h.name.as_bytes()[0].to_ascii_lowercase();
            if (c == b'c' && len == 10 && h.name.eq_ignore_ascii_case("connection"))
                || (c == b'u' && len == 7 && h.name.eq_ignore_ascii_case("upgrade"))
            {
                // Both are hop-by-hop: only kept (re-emitted) on a real upgrade.
                if !want_upgrade {
                    continue;
                }
            } else if (c == b'k' && len == 10 && h.name.eq_ignore_ascii_case("keep-alive"))
                || (c == b'p' && len == 18 && h.name.eq_ignore_ascii_case("proxy-authenticate"))
                || (c == b'p' && len == 19 && h.name.eq_ignore_ascii_case("proxy-authorization"))
                || (c == b't' && len == 2 && h.name.eq_ignore_ascii_case("te"))
                || (c == b't' && len == 7 && h.name.eq_ignore_ascii_case("trailer"))
                || (c == b't' && len == 17 && h.name.eq_ignore_ascii_case("transfer-encoding"))
            {
                continue; // S3: never forward client TE verbatim — we re-emit a canonical one below
            }
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            if is_chunked {
                continue;
            } // TE wins over CL
            if seen_clen {
                continue;
            } // collapse duplicate Content-Length
            seen_clen = true;
        }
        if inject_names
            .iter()
            .any(|inj| h.name.as_bytes().eq_ignore_ascii_case(inj.as_slice()))
        {
            continue; // we will inject this header ourselves
        }
        buf_put(x, &mut pos, h.name.as_bytes());
        buf_put(x, &mut pos, b": ");
        buf_put(x, &mut pos, h.value);
        buf_put(x, &mut pos, b"\r\n");
    }

    if !want_upgrade {
        buf_put(
            x,
            &mut pos,
            if upstream_keepalive {
                &b"Connection: keep-alive\r\n"[..]
            } else {
                &b"Connection: close\r\n"[..]
            },
        );
    }
    // Re-emit exactly one canonical chunked TE when the request body is chunked. Client TE
    // headers were stripped above, so the upstream framing is now fully proxy-controlled.
    if is_chunked {
        buf_put(x, &mut pos, b"Transfer-Encoding: chunked\r\n");
    }

    for frag in set_frags {
        match frag {
            HeaderFragment::Text(t) => buf_put(x, &mut pos, t),
            HeaderFragment::ClientIp => {
                // format the IP into a stack buffer (no heap alloc on the hot path)
                let mut ipbuf = [0u8; 45];
                let mut cur = std::io::Cursor::new(&mut ipbuf[..]);
                let _ = std::io::Write::write_fmt(&mut cur, format_args!("{}", client_ip));
                let n = cur.position() as usize;
                buf_put(x, &mut pos, &ipbuf[..n]);
            }
        }
    }
    buf_put(x, &mut pos, b"\r\n");
    pos
}

/// Build a normalized response head into `x`: strip hop-by-hop headers, keep framing
/// headers (Content-Length / Transfer-Encoding), set Connection based on client keep-alive.
/// Framing is normalized symmetrically to the request path: under chunked the response
/// Content-Length is dropped (TE wins, RFC 7230 §3.3.3), and duplicate Content-Length headers
/// are collapsed to one — so the client never receives the ambiguous CL+TE / dup-CL framing
/// that is a response-side request-smuggling primitive.
fn build_response_head(
    x: &mut Vec<u8>,
    resp: &httparse::Response,
    client_keep_alive: bool,
) -> usize {
    let mut pos = 0;
    let code = resp.code.unwrap_or(502);
    buf_put(x, &mut pos, b"HTTP/1.1 ");
    let digits = [
        b'0' + ((code / 100) % 10) as u8,
        b'0' + ((code / 10) % 10) as u8,
        b'0' + (code % 10) as u8,
    ];
    buf_put(x, &mut pos, &digits);
    buf_put(x, &mut pos, b" ");
    buf_put(x, &mut pos, resp.reason.unwrap_or("").as_bytes());
    buf_put(x, &mut pos, b"\r\n");
    let resp_chunked = resp.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value)
                .map(te_is_chunked)
                .unwrap_or(false)
    });
    let mut seen_clen = false;
    for h in resp.headers.iter() {
        if h.name.is_empty() {
            continue;
        }
        let len = h.name.len();
        if (2..=19).contains(&len) {
            let c = h.name.as_bytes()[0].to_ascii_lowercase();
            if (c == b'c' && len == 10 && h.name.eq_ignore_ascii_case("connection"))
                || (c == b'k' && len == 10 && h.name.eq_ignore_ascii_case("keep-alive"))
                || (c == b'p' && len == 18 && h.name.eq_ignore_ascii_case("proxy-authenticate"))
                || (c == b'p' && len == 19 && h.name.eq_ignore_ascii_case("proxy-authorization"))
                || (c == b'u' && len == 7 && h.name.eq_ignore_ascii_case("upgrade"))
                || (c == b't' && len == 7 && h.name.eq_ignore_ascii_case("trailer"))
                || (c == b't' && len == 2 && h.name.eq_ignore_ascii_case("te"))
            {
                continue;
            }
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            if resp_chunked {
                continue;
            } // TE wins over CL
            if seen_clen {
                continue;
            } // collapse duplicate Content-Length
            seen_clen = true;
        }
        buf_put(x, &mut pos, h.name.as_bytes());
        buf_put(x, &mut pos, b": ");
        buf_put(x, &mut pos, h.value);
        buf_put(x, &mut pos, b"\r\n");
    }
    buf_put(
        x,
        &mut pos,
        if client_keep_alive {
            &b"Connection: keep-alive\r\n"[..]
        } else {
            &b"Connection: close\r\n"[..]
        },
    );
    buf_put(x, &mut pos, b"\r\n");
    pos
}

pub struct FastValidateFail {
    pub status: u16,
    pub balancer: Option<BalancerState>,
    pub precomputed_resp: Vec<u8>,
}

pub struct FastValidateRule {
    pub rule_type: crate::config::ValidateType,
    pub name: String,
    pub matcher: Option<Matcher>,
    pub invert: bool,
    pub on_fail: FastValidateFail,
}

pub struct FastRouteState {
    pub route: Route,
    pub matcher: Matcher,
    pub balancer: Option<BalancerState>,
    pub client_timeout: u64,
    pub max_body_size: u64,
    pub drop_threshold: Option<u8>,
    pub validate: Vec<FastValidateRule>,
    pub set_headers: Vec<HeaderFragment>,
    pub set_header_names: Vec<Vec<u8>>,
    pub log_level: Option<u8>,
}

pub struct FastDomainState {
    pub matcher: Matcher,
    pub routes: Vec<FastRouteState>,
    pub def: Option<BalancerState>,
    pub allow_ip: Option<Vec<ipnet::IpNet>>,
    pub deny_ip: Option<Vec<ipnet::IpNet>>,
    pub jwt_secret: Option<String>,
    pub set_headers: Vec<HeaderFragment>,
    pub set_header_names: Vec<Vec<u8>>,
    pub client_timeout: u64,
    pub max_body_size: u64,
    pub backend_pool_size: usize,
    pub log_level: Option<u8>,
    pub listen: Vec<String>,
    pub tls_listen: Vec<String>,
}

pub struct FastRouter {
    pub cfg: Config,
    pub domains: Vec<FastDomainState>,
    pub def: Option<BalancerState>,
    pub def_headers: Vec<HeaderFragment>,
    pub def_header_names: Vec<Vec<u8>>,
}

// NOTE on Sync/Send (2026-08-15, review follow-up -- see also the
// `arc_with_non_send_sync` allow in Cargo.toml): FastRouter holds mutable
// routing state (per-domain/route matchers, balancer round-robin cursors) and
// is deliberately NOT Sync. That is sound ONLY because of the prefork worker
// model: each worker is its own OS process running a SINGLE-THREADED monoio
// runtime (`.build()`, not `.build_multi_thread()`, see platform.rs), and the
// `Arc<FastRouter>` is only ever shared between the accept-loop tasks of that
// one runtime's one thread. There is no cross-thread access by construction.
// If a future change ever switches to a multi-threaded runtime, this type must
// become Sync (or move behind a Mutex) BEFORE that lands -- the allow-list
// entry in Cargo.toml will then stop hiding a real race.

impl FastRouter {
    pub fn new(cfg: Config) -> Self {
        let mut domains = Vec::new();
        for d in &cfg.domains {
            let mut routes = Vec::new();
            for r in &d.routes {
                let mut fast_validate = Vec::new();
                for v in &r.validate {
                    let precomputed_resp = format!("HTTP/1.1 {} validation failed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", v.on_fail.status, v.on_fail.body.len(), v.on_fail.body).into_bytes();
                    fast_validate.push(FastValidateRule {
                        rule_type: v.rule_type.clone(),
                        name: v.name.clone(),
                        matcher: v.regex.as_ref().map(Matcher::exact_or_re),
                        invert: v.invert,
                        on_fail: FastValidateFail {
                            status: v.on_fail.status,
                            balancer: v.on_fail.backends.clone().map(BalancerState::new),
                            precomputed_resp,
                        },
                    });
                }

                routes.push(FastRouteState {
                    matcher: Matcher::prefix_or_re(&r.re),
                    route: r.clone(),
                    balancer: r.bl.clone().map(BalancerState::new),
                    client_timeout: r.client_timeout,
                    max_body_size: r.max_body_size,
                    drop_threshold: r.drop_threshold,
                    validate: fast_validate,
                    set_headers: compile_headers(&r.set_headers),
                    set_header_names: compile_header_names(&r.set_headers),
                    log_level: r.log_level,
                });
            }
            domains.push(FastDomainState {
                matcher: Matcher::exact_or_re(&d.re),
                routes,
                def: d.def.clone().map(BalancerState::new),
                allow_ip: d.allow_ip.clone(),
                deny_ip: d.deny_ip.clone(),
                jwt_secret: d.jwt_secret.clone(),
                set_headers: compile_headers(&d.set_headers),
                set_header_names: compile_header_names(&d.set_headers),
                client_timeout: d.client_timeout,
                max_body_size: d.max_body_size,
                backend_pool_size: d.backend_pool_size.unwrap_or(cfg.backend_pool_size),
                log_level: d.log_level,
                listen: d.listen.clone(),
                tls_listen: d.tls_listen.clone(),
            });
        }
        Self {
            cfg: cfg.clone(),
            domains,
            def: cfg.def.clone().map(BalancerState::new),
            def_headers: compile_headers(&cfg.set_headers),
            def_header_names: compile_header_names(&cfg.set_headers),
        }
    }

    fn check_filters(
        method: &str,
        path: &str,
        headers: &[httparse::Header],
        route: &Route,
    ) -> bool {
        if let Some(methods) = &route.method {
            if !methods.iter().any(|m| m == method) {
                return false;
            }
        }
        if let Some(route_headers) = &route.header {
            for h in route_headers {
                let mut found = false;
                for rh in headers {
                    if rh.name.eq_ignore_ascii_case(h) {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return false;
                }
            }
        }
        if let Some(absent) = &route.absent_header {
            for h in absent {
                for rh in headers {
                    if rh.name.eq_ignore_ascii_case(h) {
                        return false;
                    }
                }
            }
        }
        if let Some(cookies) = &route.cookie {
            let mut cookie_str = "";
            for rh in headers {
                if rh.name.eq_ignore_ascii_case("cookie") {
                    if let Ok(s) = std::str::from_utf8(rh.value) {
                        cookie_str = s;
                    }
                }
            }
            let get_cookie = |k: &str| -> Option<&str> {
                cookie_str.split(';').map(|s| s.trim()).find_map(|s| {
                    let mut parts = s.splitn(2, '=');
                    if parts.next()? == k {
                        Some(parts.next().unwrap_or(""))
                    } else {
                        None
                    }
                })
            };
            for c in cookies {
                if let Some(rest) = c.strip_prefix('!') {
                    if get_cookie(rest).is_some() {
                        return false;
                    }
                } else if c.contains('=') {
                    let (k, v) = c.split_once('=').unwrap();

                    if get_cookie(k) != Some(v) {
                        return false;
                    }
                } else {
                    if get_cookie(c.as_str()).is_none() {
                        return false;
                    }
                }
            }
        }
        if let Some(query) = &route.query {
            let q_str = path.find('?').map(|i| &path[i + 1..]).unwrap_or("");
            let get_query = |k: &str| -> Option<std::borrow::Cow<str>> {
                url::form_urlencoded::parse(q_str.as_bytes()).find_map(|(key, val)| {
                    if key == k {
                        Some(val)
                    } else {
                        None
                    }
                })
            };
            for q_cond in query.split_whitespace() {
                if let Some(rest) = q_cond.strip_prefix('!') {
                    if get_query(rest).is_some() {
                        return false;
                    }
                } else if q_cond.contains('=') {
                    let (k, expected_v) = q_cond.split_once('=').unwrap();

                    let actual_v_cow = get_query(k);
                    let actual_v = actual_v_cow.as_ref().map(|c| c.as_ref()).unwrap_or("");
                    let matched = expected_v.split('|').any(|ev| {
                        if ev == "int" {
                            actual_v.parse::<i64>().is_ok()
                        } else if ev.starts_with("enum(") && ev.ends_with(')') {
                            let enums = &ev[5..ev.len() - 1];
                            enums.split(',').any(|e| e == actual_v)
                        } else {
                            ev == actual_v || (ev == "str" && !actual_v.is_empty())
                        }
                    });
                    if !matched {
                        return false;
                    }
                } else {
                    if get_query(q_cond).is_none() {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn route<'a>(
        &'a self,
        method: &str,
        host: &str,
        path: &str,
        headers: &[httparse::Header],
        local_addr: &str,
    ) -> Option<(
        &'a BalancerState,
        Option<&'a FastRouteState>,
        Option<&'a FastDomainState>,
    )> {
        // Pick the longest-matching domain, then the first matching route within it. Each `Matcher`
        // is a plain substring search for literal patterns (alloc-free, no regex engine) and only
        // falls back to the regex engine for real patterns — so there is no per-request SetMatches
        // or Vec allocation here.
        // Domain matching is port-insensitive: a literal domain `example.com` must match
        // `Host: example.com:8443`, and an exact match would otherwise fail on the port.
        let host = host_without_port(host);
        let mut best_match: Option<&FastDomainState> = None;
        for d in &self.domains {
            if !d.matcher.is_match(host) {
                continue;
            }
            if !d.listen.iter().any(|s| s == local_addr)
                && !d.tls_listen.iter().any(|s| s == local_addr)
            {
                continue;
            }
            if best_match.is_none_or(|b| d.matcher.pat_len() > b.matcher.pat_len()) {
                best_match = Some(d);
            }
        }
        if let Some(d) = best_match {
            for r in &d.routes {
                if !r.matcher.is_match(path) {
                    continue;
                }
                if Self::check_filters(method, path, headers, &r.route) {
                    if let Some(ref b) = r.balancer {
                        return Some((b, Some(r), Some(d)));
                    } else if let Some(ref b) = d.def {
                        return Some((b, Some(r), Some(d)));
                    } else if let Some(ref b) = self.def {
                        return Some((b, Some(r), Some(d)));
                    }
                }
            }
            if let Some(ref b) = d.def {
                return Some((b, None, Some(d)));
            }
        }
        self.def.as_ref().map(|b| (b, None, None))
    }
}

/// Verify `Authorization: Bearer <jwt>` against `secret`, with a per-token
/// verify-result cache. See docs/DESIGN-NOTES.md#3.
fn jwt_authorized(headers: &[httparse::Header], secret: &str, now_secs: u64) -> bool {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(secret.as_bytes());
    let mut secret_hash = [0u8; 16];
    secret_hash.copy_from_slice(&d[..16]);

    for h in headers {
        if !h.name.eq_ignore_ascii_case("authorization") {
            continue;
        }
        let Ok(val) = std::str::from_utf8(h.value) else {
            continue;
        };
        let Some(token) = val.strip_prefix("Bearer ") else {
            continue;
        };

        let mut cached = false;
        JWT_CACHE.with(|c| {
            let mut map = c.borrow_mut();
            if let Some((exp, sh)) = map.get(token) {
                if *sh == secret_hash && *exp > std::time::Instant::now() {
                    cached = true;
                } else if *exp <= std::time::Instant::now() {
                    map.remove(token);
                }
            }
        });
        if cached {
            return true;
        }

        // Split into exactly three parts using a stack array (no Vec alloc).
        let mut sp = token.split('.');
        if let (Some(p0), Some(p1), Some(p2), None) = (sp.next(), sp.next(), sp.next(), sp.next()) {
            let parts = [p0, p1, p2];
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;

            let Ok(mut mac) =
                <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
            else {
                continue;
            };
            mac.update(parts[0].as_bytes());
            mac.update(b".");
            mac.update(parts[1].as_bytes());

            let mut sig_buf = [0u8; 64];
            let decoded_len = URL_SAFE_NO_PAD
                .decode_slice(parts[2], &mut sig_buf)
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE.decode_slice(parts[2], &mut sig_buf)
                });
            let Ok(sig_len) = decoded_len else { continue };
            if mac.verify_slice(&sig_buf[..sig_len]).is_err() {
                continue;
            }
            // Reject expired (`exp`) AND not-yet-valid (`nbf`) tokens.
            // `iat` is informational per RFC 7519 §4.1.6 -- not a rejection field.
            let payload = URL_SAFE_NO_PAD
                .decode(parts[1])
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(parts[1]))
                .ok();
            let exp = payload.as_ref().and_then(|p| {
                crate::profile_cycles!(crate::cycles::SITE_JWT_CLAIM_U64, jwt_claim_u64(p, b"exp"))
            });
            let nbf = payload.as_ref().and_then(|p| {
                crate::profile_cycles!(crate::cycles::SITE_JWT_CLAIM_U64, jwt_claim_u64(p, b"nbf"))
            });
            if exp.is_none_or(|e| e > now_secs) && nbf.is_none_or(|n| n <= now_secs) {
                // cache until expiry, capped at JWT_CACHE_TTL_SECS
                let ttl = exp
                    .map(|e| e.saturating_sub(now_secs).min(JWT_CACHE_TTL_SECS))
                    .unwrap_or(JWT_CACHE_TTL_SECS);
                JWT_CACHE.with(|c| {
                    let mut map = c.borrow_mut();
                    if map.len() > JWT_CACHE_MAX {
                        map.clear();
                    }
                    map.insert(
                        token.to_string(),
                        (
                            std::time::Instant::now() + std::time::Duration::from_secs(ttl),
                            secret_hash,
                        ),
                    );
                });
                return true;
            }
        }
    }
    false
}

/// Outcome of serving a cache hit: may the client connection continue?
#[derive(Clone, Copy, PartialEq)]
enum CacheHitOutcome {
    Continue,
    Close,
}

/// Write a cache hit to the client and report the keep-alive outcome.
/// See docs/DESIGN-NOTES.md#4.
async fn serve_cache_hit<S: monoio::io::AsyncWriteRent>(
    client: &mut S,
    status: u16,
    body: Option<bytes::Bytes>,
    hit_keepalive: bool,
    timeout: u64,
) -> CacheHitOutcome {
    if status == 304 {
        let head = if hit_keepalive {
            bytes::Bytes::from_static(
                b"HTTP/1.1 304 Not Modified\r\nConnection: keep-alive\r\n\r\n",
            )
        } else {
            bytes::Bytes::from_static(b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n")
        };
        crate::shared::add_bytes_tx(head.len() as u64);
        crate::shared::inc_status(304);
        let n = head.len();
        let ok = write_all_fast(client, head, 0, n, timeout).await.is_ok();
        return if ok && hit_keepalive {
            CacheHitOutcome::Continue
        } else {
            CacheHitOutcome::Close
        };
    }

    let blob = body.expect("200 cache hit requires a body");
    // The stored blob carries the forced keep-alive copy; a client that
    // asked for close must not get it back (would trust the header, then see
    // the proxy close the socket). See docs/DESIGN-NOTES.md#4.
    if !hit_keepalive {
        // Only search the header section (before the blank line) for the
        // Connection header to rewrite. Searching the entire blob would
        // corrupt the body if it happens to contain the exact string.
        // `header_end` is the START of the "\r\n\r\n" blank-line separator --
        // which means the LAST header line's own trailing "\r\n" is the
        // first half of that very separator (bytes [header_end..header_end+2)),
        // not something before it. Searching only `&blob[..header_end]`
        // truncates a Connection header sitting last (the common case: it is
        // appended right before the blank line) by exactly those 2 bytes, so
        // the 24-byte KA pattern can never match there. `+2` includes the
        // last header's own terminator while still excluding the blank
        // line's second "\r\n" and the body.
        let header_search_end = blob
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 2)
            .unwrap_or(blob.len());
        const KA: &[u8] = b"Connection: keep-alive\r\n";
        if let Some(pos) = find_ci(&blob[..header_search_end], KA) {
            let mut v = Vec::with_capacity(blob.len() + 4);
            v.extend_from_slice(&blob[..pos]);
            v.extend_from_slice(b"Connection: close\r\n");
            v.extend_from_slice(&blob[pos + KA.len()..]);
            let n = v.len();
            crate::shared::add_bytes_tx(n as u64);
            crate::shared::inc_status(200);
            let ok = write_all_fast(client, v, 0, n, timeout).await.is_ok();
            return if ok && hit_keepalive {
                CacheHitOutcome::Continue
            } else {
                CacheHitOutcome::Close
            };
        }
    }
    let n = blob.len();
    crate::shared::add_bytes_tx(n as u64);
    crate::shared::inc_status(200);
    let ok = write_all_fast(client, blob, 0, n, timeout).await.is_ok();
    if ok && hit_keepalive {
        CacheHitOutcome::Continue
    } else {
        CacheHitOutcome::Close
    }
}

/// Evaluate one compiled validate rule against the request (Header / Cookie /
/// Query / Post extraction + matcher). Pure: no I/O, no await -- the caller
/// applies `invert` and handles `on_fail`.
fn rule_matches(
    rule: &FastValidateRule,
    headers: &[httparse::Header],
    path: &str,
    full_body: Option<&Vec<u8>>,
) -> bool {
    match rule.rule_type {
        crate::config::ValidateType::Header => {
            for h in headers {
                if h.name.is_empty() {
                    break;
                }
                if h.name.eq_ignore_ascii_case(&rule.name) {
                    if let Some(ref re) = rule.matcher {
                        if let Ok(s) = std::str::from_utf8(h.value) {
                            if re.is_match(s) {
                                return true;
                            }
                        }
                    } else {
                        return true;
                    }
                }
            }
            false
        }
        crate::config::ValidateType::Cookie => {
            for h in headers {
                if h.name.is_empty() {
                    break;
                }
                if h.name.eq_ignore_ascii_case("cookie") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        for cookie in s.split(';') {
                            let cookie = cookie.trim();
                            if let Some(idx) = cookie.find('=') {
                                let (k, v) = cookie.split_at(idx);
                                let v = &v[1..];
                                if k == rule.name {
                                    if let Some(ref re) = rule.matcher {
                                        if re.is_match(v) {
                                            return true;
                                        }
                                    } else {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            false
        }
        crate::config::ValidateType::Query => {
            if let Some(idx) = path.find('?') {
                let q = &path[idx + 1..];
                for param in q.split('&') {
                    let mut parts = param.splitn(2, '=');
                    let k = parts.next().unwrap_or("");
                    let v = parts.next().unwrap_or("");
                    if k == rule.name {
                        if let Some(ref re) = rule.matcher {
                            if re.is_match(v) {
                                return true;
                            }
                        } else {
                            return true;
                        }
                    }
                }
            }
            false
        }
        crate::config::ValidateType::Post => {
            let Some(body) = full_body else {
                // Reachable only if a future edit calls rule_matches before the
                // request body is read -- the single call site's ordering
                // guarantees this today, not this function's type signature.
                // Fail closed (no match), but loudly, instead of silently.
                debug_assert!(
                    false,
                    "rule_matches: Post rule '{}' evaluated with no body read yet",
                    rule.name
                );
                tracing::error!(
                    "validate: Post rule '{}' evaluated before the request body was read \
                     -- treating as no-match (this indicates a caller-ordering bug)",
                    rule.name
                );
                return false;
            };
            if let Ok(s) = std::str::from_utf8(body) {
                for param in s.split('&') {
                    let mut parts = param.splitn(2, '=');
                    let k = parts.next().unwrap_or("");
                    let v = parts.next().unwrap_or("");
                    if k == rule.name {
                        if let Some(ref re) = rule.matcher {
                            if re.is_match(v) {
                                return true;
                            }
                        } else {
                            return true;
                        }
                    }
                }
            }
            false
        }
    }
}

/// Look up the shared response cache and classify the hit: 200 (cache blob)
/// or 304 (respect_headers + If-None-Match / If-Modified-Since revalidation).
/// Returns (hit, hit_304, data); expired entries are evicted.
fn cache_lookup(
    cache_key: u64,
    respect_headers: bool,
    headers: &[httparse::Header],
) -> (bool, bool, bytes::Bytes) {
    let mut hit = false;
    let mut hit_data: bytes::Bytes = bytes::Bytes::new();
    let mut hit_304 = false;

    let mut client_if_none_match = None;
    let mut client_if_modified_since = None;
    if respect_headers {
        for h in headers {
            if h.name.eq_ignore_ascii_case("if-none-match") {
                client_if_none_match = std::str::from_utf8(h.value).ok();
            }
            if h.name.eq_ignore_ascii_case("if-modified-since") {
                client_if_modified_since = std::str::from_utf8(h.value).ok();
            }
        }
    }

    RESPONSE_CACHE.with(|cache| {
        let mut map = cache.borrow_mut();
        if let Some(entry) = map.get(&cache_key) {
            if entry.expires_at > std::time::Instant::now() {
                if respect_headers
                    && ((client_if_none_match.is_some()
                        && client_if_none_match == entry.etag.as_deref())
                        || (client_if_modified_since.is_some()
                            && client_if_modified_since == entry.last_modified.as_deref()))
                {
                    hit_304 = true;
                } else {
                    hit = true;
                    hit_data = entry.data.clone();
                }
            } else {
                map.remove(&cache_key);
            }
        }
    });
    (hit, hit_304, hit_data)
}

/// Resolve the effective deny/allow/JWT policy for a request: route-level overrides
/// domain-level overrides global config. Applies even to requests served by a
/// domain/global default backend (no matching route).
fn effective_policy<'a>(
    route_opt: Option<&'a FastRouteState>,
    domain_opt: Option<&'a FastDomainState>,
    cfg: &'a crate::config::Config,
) -> (
    Option<&'a Vec<ipnet::IpNet>>,
    Option<&'a Vec<ipnet::IpNet>>,
    Option<&'a String>,
) {
    let eff_deny = route_opt
        .and_then(|r| r.route.deny_ip.as_ref())
        .or_else(|| domain_opt.and_then(|d| d.deny_ip.as_ref()))
        .or(cfg.deny_ip.as_ref());
    let eff_allow = route_opt
        .and_then(|r| r.route.allow_ip.as_ref())
        .or_else(|| domain_opt.and_then(|d| d.allow_ip.as_ref()))
        .or(cfg.allow_ip.as_ref());
    let eff_jwt = route_opt
        .and_then(|r| r.route.jwt_secret.as_ref())
        .or_else(|| domain_opt.and_then(|d| d.jwt_secret.as_ref()))
        .or(cfg.jwt_secret.as_ref());
    (eff_deny, eff_allow, eff_jwt)
}

struct FramingResult<'b> {
    clen: usize,
    host_str: &'b str,
    client_keep_alive: bool,
    is_chunked: bool,
    /// Covers ambiguous Transfer-Encoding, duplicate/missing Host, an illegal or
    /// evasive request-target, and a malformed or conflicting Content-Length.
    bad_request: bool,
}

/// Validate framing (Content-Length / Transfer-Encoding / Host / request-target) per RFC 7230,
/// combining the header scan with the smuggling-primitive checks it feeds.
/// `#[inline(always)]`: single call site on the hot path, matching the pre-extraction shape
/// where this logic was inlined directly in `proxy_l7_core`.
#[inline(always)]
fn validate_request_framing<'b>(
    headers: &[httparse::Header<'b>],
    version: Option<u8>,
    path: Option<&'b str>,
    reject_encoded_slash: bool,
) -> FramingResult<'b> {
    let mut clen = 0;
    let mut host_str = "";
    let mut client_keep_alive = version == Some(1);
    let mut clen_count = 0;
    let mut host_count = 0u32;
    let mut is_400 = false;
    // Transfer-Encoding accounting. We only honour exactly one `Transfer-Encoding: chunked`.
    let mut te_count = 0u32;
    let mut te_chunked_single = false; // a TE header whose sole coding is `chunked`
    let mut te_other = false; // any TE header that is NOT a bare `chunked`

    for h in headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            // Strict parse. A Content-Length must be a non-empty run of ASCII digits
            // (after trimming OWS) that fits usize. Anything else (junk, sign, hex, non-UTF8,
            // overflow) is rejected with 400 instead of silently defaulting to 0 while the
            // header is still forwarded upstream — that mismatch is a smuggling primitive.
            let parsed = std::str::from_utf8(h.value)
                .ok()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<usize>().ok());
            match parsed {
                Some(parsed_clen) => {
                    if clen_count > 0 && parsed_clen != clen {
                        is_400 = true;
                    }
                    clen = parsed_clen;
                    clen_count += 1;
                }
                None => {
                    is_400 = true;
                }
            }
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            te_count += 1;
            let bare_chunked = std::str::from_utf8(h.value)
                .ok()
                .map(|s| s.trim().eq_ignore_ascii_case("chunked"))
                .unwrap_or(false);
            if bare_chunked {
                te_chunked_single = true;
            } else {
                te_other = true;
            }
        }
        if h.name.eq_ignore_ascii_case("host") {
            host_count += 1;
            if let Ok(s) = std::str::from_utf8(h.value) {
                host_str = s;
            }
        }
        if h.name.eq_ignore_ascii_case("connection") {
            if contains_ci(h.value, b"close") {
                client_keep_alive = false;
            } else if contains_ci(h.value, b"keep-alive") {
                client_keep_alive = true;
            }
        }
    }

    // Accept chunked framing ONLY when there is exactly one `Transfer-Encoding: chunked`
    // header. Any other shape (multiple TE headers, a coding list, a non-chunked coding, or a
    // non-UTF8 value) is ambiguous framing that the proxy refuses to forward — that ambiguity
    // is the request-smuggling primitive. We then rebuild a single canonical TE header upstream.
    let te_present = te_count > 0;
    let is_chunked = te_count == 1 && te_chunked_single && !te_other;
    let te_ambiguous = te_present && !is_chunked;

    // RFC 7230 §5.4: an HTTP/1.1 request must carry exactly one Host. Duplicate Host is a
    // routing/smuggling discrepancy (we route on one copy but would forward all of them);
    // a missing Host on 1.1 is malformed. Reject both with 400.
    let bad_host = host_count > 1 || (host_count == 0 && version == Some(1));
    // RFC 7230 §5.3: a reverse proxy serves origin-form ("/path") or asterisk-form ("*").
    // Absolute-form ("http://host/…") / authority-form ("host:port") are for forward proxies
    // and would let the target disagree with our Host-based routing — reject them.
    // A fragment is likewise illegal in a request-target (§5.3 origin-form is
    // `absolute-path [ "?" query ]`), and it is a canonicalisation bypass if tolerated:
    // `/pub#/../admin` stops the canonicaliser at the `#`, so the rule sees `/pub…` while
    // a backend that treats `#` as an ordinary path byte resolves the dot-segments and
    // serves /admin.
    let bad_target = path.is_some_and(|p| (!p.starts_with('/') && p != "*") || p.contains('#'));
    // Opt-in, default off: an encoded path separator in the path part. Off by default
    // because it breaks legitimate encoded-slash users; on for deployments whose upstream
    // decodes `%2F`/`%5C` before resolving dot-segments. One bool test when disabled.
    let bad_encoded_sep =
        reject_encoded_slash && path.is_some_and(|p| path_has_separator_evasion(p.as_bytes()));
    let bad_request = is_400
        || te_ambiguous
        || bad_host
        || bad_target
        || bad_encoded_sep
        || (clen_count > 1 && is_chunked);

    FramingResult {
        clen,
        host_str,
        client_keep_alive,
        is_chunked,
        bad_request,
    }
}

pub async fn proxy_l7_core<S>(
    mut client: S,
    router: Arc<FastRouter>,
    client_ip: std::net::IpAddr,
    _is_tls: bool,
    local_addr: String,
) where
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    S::OwnedRead: monoio::io::AsyncReadRent,
    S::OwnedWrite: monoio::io::AsyncWriteRent,
{
    let mut c_buf_guard = PooledBuf::new();
    let mut x_buf_guard = PooledBuf::new();
    let mut b_buf_guard = PooledBuf::new();
    let mut c_buf = c_buf_guard.take();
    let mut x_buf = x_buf_guard.take();
    let mut b_buf = b_buf_guard.take();
    let mut c_pos = 0;
    let mut c_start = 0;

    ACTIVE_REQUESTS.with(|c| c.set(c.get() + 1));
    crate::shared::inc_active_connections();

    // Unconditional per-worker concurrency cap (independent of the optional QoS `drop_threshold`)
    // so a connection flood can't exhaust memory/FDs. The default (max_active_requests, 10000/worker)
    // is high enough not to throttle normal load.
    if ACTIVE_REQUESTS.with(|c| c.get()) > router.cfg.max_active_requests {
        let resp = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 19\r\nConnection: close\r\n\r\nService Unavailable";
        let _ = write_all_fast(&mut client, resp, 0, resp.len(), router.cfg.client_timeout).await;
        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
        crate::shared::dec_active_connections();
        crate::shared::inc_status(503);
        return;
    }

    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let parsed = req.parse(&c_buf[c_start..c_pos]);

        if let Ok(httparse::Status::Partial) = parsed {
            if c_pos - c_start >= router.cfg.max_headers_size as usize {
                let err =
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n";
                let _ =
                    write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout).await;
                ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                crate::shared::dec_active_connections();
                return;
            }
            // monoio's `read` sets the Vec's len to (start + n), so c_buf.len() no longer reflects
            // the buffer size — its capacity does. The read target passed to SliceMut is an ABSOLUTE
            // end index, so it must be the capacity, not a remaining-byte count. Using `len - c_pos`
            // (the old code) produced a zero-width [c_pos, c_pos) slice on the 2nd read of any
            // request split across packets → n=0 → false EOF → dropped connection.
            if c_pos >= c_buf.capacity() {
                if c_start > 0 {
                    c_buf.copy_within(c_start..c_pos, 0);
                    c_pos -= c_start;
                    c_start = 0;
                }
                if c_pos >= c_buf.capacity() {
                    let cap = c_buf.capacity();
                    c_buf.reserve(cap.max(BUF_SIZE)); // grow capacity for oversized headers
                }
            }
            let read_end = c_buf.capacity();
            match read_with_timeout(
                &mut client,
                c_buf,
                c_pos,
                read_end,
                router.cfg.client_timeout,
            )
            .await
            {
                Ok((n, b)) => {
                    c_buf = b;
                    if n == 0 {
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        return;
                    }
                    c_pos += n;
                    crate::shared::add_bytes_rx(n as u64);
                    continue;
                }
                Err(_) => {
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    return;
                }
            }
        } else if parsed.is_err() {
            let err = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
            let _ = write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout).await;
            ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
            crate::shared::dec_active_connections();
            return;
        } else if let Ok(httparse::Status::Complete(req_len)) = parsed {
            // One thread-local Cell increment per request (no alloc, no lock); drives the optional
            // worker_max_requests recycle trigger. Negligible next to parse + I/O on the hot path.
            REQUESTS_SERVED.with(|c| c.set(c.get().wrapping_add(1)));
            let fr = validate_request_framing(
                req.headers,
                req.version,
                req.path,
                router.cfg.reject_encoded_slash,
            );
            if fr.bad_request {
                let err = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                let _ =
                    write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout).await;
                ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                crate::shared::dec_active_connections();
                return;
            }
            let host_str = fr.host_str;
            let client_keep_alive = fr.client_keep_alive;
            let is_chunked = fr.is_chunked;
            // TE chunked wins over Content-Length (CL stripped upstream)
            let clen = if is_chunked { 0 } else { fr.clen };
            let method = req.method.unwrap_or("GET");
            let raw_path = req.path.unwrap_or("/");
            // Canonicalise the target BEFORE it feeds any decision (route match, filters, JWT
            // route selection, cache key, urlhash) and forward that same form upstream. Matching the
            // raw target while the backend resolves dot-segments and percent-escapes itself is an
            // ACL-bypass differential: `/x/../admin`, `//admin` and `/%61dmin` all miss a prefix rule
            // here yet land on /admin there. Canonical targets (nearly all real traffic) keep the
            // zero-alloc path — `needs_path_normalize` is a single scan and `norm_buf` stays unused.
            let mut norm_buf: Vec<u8> = Vec::new();
            let path: &str = if router.cfg.normalize_path
                && raw_path.starts_with('/')
                && needs_path_normalize(raw_path.as_bytes())
            {
                normalize_path_into(raw_path, &mut norm_buf);
                std::str::from_utf8(&norm_buf).unwrap_or(raw_path)
            } else {
                raw_path
            };
            let (balancer, route_opt, domain_opt) =
                match router.route(method, host_str, path, req.headers, &local_addr) {
                    Some(res) => res,
                    None => {
                        let err = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
                        let _ = write_all_fast(
                            &mut client,
                            err,
                            0,
                            err.len(),
                            router.cfg.client_timeout,
                        )
                        .await;
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        return;
                    }
                };
            let mut active_balancer = balancer;
            let mut full_body: Option<Vec<u8>> = None;
            let mut consumed_from_buf = 0;

            // Effective IP/JWT policy (route -> domain -> global) enforced for EVERY request,
            // including requests served by a domain/global default backend (no matching route).
            let (eff_deny, eff_allow, eff_jwt) =
                effective_policy(route_opt, domain_opt, &router.cfg);

            if let Some(deny) = eff_deny {
                if deny.iter().any(|net| net.contains(&client_ip)) {
                    let err = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
                    let _ =
                        write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout)
                            .await;
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    crate::shared::inc_ip_drop();
                    crate::shared::inc_status(403);
                    return;
                }
            }

            if let Some(allow) = eff_allow {
                if !allow.iter().any(|net| net.contains(&client_ip)) {
                    let err = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
                    let _ =
                        write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout)
                            .await;
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    crate::shared::inc_ip_drop();
                    crate::shared::inc_status(403);
                    return;
                }
            }

            if let Some(secret) = eff_jwt {
                // JWT gate: Authorization: Bearer must validate against this
                // route/domain/global secret. Verification result is cached per
                // token until expiry (bound to the secret via a truncated
                // SHA-256 hash, so one route's token can't replay on another).
                // See docs/DESIGN-NOTES.md#3.
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if !jwt_authorized(req.headers, secret, now_secs) {
                    let err = b"HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n";
                    let _ =
                        write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout)
                            .await;
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    crate::shared::inc_jwt_drop();
                    crate::shared::inc_status(401);
                    return;
                }
            }

            // route-only checks (rate limit / body limits / validate) below
            if let Some(r) = route_opt {
                if let Some(limit) = r.route.rate_limit {
                    // unwrap_or(0): a clock before UNIX_EPOCH must not panic the worker (panic=abort).
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let mut allowed = false;
                    RATE_LIMITS.with(|rl| {
                        let mut map = rl.borrow_mut();
                        if map.len() > RATE_LIMIT_MAP_MAX {
                            map.clear();
                        }
                        let entry = map.entry((r.route.id, client_ip)).or_insert((now, 0));
                        if entry.0 != now {
                            entry.0 = now;
                            entry.1 = 0;
                        }
                        entry.1 += 1;
                        if entry.1 <= limit {
                            allowed = true;
                        }
                    });

                    if !allowed {
                        let err = b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n";
                        let _ = write_all_fast(
                            &mut client,
                            err,
                            0,
                            err.len(),
                            router.cfg.client_timeout,
                        )
                        .await;
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        crate::shared::inc_rate_limit_drop();
                        crate::shared::inc_status(429);
                        return;
                    }
                }

                let max_body_size = route_opt
                    .map(|rt| rt.max_body_size)
                    .or_else(|| domain_opt.map(|d| d.max_body_size))
                    .unwrap_or(router.cfg.max_body_size);

                if r.route.post.is_some()
                    || r.validate
                        .iter()
                        .any(|rule| rule.rule_type == crate::config::ValidateType::Post)
                {
                    // Reuse the already strictly-parsed Content-Length. A malformed CL was
                    // rejected with 400 above, so `clen` is authoritative — no lenient re-parse.
                    let cl = clen;
                    if cl > max_body_size as usize {
                        let err = b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n";
                        let _ = write_all_fast(
                            &mut client,
                            err,
                            0,
                            err.len(),
                            router.cfg.client_timeout,
                        )
                        .await;
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        crate::shared::inc_status(413);
                        return;
                    }

                    let mut body_vec = Vec::with_capacity(cl);
                    let body_in_buf = (c_pos - c_start).saturating_sub(req_len);
                    consumed_from_buf = std::cmp::min(cl, body_in_buf);
                    let body_start = c_start + req_len;
                    body_vec.extend_from_slice(&c_buf[body_start..body_start + consumed_from_buf]);

                    let mut remaining = cl.saturating_sub(consumed_from_buf);
                    while remaining > 0 {
                        let temp_buf = get_buf();
                        let read_len = std::cmp::min(remaining, BUF_SIZE);
                        let slice = monoio::buf::SliceMut::new(temp_buf, 0, read_len);
                        let (n, tb) = match monoio::time::timeout(
                            std::time::Duration::from_secs(router.cfg.client_timeout),
                            client.read(slice),
                        )
                        .await
                        {
                            Ok((Ok(n), s)) => (Ok(n), s.into_inner()),
                            Ok((Err(e), s)) => (Err(e), s.into_inner()),
                            Err(_) => break, // R12: bound slow POST-body reads (Slowloris)
                        };
                        if let Ok(n) = n {
                            if n == 0 {
                                put_buf(tb);
                                break;
                            }
                            body_vec.extend_from_slice(&tb[..n]);
                            remaining -= n;
                            put_buf(tb);
                        } else {
                            put_buf(tb);
                            break;
                        }
                    }
                    full_body = Some(body_vec);
                }

                // `post:` body filter (form-data): reject if conditions don't match
                if let Some(ref post_conds) = r.route.post {
                    let body_str = full_body
                        .as_deref()
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .unwrap_or("");
                    let ok = eval_field_conditions(post_conds, |k| {
                        url::form_urlencoded::parse(body_str.as_bytes()).find_map(|(kk, v)| {
                            if kk == k {
                                Some(v)
                            } else {
                                None
                            }
                        })
                    });
                    if !ok {
                        let err = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
                        let _ = write_all_fast(
                            &mut client,
                            err,
                            0,
                            err.len(),
                            router.cfg.client_timeout,
                        )
                        .await;
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        crate::shared::inc_rule_drop();
                        crate::shared::inc_status(403);
                        return;
                    }
                }

                let mut failed_rule = None;
                for rule in &r.validate {
                    let found = rule_matches(rule, req.headers, path, full_body.as_ref());
                    let failed = if rule.invert { found } else { !found };
                    if failed {
                        failed_rule = Some(rule);
                        break;
                    }
                }

                if let Some(rule) = failed_rule {
                    if let Some(ref bl) = rule.on_fail.balancer {
                        active_balancer = bl;
                    } else {
                        let n = rule.on_fail.precomputed_resp.len();
                        if x_buf.len() < n {
                            x_buf.resize(n, 0);
                        }
                        x_buf[..n].copy_from_slice(&rule.on_fail.precomputed_resp);
                        if let Ok(b) | Err(Some(b)) =
                            write_all_fast(&mut client, x_buf, 0, n, router.cfg.client_timeout)
                                .await
                        {
                            x_buf_guard.put(b);
                        }
                        crate::shared::add_bytes_tx(n as u64);
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        crate::shared::inc_rule_drop();
                        crate::shared::inc_status(rule.on_fail.status);
                        return;
                    }
                }
            }

            if router.cfg.has_qos {
                let mut threshold = None;
                if let Some(r) = route_opt {
                    threshold = r.drop_threshold;
                }

                if let Some(pct) = threshold {
                    let cpu_load =
                        crate::shared::GLOBAL_CPU_LOAD.load(std::sync::atomic::Ordering::Relaxed);
                    let current_active = ACTIVE_REQUESTS.with(|c| c.get());
                    let max_active = router.cfg.max_active_requests;

                    if cpu_load > pct || current_active > max_active {
                        // Build a correctly-framed 503 (the old hardcoded length declared CL:29 for
                        // a 30-byte body and wrote only 81 of 86 bytes — a malformed, truncated response).
                        const QOS_DROP_RESP: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 30\r\nConnection: close\r\n\r\nService Unavailable (QoS Drop)";
                        let n = QOS_DROP_RESP.len();
                        let _ = write_all_fast(
                            &mut client,
                            QOS_DROP_RESP,
                            0,
                            n,
                            router.cfg.client_timeout,
                        )
                        .await;
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        crate::shared::inc_qos_drop();
                        crate::shared::inc_status(503);
                        crate::shared::add_bytes_tx(n as u64);
                        return;
                    }
                }
            }

            let (use_headers, use_header_names): (&[HeaderFragment], &[Vec<u8>]) =
                if let Some(r) = route_opt {
                    if !r.set_headers.is_empty() {
                        (&r.set_headers, &r.set_header_names)
                    } else if let Some(d) = domain_opt {
                        if !d.set_headers.is_empty() {
                            (&d.set_headers, &d.set_header_names)
                        } else {
                            (&router.def_headers, &router.def_header_names)
                        }
                    } else {
                        (&router.def_headers, &router.def_header_names)
                    }
                } else if let Some(d) = domain_opt {
                    if !d.set_headers.is_empty() {
                        (&d.set_headers, &d.set_header_names)
                    } else {
                        (&router.def_headers, &router.def_header_names)
                    }
                } else {
                    (&router.def_headers, &router.def_header_names)
                };

            let client_timeout = route_opt
                .map(|r| r.client_timeout)
                .or_else(|| domain_opt.map(|d| d.client_timeout))
                .unwrap_or(router.cfg.client_timeout);

            let max_body_size = route_opt
                .map(|r| r.max_body_size)
                .or_else(|| domain_opt.map(|d| d.max_body_size))
                .unwrap_or(router.cfg.max_body_size);

            // Reject an over-sized declared body up front (before connecting/forwarding the head),
            // for the common streamed case where the length is known from Content-Length. The post
            // path already enforced this for buffered bodies; chunked has no declared length so it
            // stays bounded inside pipe_body via total_read.
            if !is_chunked && full_body.is_none() && clen as u64 > max_body_size {
                let err = b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n";
                let _ =
                    write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout).await;
                ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                crate::shared::dec_active_connections();
                crate::shared::inc_status(413);
                return;
            }

            let pool_sz = route_opt
                .map(|r| r.route.backend_pool_size)
                .unwrap_or_else(|| {
                    domain_opt
                        .map(|d| d.backend_pool_size)
                        .unwrap_or(router.cfg.backend_pool_size)
                });

            let log_level = route_opt
                .and_then(|r| r.log_level)
                .or_else(|| domain_opt.and_then(|d| d.log_level))
                .unwrap_or(router.cfg.log_level);

            let mut cache_key = 0u64;

            // Per-request request line logs only at debug+ so the default (info) hot path stays
            // allocation-free — tracing formats (and allocates) the event whenever its level is
            // enabled. Raise log_level to `debug` for per-request access logging.
            if log_level >= 4 {
                // Log the raw target alongside the canonical one when normalization rewrote it — during an
                // incident the bytes the client actually sent are the interesting half.
                if path == raw_path {
                    debug!("Request: {} {}{}", req.method.unwrap_or(""), host_str, path);
                } else {
                    debug!(
                        "Request: {} {}{} (raw {})",
                        req.method.unwrap_or(""),
                        host_str,
                        path,
                        raw_path
                    );
                }
            }
            let mut cache_cfg = None;
            // Never serve a cached entry to, or store a response for, a credentialed request.
            // An `Authorization`-bearing request can yield private content; a shared cache must not
            // reuse it for other clients (RFC 7234 §3.2).
            let req_has_auth = req
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("authorization"));
            if req.method.unwrap_or("") == "GET" && !req_has_auth {
                if let Some(r) = route_opt {
                    if let Some(ref c) = r.route.cache {
                        cache_cfg = Some(c.clone());

                        let mut client_enc = "";
                        for h in req.headers.iter() {
                            if h.name.eq_ignore_ascii_case("accept-encoding") {
                                if let Ok(s) = std::str::from_utf8(h.value) {
                                    if s.contains("br") {
                                        client_enc = "br";
                                    } else if s.contains("gzip") {
                                        client_enc = "gzip";
                                    }
                                }
                            }
                        }
                        use std::hash::{Hash, Hasher};

                        let mut skip_cache = false;
                        for h in req.headers.iter() {
                            if h.name.eq_ignore_ascii_case("cache-control")
                                && (contains_ci(h.value, b"no-cache")
                                    || contains_ci(h.value, b"no-store"))
                            {
                                skip_cache = true;
                            }
                            // A protocol-upgrade (e.g. WebSocket) request is not a cacheable GET even
                            // though it uses the GET method: never look it up in or store it to the
                            // shared cache. Disable both lookup (skip_cache) and store (cache_cfg).
                            if h.name.eq_ignore_ascii_case("upgrade") {
                                skip_cache = true;
                                cache_cfg = None;
                            }
                        }

                        if !skip_cache {
                            let mut hasher = std::collections::hash_map::DefaultHasher::new();
                            host_str.hash(&mut hasher);
                            path.hash(&mut hasher);
                            client_enc.hash(&mut hasher);
                            cache_key = hasher.finish();

                            let (hit, hit_304, hit_data) =
                                cache_lookup(cache_key, c.respect_headers, req.headers);

                            // Cache hits keep the client connection alive (the cached blob is
                            // self-delimited by Content-Length/chunked). Only safe when the request
                            // carried no body — otherwise unread body bytes would desync the stream.
                            let hit_keepalive = client_keep_alive && clen == 0 && !is_chunked;
                            if hit || hit_304 {
                                let outcome = if hit_304 {
                                    serve_cache_hit(
                                        &mut client,
                                        304,
                                        None,
                                        hit_keepalive,
                                        router.cfg.client_timeout,
                                    )
                                    .await
                                } else {
                                    serve_cache_hit(
                                        &mut client,
                                        200,
                                        Some(hit_data),
                                        hit_keepalive,
                                        router.cfg.client_timeout,
                                    )
                                    .await
                                };
                                match outcome {
                                    CacheHitOutcome::Continue => {
                                        c_start += req_len;
                                        continue;
                                    }
                                    CacheHitOutcome::Close => {
                                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                                        crate::shared::dec_active_connections();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // --- Select a live backend and connect, with cross-backend failover ---
            let mut chosen: Option<&crate::config::Backend> = None;
            let mut conn: Option<BackendStream> = None;
            let mut reused_pooled = false;
            let mut skip_ids = [0usize; MAX_BACKEND_TRIES];
            let mut skip_count = 0;
            for _ in 0..MAX_BACKEND_TRIES {
                let be =
                    match active_balancer.select_backend(&client_ip, path, &skip_ids[..skip_count])
                    {
                        Some(b) => b,
                        None => break,
                    };
                chosen = Some(be);
                let pooled = BACKEND_POOL
                    .with(|pool| pool.borrow_mut().get_mut(&be.id).and_then(|q| q.pop_back()));
                if let Some(s) = pooled {
                    conn = Some(s);
                    reused_pooled = true;
                    break;
                }
                // connect_to is in SECONDS (was from_millis => ~ms timeout)
                match connect_backend(be, be.connect_to.max(1)).await {
                    Some(s) => {
                        conn = Some(s);
                        reused_pooled = false;
                        break;
                    }
                    None => {
                        if skip_count < MAX_BACKEND_TRIES {
                            skip_ids[skip_count] = be.id;
                            skip_count += 1;
                        }
                        continue;
                    }
                }
            }
            let (be, mut b_stream) = match (chosen, conn) {
                (Some(b), Some(s)) => (b, s),
                _ => {
                    let err = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
                    let _ =
                        write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout)
                            .await;
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    crate::shared::inc_status(502);
                    crate::shared::add_bytes_tx(err.len() as u64);
                    return;
                }
            };
            let response_timeout = be.response_to.max(1); // per-backend response timeout (seconds)
                                                          // Hold the backend active-conn count for the WHOLE request (incl. response phase)
            let _conn_guard = crate::shared::ConnGuard::new(be.state.clone());

            // Client requesting a protocol upgrade (e.g. WebSocket)?
            let want_upgrade = req
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("upgrade"))
                && req.headers.iter().any(|h| {
                    h.name.eq_ignore_ascii_case("connection") && contains_ci(h.value, b"upgrade")
                });

            // Build a clean upstream request head (zero per-header String alloc)
            let upstream_keepalive = pool_sz > 0 && !want_upgrade;
            let x_pos = crate::profile_cycles!(
                crate::cycles::SITE_BUILD_UPSTREAM_HEAD,
                build_upstream_head(
                    &mut x_buf,
                    &req,
                    path,
                    use_headers,
                    use_header_names,
                    &client_ip,
                    is_chunked,
                    upstream_keepalive,
                    want_upgrade
                )
            );

            // Fast-path for request path. Combine head and fully buffered body into one write.
            let mut combined_write = false;
            let mut total_x_pos = x_pos;
            if let Some(body) = &full_body {
                if x_pos + body.len() <= x_buf.len() {
                    x_buf[x_pos..x_pos + body.len()].copy_from_slice(body);
                    total_x_pos += body.len();
                    combined_write = true;
                }
            }

            // Write request head (and body if combined); one transparent retry if a (possibly stale) pooled conn failed.
            let mut wrote_ok;
            match write_all_fast(&mut b_stream, x_buf, 0, total_x_pos, client_timeout).await {
                Ok(b) => {
                    x_buf = b;
                    wrote_ok = true;
                }
                Err(Some(b)) => {
                    x_buf = b;
                    wrote_ok = false;
                }
                Err(None) => {
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    return;
                }
            }
            if !wrote_ok && reused_pooled {
                if let Some(s2) = connect_backend(be, be.connect_to.max(1)).await {
                    b_stream = s2;
                    match write_all_fast(&mut b_stream, x_buf, 0, total_x_pos, client_timeout).await
                    {
                        Ok(b) => {
                            x_buf = b;
                            wrote_ok = true;
                        }
                        Err(Some(b)) => {
                            x_buf = b;
                            wrote_ok = false;
                        }
                        Err(None) => {
                            ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                            crate::shared::dec_active_connections();
                            return;
                        }
                    }
                }
            }
            if !wrote_ok {
                let err = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
                let _ =
                    write_all_fast(&mut client, err, 0, err.len(), router.cfg.client_timeout).await;
                ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                crate::shared::dec_active_connections();
                crate::shared::inc_status(502);
                crate::shared::add_bytes_tx(err.len() as u64);
                return;
            }
            if let Some(body) = full_body.take() {
                if !combined_write {
                    let body_len = body.len();
                    // Retain the (already buffered) body so a stale-pooled-conn retry below can replay
                    // it. write_all_fast hands the buffer back, so this costs no copy on the happy path.
                    match write_all_fast(
                        &mut b_stream,
                        body,
                        0,
                        body_len,
                        router.cfg.client_timeout,
                    )
                    .await
                    {
                        Ok(b) | Err(Some(b)) => full_body = Some(b),
                        Err(None) => {}
                    }
                } else {
                    full_body = Some(body); // just to match original type inference / ownership tracking
                }
                c_start += req_len + consumed_from_buf;
            } else {
                c_start += req_len;

                if c_start > 0 {
                    c_buf.copy_within(c_start..c_pos, 0);
                    c_pos -= c_start;
                    c_start = 0;
                }
                match pipe_body(
                    &mut client,
                    &mut b_stream,
                    c_buf,
                    c_pos,
                    is_chunked,
                    clen,
                    false,
                    max_body_size,
                    &mut None,
                    0,
                    client_timeout,
                )
                .await
                {
                    Ok((b, p)) => {
                        c_buf = b;
                        c_pos = p;
                    }
                    Err(too_large) => {
                        if too_large {
                            let err =
                                b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n";
                            let _ = write_all_fast(
                                &mut client,
                                err,
                                0,
                                err.len(),
                                router.cfg.client_timeout,
                            )
                            .await;
                            crate::shared::inc_status(413);
                        }
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        return;
                    }
                }
            }

            let mut b_pos = 0;
            let mut resp_complete = false;
            let mut r_len = 0;
            let mut resp_head_len = 0usize;
            let mut r_clen = 0;
            let mut r_clen_present = false;
            let mut r_chunked = false;
            // Framing: whether the response body is delimited only by connection close, and the
            // effective client keep-alive (forced off for eof-delimited responses, which a client
            // cannot otherwise frame).
            let mut eof_body = false;
            let mut client_ka_eff = client_keep_alive;

            let mut r_cache_buf = None;
            let mut r_cache_valid = false;
            let mut r_cache_max = 0;
            let mut r_cache_etag = None;
            let mut r_cache_last_modified = None;
            let mut r_cache_ttl = 0;
            let mut backend_keep_alive = true;
            if let Some(ref c_cfg) = cache_cfg {
                r_cache_buf = Some(Vec::with_capacity(16384));
                r_cache_max = c_cfg.max_size;
                r_cache_valid = true;
                r_cache_ttl = c_cfg.ttl;
            }

            let mut stale_retry_used = false;
            while !resp_complete {
                // Recover both the read count and the buffer. A connection reset (Err(Some)) is
                // treated like a 0-byte close so the stale-pooled-connection recovery below also
                // fires on RST, which is how a backend keep-alive idle-close often surfaces.
                let n = match read_fast(&mut b_stream, b_buf, b_pos, BUF_SIZE, response_timeout)
                    .await
                {
                    Ok((n, b)) => {
                        b_buf = b;
                        n
                    }
                    Err(Some(b)) => {
                        b_buf = b;
                        0
                    }
                    Err(None) => {
                        // read timed out; the buffer is gone to the kernel
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        return;
                    }
                };
                if n == 0 {
                    // Backend closed before sending any response byte. If we reused a pooled
                    // keep-alive connection and the request is replayable, the pooled socket had gone
                    // stale (backend keep-alive idle close): reconnect once and resend head (+body) on
                    // a fresh connection. Mirrors the write-side retry and closes the pool race.
                    // Replayable = nothing irrecoverable consumed from the client: a body-less request,
                    // or a fully buffered body (`full_body`) we can re-send. A streamed/chunked body was
                    // already piped through and is gone, so those are not replayable (→ honest 502).
                    let replayable =
                        !want_upgrade && ((clen == 0 && !is_chunked) || full_body.is_some());
                    if b_pos == 0 && reused_pooled && !stale_retry_used && replayable {
                        stale_retry_used = true;
                        reused_pooled = false;
                        if let Some(s2) = connect_backend(be, be.connect_to.max(1)).await {
                            b_stream = s2;
                            if let Ok(b) =
                                write_all_fast(&mut b_stream, x_buf, 0, x_pos, client_timeout).await
                            {
                                x_buf = b;
                                // Replay the buffered request body, if any.
                                let mut replay_ok = true;
                                if let Some(body) = full_body.take() {
                                    let bl = body.len();
                                    match write_all_fast(&mut b_stream, body, 0, bl, client_timeout)
                                        .await
                                    {
                                        Ok(b2) => full_body = Some(b2),
                                        _ => replay_ok = false,
                                    }
                                }
                                if replay_ok {
                                    continue;
                                } // retry the response read on the fresh connection
                            }
                        }
                    }
                    // Nothing has been sent to the client yet (b_pos == 0): a 0-byte first read is a
                    // gateway error — answer 502 instead of silently dropping the connection.
                    if b_pos == 0 {
                        let err = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
                        let _ = write_all_fast(
                            &mut client,
                            err,
                            0,
                            err.len(),
                            router.cfg.client_timeout,
                        )
                        .await;
                        crate::shared::inc_status(502);
                        crate::shared::add_bytes_tx(err.len() as u64);
                    }
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    return;
                }
                crate::shared::add_bytes_rx(n as u64);
                b_pos += n;

                // Forward and strip any leading interim 1xx responses (100 Continue, 103 Early
                // Hints) that precede the final response. Re-parsing the buffered remainder here
                // avoids treating an interim response as final (a response-side desync).
                loop {
                    // Cheap check to skip the interim parse for normal responses (2xx-5xx).
                    if b_pos >= 12 && b_buf.starts_with(b"HTTP/1.") && b_buf[8] == b' ' {
                        if b_buf[9] != b'1' {
                            break; // Not a 1xx response, skip double parsing.
                        }
                    } else if b_pos >= 12 {
                        break; // Malformed or non-HTTP/1.x, let the main parser handle it.
                    }

                    let interim = {
                        let mut ih = [httparse::EMPTY_HEADER; 64];
                        let mut ir = httparse::Response::new(&mut ih);
                        match ir.parse(&b_buf[..b_pos]) {
                            Ok(httparse::Status::Complete(ilen)) => {
                                let code = ir.code.unwrap_or(0);
                                if (100..=199).contains(&code) && code != 101 {
                                    Some(ilen)
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    };
                    match interim {
                        Some(ilen) => {
                            match write_all_fast(&mut client, b_buf, 0, ilen, client_timeout).await
                            {
                                Ok(b) => {
                                    b_buf = b;
                                    crate::shared::add_bytes_tx(ilen as u64);
                                }
                                Err(_) => {
                                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                                    crate::shared::dec_active_connections();
                                    return;
                                }
                            }
                            b_buf.copy_within(ilen..b_pos, 0);
                            b_pos -= ilen;
                        }
                        None => break,
                    }
                }

                let mut resp_headers = [httparse::EMPTY_HEADER; 64];
                let mut resp = httparse::Response::new(&mut resp_headers);
                if let Ok(httparse::Status::Complete(len)) = resp.parse(&b_buf[..b_pos]) {
                    let code = resp.code.unwrap_or(502);
                    if code == 101 {
                        // The upgraded connection lives for the whole tunnel, so the backend
                        // active-conn guard must be held until the tunnel ends — move it into the
                        // spawned task rather than letting it drop at this function's return
                        // (which would undercount backend connections for the websocket's lifetime).
                        if write_all_fast(&mut client, b_buf, 0, b_pos, client_timeout)
                            .await
                            .is_ok()
                        {
                            let tunnel_guard = _conn_guard;
                            monoio::spawn(async move {
                                let _g = tunnel_guard; // released when the tunnel closes
                                                       // forward client bytes already buffered (c_buf[..c_pos]) into the backend
                                pipe_tunnel(
                                    client,
                                    b_stream,
                                    client_timeout,
                                    vec![],
                                    0,
                                    c_buf,
                                    c_pos,
                                )
                                .await;
                                ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                                crate::shared::dec_active_connections();
                            });
                        } else {
                            // Client vanished mid-upgrade: no tunnel was spawned, so release the
                            // per-worker counters here instead of leaking them (would otherwise
                            // count toward max_active_requests forever and slowly wedge the worker).
                            ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                            crate::shared::dec_active_connections();
                        }
                        return;
                    }
                    if code != 200 {
                        r_cache_valid = false;
                        r_cache_buf = None;
                    }
                    r_len = len;
                    for h in resp.headers.iter() {
                        if h.name.eq_ignore_ascii_case("content-length") {
                            if let Some(v) = std::str::from_utf8(h.value)
                                .ok()
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                                .and_then(|s| s.parse::<usize>().ok())
                            {
                                r_clen = v;
                                r_clen_present = true;
                            }
                        }
                        if h.name.eq_ignore_ascii_case("transfer-encoding") {
                            if let Ok(s) = std::str::from_utf8(h.value) {
                                if te_is_chunked(s) {
                                    r_chunked = true;
                                }
                            }
                        }
                        // A response that plants a cookie or varies on headers we don't key on
                        // must never be stored — otherwise it is replayed to every other client
                        // (Set-Cookie replay = session fixation; Vary = wrong-variant poisoning).
                        if r_cache_valid && h.name.eq_ignore_ascii_case("set-cookie") {
                            r_cache_valid = false;
                            r_cache_buf = None;
                        }
                        if r_cache_valid && h.name.eq_ignore_ascii_case("vary") {
                            let vary_safe = std::str::from_utf8(h.value)
                                .map(|s| {
                                    s.split(',')
                                        .all(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
                                })
                                .unwrap_or(false);
                            if !vary_safe {
                                r_cache_valid = false;
                                r_cache_buf = None;
                            }
                        }
                        if r_cache_valid {
                            if h.name.eq_ignore_ascii_case("cache-control") {
                                if contains_ci(h.value, b"no-cache")
                                    || contains_ci(h.value, b"no-store")
                                    || contains_ci(h.value, b"private")
                                {
                                    r_cache_valid = false;
                                    r_cache_buf = None;
                                } else if let Some(idx) = find_ci(h.value, b"max-age=") {
                                    // parse digits after "max-age=" without allocating a lowercased copy
                                    if let Ok(rest) = std::str::from_utf8(&h.value[idx + 8..]) {
                                        let val = rest.split(',').next().unwrap_or("").trim();
                                        if let Ok(ma) = val.parse::<u64>() {
                                            r_cache_ttl = ma;
                                        }
                                    }
                                }
                            } else if h.name.eq_ignore_ascii_case("etag") {
                                r_cache_etag =
                                    std::str::from_utf8(h.value).ok().map(|s| s.to_string());
                            } else if h.name.eq_ignore_ascii_case("last-modified") {
                                r_cache_last_modified =
                                    std::str::from_utf8(h.value).ok().map(|s| s.to_string());
                            }
                        }
                        if h.name.eq_ignore_ascii_case("connection")
                            && contains_ci(h.value, b"close")
                        {
                            backend_keep_alive = false;
                        }
                    }
                    // A response with neither Content-Length nor chunked framing (and not a bodiless
                    // status) is delimited only by connection close. Such a body cannot be cached as a
                    // keep-alive blob, and the client must be told to close.
                    eof_body = !r_chunked
                        && !r_clen_present
                        && !matches!(code, 204 | 304)
                        && !(100..=199).contains(&code);
                    if eof_body {
                        r_cache_valid = false;
                        r_cache_buf = None;
                    }
                    client_ka_eff = client_keep_alive && !eof_body;
                    // Graceful worker recycle: once this worker is draining, advertise
                    // `Connection: close` so keep-alive clients finish the in-flight request and
                    // reconnect to a sibling worker, instead of being cut mid-stream at exit.
                    if client_ka_eff && RECYCLE_SHUTDOWN.with(|f| f.get()) {
                        client_ka_eff = false;
                    }

                    resp_head_len = crate::profile_cycles!(
                        crate::cycles::SITE_BUILD_RESPONSE_HEAD,
                        build_response_head(&mut x_buf, &resp, client_ka_eff)
                    );
                    // Stash a keep-alive-forced copy of the head for the cache so served hits can
                    // reuse the connection regardless of the storing client's keep-alive state
                    // (see docs/DESIGN-NOTES.md#4).
                    // (Not profiled separately — same function, but a distinct call shape/purpose
                    // that would otherwise blend two different cost profiles into one site.)
                    if r_cache_valid && r_cache_buf.is_some() {
                        let mut hbuf = get_buf();
                        let hn = build_response_head(&mut hbuf, &resp, true);
                        let fits = {
                            let cb = r_cache_buf.as_mut().unwrap();
                            if cb.len() + hn <= r_cache_max {
                                cb.extend_from_slice(&hbuf[..hn]);
                                true
                            } else {
                                false
                            }
                        };
                        if !fits {
                            r_cache_buf = None;
                            r_cache_valid = false;
                        }
                        put_buf(hbuf);
                    }
                    resp_complete = true;
                } else if b_pos == 16384 {
                    ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                    crate::shared::dec_active_connections();
                    return;
                }
            }

            // Fast-path for completely buffered body with Content-Length.
            // If the body is already fully buffered in `b_buf` and fits in `x_buf` along with the head,
            // we concatenate head and body in `x_buf` and do a single `write_all_fast`.
            let clen = if r_clen_present { r_clen } else { 0 };
            let body_fully_buffered = r_clen_present && b_pos >= r_len + clen;

            if body_fully_buffered && (resp_head_len + clen <= x_buf.len()) {
                if r_cache_valid {
                    if let Some(cb) = &mut r_cache_buf {
                        if cb.len() + clen <= r_cache_max {
                            cb.extend_from_slice(&b_buf[r_len..r_len + clen]);
                        } else {
                            r_cache_buf = None;
                            r_cache_valid = false;
                        }
                    }
                }

                x_buf[resp_head_len..resp_head_len + clen]
                    .copy_from_slice(&b_buf[r_len..r_len + clen]);
                match write_all_fast(&mut client, x_buf, 0, resp_head_len + clen, client_timeout)
                    .await
                {
                    Ok(b) => {
                        x_buf = b;
                        crate::shared::add_bytes_tx((resp_head_len + clen) as u64);
                    }
                    Err(_) => {
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        return;
                    }
                }
                // Whole response (head + buffered body) is sent; nothing left to forward.
                // `b_pos` is reset to 0 at the top of the next keep-alive iteration, so any
                // trailing bytes in `b_buf` need no shifting here (a well-behaved HTTP/1.1
                // backend sends no response bytes before the next request anyway).
            } else {
                // The cache copy of the head (keep-alive forced) was already stashed above; here we only
                // send the per-client normalized head (from x_buf) and then drop the raw head from b_buf.
                match write_all_fast(&mut client, x_buf, 0, resp_head_len, client_timeout).await {
                    Ok(b) => {
                        x_buf = b;
                        crate::shared::add_bytes_tx(resp_head_len as u64);
                    }
                    Err(_) => {
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        return;
                    }
                }

                // eof_body / client_ka_eff were computed from the parsed response framing above.
                b_buf.copy_within(r_len..b_pos, 0);
                b_pos -= r_len;
                match pipe_body(
                    &mut b_stream,
                    &mut client,
                    b_buf,
                    b_pos,
                    r_chunked,
                    r_clen,
                    eof_body,
                    u64::MAX,
                    &mut r_cache_buf,
                    r_cache_max,
                    response_timeout,
                )
                .await
                {
                    Ok((b, _)) => {
                        b_buf = b;
                    }
                    Err(_) => {
                        ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                        crate::shared::dec_active_connections();
                        return;
                    }
                }
            }

            if let Some(cb) = r_cache_buf {
                if r_cache_valid {
                    RESPONSE_CACHE.with(|cache| {
                        let mut map = cache.borrow_mut();
                        map.put(
                            cache_key,
                            CacheEntry {
                                data: bytes::Bytes::from(cb),
                                expires_at: std::time::Instant::now()
                                    + std::time::Duration::from_secs(r_cache_ttl),
                                etag: r_cache_etag,
                                last_modified: r_cache_last_modified,
                            },
                        );
                    });
                }
            }

            // Don't pool a connection whose response was eof-delimited (the backend closes it).
            if pool_sz > 0 && backend_keep_alive && !eof_body {
                BACKEND_POOL.with(|pool| {
                    let mut map = pool.borrow_mut();
                    let queue = map
                        .entry(be.id)
                        .or_insert_with(std::collections::VecDeque::new);
                    if queue.len() < pool_sz {
                        queue.push_back(b_stream);
                    }
                });
            }

            if !client_ka_eff {
                ACTIVE_REQUESTS.with(|c| c.set(c.get().saturating_sub(1)));
                crate::shared::dec_active_connections();
                c_buf_guard.put(c_buf);
                x_buf_guard.put(x_buf);
                b_buf_guard.put(b_buf);
                return;
            }
        }
    }
}

pub async fn run_worker(
    cfg: Config,
    std_listeners_http: Vec<std::net::TcpListener>,
    std_listeners_https: Vec<std::net::TcpListener>,
    tls_acceptor: Option<TlsAcceptor>,
) {
    // Configure the per-worker cache budget before any request can initialize RESPONSE_CACHE.
    CACHE_MAX_BYTES.with(|c| c.set(cfg.cache_max_bytes));
    let router = Arc::new(FastRouter::new(cfg.clone()));

    // Worker recycling (opt-in, default off): when a lifetime or max-request budget is set, the
    // worker stops accepting and exits once the budget is spent; the supervisor respawns it. This
    // bounds the blast radius of any latent per-worker leak/corruption. When disabled, the accept
    // loop is byte-for-byte the original tight `accept().await` (the `recycle` flag short-circuits).
    let recycle = cfg.worker_lifetime.is_some() || cfg.worker_max_requests.is_some();

    for std_l in std_listeners_http {
        let listener = TcpListener::from_std(std_l).unwrap();
        let r_http = router.clone();
        let local_addr_str = listener.local_addr().unwrap().to_string();
        monoio::spawn(async move {
            loop {
                let accepted = if recycle {
                    if RECYCLE_SHUTDOWN.with(|f| f.get()) {
                        break;
                    }
                    // Bounded accept so the drain flag is re-checked even with no new connections.
                    match monoio::time::timeout(
                        std::time::Duration::from_millis(500),
                        listener.accept(),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => continue,
                    }
                } else {
                    listener.accept().await
                };
                if let Ok((stream, addr)) = accepted {
                    let _ = stream.set_nodelay(true);
                    monoio::spawn(proxy_l7_core(
                        stream,
                        r_http.clone(),
                        addr.ip(),
                        false,
                        local_addr_str.clone(),
                    ));
                }
            }
        });
    }

    // Spawn HTTPS listeners
    if let Some(tls_acceptor_cfg) = tls_acceptor {
        for std_l in std_listeners_https {
            let https_listener = TcpListener::from_std(std_l).unwrap();
            let tls_cfg = tls_acceptor_cfg.clone();
            let r_https = router.clone();
            let local_addr_str = https_listener.local_addr().unwrap().to_string();
            monoio::spawn(async move {
                loop {
                    let accepted = if recycle {
                        if RECYCLE_SHUTDOWN.with(|f| f.get()) {
                            break;
                        }
                        match monoio::time::timeout(
                            std::time::Duration::from_millis(500),
                            https_listener.accept(),
                        )
                        .await
                        {
                            Ok(r) => r,
                            Err(_) => continue,
                        }
                    } else {
                        https_listener.accept().await
                    };
                    if let Ok((stream, addr)) = accepted {
                        let _ = stream.set_nodelay(true);
                        let tls_c = tls_cfg.clone();
                        let r2 = r_https.clone();
                        let laddr = local_addr_str.clone();
                        monoio::spawn(async move {
                            if let Ok(tls_stream) = tls_c.accept(stream).await {
                                proxy_l7_core(tls_stream, r2, addr.ip(), true, laddr).await;
                            }
                        });
                    }
                }
            });
        }
    }

    // Recycle monitor: trips on lifetime or request budget, flips the drain flag (which makes the
    // accept loops stop and in-flight keep-alive responses advertise `Connection: close`), waits
    // for in-flight requests to finish (bounded by `worker_drain`), then exits for respawn.
    if recycle {
        use rand::Rng;
        let lifetime = cfg.worker_lifetime;
        let max_reqs = cfg.worker_max_requests;
        let drain = cfg.worker_drain;
        // Per-worker jitter so workers forked together don't all recycle at the same instant
        // (avoids a synchronized capacity dip / fork storm). Up to +25% of the lifetime.
        let deadline = lifetime.map(|secs| {
            let jitter = if secs >= 4 {
                rand::thread_rng().gen_range(0..=secs / 4)
            } else {
                0
            };
            std::time::Instant::now() + std::time::Duration::from_secs(secs + jitter)
        });
        monoio::spawn(async move {
            loop {
                monoio::time::sleep(std::time::Duration::from_millis(500)).await;
                let time_up = deadline.is_some_and(|d| std::time::Instant::now() >= d);
                let reqs_up = max_reqs.is_some_and(|m| REQUESTS_SERVED.with(|c| c.get()) >= m);
                if time_up || reqs_up {
                    let served = REQUESTS_SERVED.with(|c| c.get());
                    let reason = if time_up { "lifetime" } else { "max_requests" };
                    tracing::info!("Worker recycling (reason={}, served={}); draining up to {}s, then exiting for supervisor respawn.", reason, served, drain);
                    RECYCLE_SHUTDOWN.with(|f| f.set(true));
                    let drain_deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(drain);
                    loop {
                        let active = ACTIVE_REQUESTS.with(|c| c.get());
                        if active == 0 || std::time::Instant::now() >= drain_deadline {
                            break;
                        }
                        monoio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    tracing::info!(
                        "Worker drained (remaining in-flight={}); exiting.",
                        ACTIVE_REQUESTS.with(|c| c.get())
                    );
                    std::process::exit(0);
                }
            }
        });
    }

    // Sleep forever in the main worker task
    loop {
        monoio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

#[inline(always)]
async fn read_with_timeout<R>(
    io: &mut R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    timeout_sec: u64,
) -> Result<(usize, Vec<u8>), Option<Vec<u8>>>
where
    R: monoio::io::AsyncReadRent,
{
    let slice = SliceMut::new(buf, start, end);
    match monoio::time::timeout(std::time::Duration::from_secs(timeout_sec), io.read(slice)).await {
        Ok((Ok(n), s)) => Ok((n, s.into_inner())),
        Ok((Err(_), s)) => Err(Some(s.into_inner())),
        Err(_) => Err(None), // timeout, buffer is lost to the kernel
    }
}

#[inline(always)]
async fn write_all_fast<W, B>(
    io: &mut W,
    buf: B,
    start: usize,
    end: usize,
    timeout_sec: u64,
) -> Result<B, Option<B>>
where
    W: monoio::io::AsyncWriteRent,
    B: monoio::buf::IoBuf,
{
    let slice = Slice::new(buf, start, end);
    match monoio::time::timeout(
        std::time::Duration::from_secs(timeout_sec),
        io.write_all(slice),
    )
    .await
    {
        Ok((Ok(_), s)) => Ok(s.into_inner()),
        Ok((Err(_), s)) => Err(Some(s.into_inner())),
        Err(_) => Err(None),
    }
}

#[inline(always)]
async fn read_fast<R>(
    io: &mut R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    timeout_sec: u64,
) -> Result<(usize, Vec<u8>), Option<Vec<u8>>>
where
    R: monoio::io::AsyncReadRent,
{
    let slice = SliceMut::new(buf, start, end);
    match monoio::time::timeout(std::time::Duration::from_secs(timeout_sec), io.read(slice)).await {
        Ok((Ok(n), s)) => Ok((n, s.into_inner())),
        Ok((Err(_), s)) => Err(Some(s.into_inner())),
        Err(_) => Err(None),
    }
}

async fn pipe_tunnel<S1, S2>(
    client: S1,
    backend: S2,
    timeout_sec: u64,
    b_buf: Vec<u8>,
    b_pos: usize,
    c_buf: Vec<u8>,
    c_pos: usize,
) where
    S1: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    S2: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    S1::OwnedRead: monoio::io::AsyncReadRent,
    S1::OwnedWrite: monoio::io::AsyncWriteRent,
    S2::OwnedRead: monoio::io::AsyncReadRent,
    S2::OwnedWrite: monoio::io::AsyncWriteRent,
{
    let (mut cr, mut cw) = client.into_split();
    let (mut br, mut bw) = backend.into_split();

    // Flush any bytes already buffered before the tunnel started: backend->client (e.g. data the
    // backend sent right after 101) and client->backend (e.g. early frames the client pipelined).
    if b_pos > 0 {
        let _ = write_all_fast(&mut cw, b_buf, 0, b_pos, timeout_sec).await;
    }
    if c_pos > 0 {
        let _ = write_all_fast(&mut bw, c_buf, 0, c_pos, timeout_sec).await;
    }

    monoio::spawn(async move {
        let mut buf = vec![0; 16384];
        loop {
            match read_fast(&mut cr, buf, 0, 16384, timeout_sec).await {
                Ok((0, _)) => break,
                Ok((n, b)) => {
                    buf = match write_all_fast(&mut bw, b, 0, n, timeout_sec).await {
                        Ok(b) => b,
                        Err(_) => break,
                    };
                }
                Err(_) => break,
            }
        }
    });

    let mut buf = vec![0; 16384];
    loop {
        match read_fast(&mut br, buf, 0, 16384, timeout_sec).await {
            Ok((0, _)) => break,
            Ok((n, b)) => {
                buf = match write_all_fast(&mut cw, b, 0, n, timeout_sec).await {
                    Ok(b) => b,
                    Err(_) => break,
                };
            }
            Err(_) => break,
        }
    }
}

async fn pipe_body<R, W>(
    src: &mut R,
    dst: &mut W,
    mut buf: Vec<u8>,
    mut pos: usize,
    is_chunked: bool,
    mut clen: usize,
    eof_body: bool,
    max_body_size: u64,
    cache_buf: &mut Option<Vec<u8>>,
    cache_max_size: usize,
    timeout_sec: u64,
) -> Result<(Vec<u8>, usize), bool>
where
    R: monoio::io::AsyncReadRent,
    W: monoio::io::AsyncWriteRent,
{
    let mut total_read: u64 = 0;
    if eof_body {
        loop {
            if pos > 0 {
                if let Some(cb) = cache_buf {
                    if cb.len() + pos <= cache_max_size {
                        cb.extend_from_slice(&buf[0..pos]);
                    } else {
                        *cache_buf = None;
                    }
                }
                buf = match write_all_fast(dst, buf, 0, pos, timeout_sec).await {
                    Ok(b) => b,
                    Err(_) => return Err(false),
                };
                pos = 0;
            } else {
                let (n, b) = match read_fast(src, buf, 0, 16384, timeout_sec).await {
                    Ok(r) => r,
                    Err(_) => return Err(false),
                };
                buf = b;
                pos = n;
                if pos == 0 {
                    return Ok((buf, 0));
                }
            }
        }
    } else if !is_chunked {
        if clen as u64 > max_body_size {
            return Err(true);
        }
        while clen > 0 {
            if pos > 0 {
                let to_write = std::cmp::min(pos, clen);
                if let Some(cb) = cache_buf {
                    if cb.len() + to_write <= cache_max_size {
                        cb.extend_from_slice(&buf[0..to_write]);
                    } else {
                        *cache_buf = None;
                    }
                }
                buf = match write_all_fast(dst, buf, 0, to_write, timeout_sec).await {
                    Ok(b) => b,
                    Err(_) => return Err(false),
                };
                clen -= to_write;
                if pos > to_write {
                    buf.copy_within(to_write..pos, 0);
                    pos -= to_write;
                } else {
                    pos = 0;
                }
            } else {
                let (n, b) = match read_fast(src, buf, 0, 16384, timeout_sec).await {
                    Ok(r) => r,
                    Err(_) => return Err(false),
                };
                buf = b;
                pos = n;
                if pos == 0 {
                    return Err(false);
                }
            }
        }
        Ok((buf, pos))
    } else {
        loop {
            let mut crlf_idx = None;
            loop {
                for i in 0..pos.saturating_sub(1) {
                    if buf[i] == b'\r' && buf[i + 1] == b'\n' {
                        crlf_idx = Some(i);
                        break;
                    }
                }
                if crlf_idx.is_some() {
                    break;
                }
                if pos == 16384 {
                    return Err(false);
                }
                let (n, b) = match read_fast(src, buf, pos, 16384, timeout_sec).await {
                    Ok(r) => r,
                    Err(_) => return Err(false),
                };
                buf = b;
                if n == 0 {
                    return Err(false);
                }
                pos += n;
            }
            let idx = crlf_idx.unwrap();
            let hex_str = std::str::from_utf8(&buf[0..idx]).map_err(|_| false)?;
            let hex_str = hex_str.split(';').next().unwrap().trim();
            let chunk_size = usize::from_str_radix(hex_str, 16).map_err(|_| false)?;

            if let Some(cb) = cache_buf {
                if cb.len() + idx + 2 <= cache_max_size {
                    cb.extend_from_slice(&buf[0..idx + 2]);
                } else {
                    *cache_buf = None;
                }
            }
            buf = match write_all_fast(dst, buf, 0, idx + 2, timeout_sec).await {
                Ok(b) => b,
                Err(_) => return Err(false),
            };
            buf.copy_within(idx + 2..pos, 0);
            pos -= idx + 2;

            if chunk_size == 0 {
                // Last chunk. Consume the trailer section — a bare CRLF when there are no
                // trailers, or trailer lines ending in a blank line — forwarding all of it so a
                // keep-alive stream stays correctly framed (the old code consumed exactly 2 bytes
                // and desynced whenever the backend sent trailers).
                loop {
                    if pos >= 2 && &buf[0..2] == b"\r\n" {
                        if let Some(cb) = cache_buf {
                            if cb.len() + 2 <= cache_max_size {
                                cb.extend_from_slice(&buf[0..2]);
                            } else {
                                *cache_buf = None;
                            }
                        }
                        buf = match write_all_fast(dst, buf, 0, 2, timeout_sec).await {
                            Ok(b) => b,
                            Err(_) => return Err(false),
                        };
                        buf.copy_within(2..pos, 0);
                        pos -= 2;
                        return Ok((buf, pos));
                    }
                    if let Some(end) = buf[..pos].windows(4).position(|w| w == b"\r\n\r\n") {
                        let consume = end + 4;
                        if let Some(cb) = cache_buf {
                            if cb.len() + consume <= cache_max_size {
                                cb.extend_from_slice(&buf[0..consume]);
                            } else {
                                *cache_buf = None;
                            }
                        }
                        buf = match write_all_fast(dst, buf, 0, consume, timeout_sec).await {
                            Ok(b) => b,
                            Err(_) => return Err(false),
                        };
                        buf.copy_within(consume..pos, 0);
                        pos -= consume;
                        return Ok((buf, pos));
                    }
                    if pos == 16384 {
                        return Err(false);
                    } // trailer section too large
                    let (n, b) = match read_fast(src, buf, pos, 16384, timeout_sec).await {
                        Ok(r) => r,
                        Err(_) => return Err(false),
                    };
                    buf = b;
                    if n == 0 {
                        return Err(false);
                    }
                    pos += n;
                }
            } else {
                total_read += chunk_size as u64;
                if total_read > max_body_size {
                    return Err(true);
                }

                // A chunk size that would overflow `+2` (e.g. 0xFFFF…FFFF) is malformed framing —
                // refuse it instead of wrapping to a tiny `remaining` and desyncing the stream.
                // (The response path passes max_body_size = u64::MAX, so the cap above can't catch it.)
                let mut remaining = match chunk_size.checked_add(2) {
                    Some(v) => v,
                    None => return Err(false),
                };
                while remaining > 0 {
                    if pos > 0 {
                        let to_write = std::cmp::min(pos, remaining);
                        if let Some(cb) = cache_buf {
                            if cb.len() + to_write <= cache_max_size {
                                cb.extend_from_slice(&buf[0..to_write]);
                            } else {
                                *cache_buf = None;
                            }
                        }
                        buf = match write_all_fast(dst, buf, 0, to_write, timeout_sec).await {
                            Ok(b) => b,
                            Err(_) => return Err(false),
                        };
                        remaining -= to_write;
                        if pos > to_write {
                            buf.copy_within(to_write..pos, 0);
                            pos -= to_write;
                        } else {
                            pos = 0;
                        }
                    } else {
                        let (n, b) = match read_fast(src, buf, 0, 16384, timeout_sec).await {
                            Ok(r) => r,
                            Err(_) => return Err(false),
                        };
                        buf = b;
                        pos = n;
                        if pos == 0 {
                            return Err(false);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
    use monoio::io::{AsyncReadRent, AsyncWriteRent};
    use std::borrow::Cow;
    // HashMap moved to header_util with compile_headers; the tests for it
    // still live here, so import it locally.
    use std::collections::HashMap;

    // NOTE (2026-08-15): every `#[monoio::test]` here builds an io-uring
    // runtime and registers buffers against the process's RLIMIT_MEMLOCK.
    // On hosts with a small `ulimit -l` (e.g. 8MB) a handful of these in
    // one process can exhaust it and monoio reports `Failed building the
    // Runtime: OutOfMemory`. This is environmental, not a code bug -- CI
    // runners ship a high/ unlimited memlock. If you see those failures
    // locally, raise the limit: `ulimit -l unlimited` (or run each test
    // binary separately).

    /// Read source for `pipe_body` tests that mirrors monoio's own `impl AsyncReadRent for &[u8]`
    /// (monoio's `async_read_rent.rs`) using the real `IoBufMut` methods (`write_ptr`/
    /// `bytes_total`/`set_init`) instead of inventing simplified semantics. `bytes_total()` on the
    /// `SliceMut` window `pipe_body` passes down is exactly `end - begin` from the caller's
    /// `SliceMut::new(buf, begin, end)` (see monoio's `slice.rs`) — respecting it here, and capping
    /// by `max_per_read`, is what makes a small `max_per_read` a faithful simulation of a body that
    /// arrives across many short reads (slow client / TCP segmentation), the same class of surface
    /// as the historical round-3 P0 partial-read bug (which lived in the request-HEADER read loop,
    /// not here — see the sanity-check note on the test using this reader below).
    struct SegReader {
        data: Vec<u8>,
        pos: usize,
        max_per_read: usize,
    }

    impl SegReader {
        fn new(data: &[u8], max_per_read: usize) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
                max_per_read,
            }
        }
    }

    impl AsyncReadRent for SegReader {
        fn read<T: IoBufMut>(
            &mut self,
            mut buf: T,
        ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
            let remaining = self.data.len() - self.pos;
            let amt = remaining
                .min(buf.bytes_total())
                .min(self.max_per_read.max(1));
            unsafe {
                buf.write_ptr()
                    .copy_from_nonoverlapping(self.data[self.pos..].as_ptr(), amt);
                buf.set_init(amt);
            }
            self.pos += amt;
            async move { (Ok(amt), buf) }
        }
        fn readv<T: IoVecBufMut>(
            &mut self,
            buf: T,
        ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
            async move { (Ok(0), buf) } // pipe_body never calls readv
        }
    }

    /// Write sink for `pipe_body` tests: accepts every write whole (no injected short-writes —
    /// `write_all_fast`'s retry loop is generic monoio machinery, already exercised elsewhere; the
    /// thing under test here is `pipe_body`'s own read-side framing) and records exactly what was
    /// written, in order, so tests can assert on the bytes actually forwarded downstream.
    #[derive(Default)]
    struct SinkBuf(Vec<u8>);

    impl AsyncWriteRent for SinkBuf {
        fn write<T: IoBuf>(
            &mut self,
            buf: T,
        ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
            let n = buf.bytes_init();
            unsafe {
                let s = std::slice::from_raw_parts(buf.read_ptr(), n);
                self.0.extend_from_slice(s);
            }
            async move { (Ok(n), buf) }
        }
        fn writev<T: IoVecBuf>(
            &mut self,
            buf_vec: T,
        ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
            async move { (Ok(0), buf_vec) } // pipe_body never calls writev
        }
        fn flush(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> {
            async move { Ok(()) }
        }
        fn shutdown(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> {
            async move { Ok(()) }
        }
    }

    /// Buffer pipe_body's internal `read_fast(src, buf, .., 16384, ..)` calls can legally request
    /// a window against — matches the pooled `BUF_SIZE` buffer production always hands it.
    fn body_buf() -> Vec<u8> {
        vec![0u8; BUF_SIZE]
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_content_length_segmented_with_prebuffered_prefix() {
        // Mirrors the real call shape: a couple of body bytes already sitting in the header-parse
        // buffer ("he"), the rest arriving from the wire split into 3-byte reads.
        let mut buf = body_buf();
        buf[0] = b'h';
        buf[1] = b'e';
        let mut src = SegReader::new(b"llo world!", 3);
        let mut dst = SinkBuf::default();
        let mut cache = Some(Vec::new());

        let (_, pos) = pipe_body(
            &mut src,
            &mut dst,
            buf,
            2,
            false,
            12,
            false,
            u64::MAX,
            &mut cache,
            1_000_000,
            5,
        )
        .await
        .expect("must succeed");
        assert_eq!(pos, 0, "no leftover expected");
        assert_eq!(dst.0, b"hello world!");
        assert_eq!(
            cache.unwrap(),
            b"hello world!",
            "cache must mirror what was forwarded"
        );
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_content_length_retains_pipelined_leftover() {
        // buf already holds the WHOLE body plus the start of the next pipelined request — no read
        // should even happen. An empty SegReader makes that assertable: if pipe_body incorrectly
        // tried to read more, it would hit an immediate 0-byte "EOF" and return Err(false).
        let mut buf = body_buf();
        buf[0..7].copy_from_slice(b"hi!NEXT");
        let mut src = SegReader::new(b"", 16);
        let mut dst = SinkBuf::default();

        let (buf, pos) = pipe_body(
            &mut src,
            &mut dst,
            buf,
            7,
            false,
            3,
            false,
            u64::MAX,
            &mut None,
            0,
            5,
        )
        .await
        .expect("must succeed without reading");
        assert_eq!(dst.0, b"hi!");
        assert_eq!(pos, 4, "leftover pipelined bytes must be retained");
        assert_eq!(
            &buf[0..pos],
            b"NEXT",
            "leftover must be shifted to the front of the buffer"
        );
    }

    // Mutation-tested (2026-07-30): a 1-byte-short trailer terminator (`end + 3` instead of
    // `end + 4`) is caught by this test. A 1-byte-short *chunk* CRLF (`chunk_size.checked_add(1)`
    // instead of `+2`) is NOT caught by a byte-exact passthrough assertion here or in any input
    // shape tried: the dangling `\n` is reinterpreted as the start of the next chunk-size line,
    // and `hex_str.trim()` (deliberately lenient, for real-world stray whitespace) strips it back
    // out — so the same byte just moves which write_all_fast call emits it, and concatenated
    // output is unchanged. Not a security hole (framing still terminates correctly, just one
    // read/write call boundary earlier than "intended"), but worth knowing this class of off-by-
    // one at a chunk boundary is invisible to output-comparison tests; catching it would need an
    // assertion on the read call pattern itself, not on the forwarded bytes.
    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_chunked_segmented_with_trailer() {
        // Two chunks ("hel" + "lo ") plus a trailer header before the final blank line. pipe_body
        // forwards chunked bodies byte-for-byte (it does not decode/re-encode), so the sink should
        // receive an exact copy of the wire bytes.
        let encoded: &[u8] = b"3\r\nhel\r\n3\r\nlo \r\n0\r\nX-Trailer: v\r\n\r\n";
        let mut src = SegReader::new(encoded, 4); // forces multiple reads in both the
                                                  // chunk-size-line scan and the trailer scan
        let mut dst = SinkBuf::default();
        let mut cache = Some(Vec::new());

        let (_, pos) = pipe_body(
            &mut src,
            &mut dst,
            body_buf(),
            0,
            true,
            0,
            false,
            u64::MAX,
            &mut cache,
            1_000_000,
            5,
        )
        .await
        .expect("must succeed");
        assert_eq!(pos, 0);
        assert_eq!(
            dst.0, encoded,
            "chunked body must be forwarded byte-for-byte, including trailer"
        );
        assert_eq!(cache.unwrap(), encoded);
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_chunked_retains_pipelined_leftover() {
        // Terminator with no trailers (bare CRLF), followed by the start of the next request
        // already in the same read.
        let mut buf = body_buf();
        let encoded_plus_next = b"3\r\nhel\r\n0\r\n\r\nNEXT";
        buf[..encoded_plus_next.len()].copy_from_slice(encoded_plus_next);
        let mut src = SegReader::new(b"", 16);
        let mut dst = SinkBuf::default();

        let (buf, pos) = pipe_body(
            &mut src,
            &mut dst,
            buf,
            encoded_plus_next.len(),
            true,
            0,
            false,
            u64::MAX,
            &mut None,
            0,
            5,
        )
        .await
        .expect("must succeed");
        assert_eq!(dst.0, b"3\r\nhel\r\n0\r\n\r\n");
        assert_eq!(pos, 4);
        assert_eq!(&buf[0..pos], b"NEXT");
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_eof_delimited_segmented() {
        let data = b"eof-delimited body split across many short reads";
        let mut src = SegReader::new(data, 5);
        let mut dst = SinkBuf::default();

        let (_, pos) = pipe_body(
            &mut src,
            &mut dst,
            body_buf(),
            0,
            false,
            0,
            true,
            u64::MAX,
            &mut None,
            0,
            5,
        )
        .await
        .expect("must succeed");
        assert_eq!(pos, 0);
        assert_eq!(dst.0, data);
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_content_length_over_max_body_size_rejected() {
        let mut src = SegReader::new(b"", 16);
        let mut dst = SinkBuf::default();
        // clen=100 > max_body_size=50 must be rejected before any read.
        let err = pipe_body(
            &mut src,
            &mut dst,
            body_buf(),
            0,
            false,
            100,
            false,
            50,
            &mut None,
            0,
            5,
        )
        .await;
        assert_eq!(
            err,
            Err(true),
            "must be the 413 (too_large) variant, not a plain connection error"
        );
        assert!(dst.0.is_empty(), "nothing should have been forwarded");
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_chunked_over_max_body_size_rejected() {
        // Declared chunk size (0xA = 10) exceeds max_body_size=5 — must be caught right after the
        // size line is parsed, before the (possibly attacker-huge) chunk body is read.
        let mut src = SegReader::new(b"a\r\n0123456789\r\n0\r\n\r\n", 16);
        let mut dst = SinkBuf::default();
        let err = pipe_body(
            &mut src,
            &mut dst,
            body_buf(),
            0,
            true,
            0,
            false,
            5,
            &mut None,
            0,
            5,
        )
        .await;
        assert_eq!(err, Err(true));
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_pipe_body_chunked_malformed_size_is_connection_error() {
        let mut src = SegReader::new(b"ZZ\r\ndata", 16);
        let mut dst = SinkBuf::default();
        let err = pipe_body(
            &mut src,
            &mut dst,
            body_buf(),
            0,
            true,
            0,
            false,
            u64::MAX,
            &mut None,
            0,
            5,
        )
        .await;
        assert_eq!(
            err,
            Err(false),
            "malformed chunk size must be a connection error (400/close), not 413"
        );
    }

    #[test]
    fn test_is_plain_literal() {
        // metacharacter-free -> literal
        assert!(is_plain_literal("localhost"));
        assert!(is_plain_literal("/api"));
        assert!(is_plain_literal("api-v2_x")); // '-' and '_' are not regex metachars
        assert!(is_plain_literal("example_com"));
        // any regex metacharacter -> not a literal (stays on the engine)
        assert!(!is_plain_literal("example.com")); // '.'
        assert!(!is_plain_literal(".*"));
        assert!(!is_plain_literal("^/api"));
        assert!(!is_plain_literal("/v[0-9]+/"));
        assert!(!is_plain_literal("a|b"));
        assert!(!is_plain_literal("")); // empty -> engine (matches everything)
    }

    /// Helper: normalize unconditionally (bypasses the `needs_path_normalize` gate) so the
    /// canonicaliser itself is tested, including on already-canonical input.
    fn norm(target: &str) -> String {
        let mut out = Vec::new();
        normalize_path_into(target, &mut out);
        String::from_utf8(out).expect("normalized target must stay valid UTF-8")
    }

    #[test]
    fn test_needs_path_normalize_gate() {
        // canonical targets must not trigger a rewrite (this is the hot path)
        assert!(!needs_path_normalize(b"/"));
        assert!(!needs_path_normalize(b"/api/users/42"));
        assert!(!needs_path_normalize(b"/a.b/c-d_e~f"));
        assert!(!needs_path_normalize(b"*"));
        // the query/fragment must never arm the path rewriter
        assert!(!needs_path_normalize(b"/api?r=//evil&a=%2e%2e"));
        assert!(!needs_path_normalize(b"/api#/../x"));
        // …but anything suspicious in the path part must
        assert!(needs_path_normalize(b"/a/../b"));
        assert!(needs_path_normalize(b"//admin"));
        assert!(needs_path_normalize(b"/%61dmin"));
        assert!(needs_path_normalize(b"/a/./b"));
        assert!(needs_path_normalize(b"/a/."));
        assert!(needs_path_normalize(b"/a//"));
    }

    #[test]
    fn test_path_has_separator_evasion() {
        // encoded separators in the PATH part, either case
        assert!(path_has_separator_evasion(b"/a%2Fb"));
        assert!(path_has_separator_evasion(b"/a%2fb"));
        assert!(path_has_separator_evasion(b"/a%5Cb"));
        assert!(path_has_separator_evasion(b"/a%5cb"));
        assert!(path_has_separator_evasion(b"/a%2f../admin"));
        // raw backslash: illegal pchar, and a separator for Windows/IIS-family upstreams
        assert!(path_has_separator_evasion(b"/pub\\..\\admin"));
        // the query is excluded on purpose: encoded slashes there are legitimate
        assert!(!path_has_separator_evasion(
            b"/oauth?redirect_uri=https%3A%2F%2Fx.test%2Fcb"
        ));
        assert!(!path_has_separator_evasion(b"/a?x=%5C"));
        assert!(!path_has_separator_evasion(b"/a?x=a\\b"));
        assert!(!path_has_separator_evasion(b"/a#%2F"));
        // other escapes and malformed ones are not separators
        assert!(!path_has_separator_evasion(b"/a%20b"));
        assert!(!path_has_separator_evasion(b"/%61dmin"));
        assert!(!path_has_separator_evasion(b"/a%2"));
        assert!(!path_has_separator_evasion(b"/a%"));
        assert!(!path_has_separator_evasion(b"/plain/path"));
        // double-encoding is NOT caught here (it needs two upstream decodes) — documented residual
        assert!(!path_has_separator_evasion(b"/a%252Fb"));
    }

    #[test]
    fn test_normalize_dot_segments() {
        assert_eq!(norm("/"), "/");
        assert_eq!(norm("/api/users"), "/api/users");
        assert_eq!(norm("/x/../admin"), "/admin");
        assert_eq!(norm("/./admin"), "/admin");
        assert_eq!(norm("//admin"), "/admin");
        assert_eq!(norm("///a////b"), "/a/b");
        assert_eq!(norm("/a/b/../../c"), "/c");
        // cannot escape the root, whatever the depth
        assert_eq!(norm("/.."), "/");
        assert_eq!(norm("/../.."), "/");
        assert_eq!(norm("/../../../etc/passwd"), "/etc/passwd");
        assert_eq!(norm("//.."), "/");
        assert_eq!(norm("/."), "/");
        // RFC 3986 §5.2.4: a final "." / ".." leaves a trailing slash
        assert_eq!(norm("/a/b/"), "/a/b/");
        assert_eq!(norm("/a/b/."), "/a/b/");
        assert_eq!(norm("/a/b/.."), "/a/");
        assert_eq!(norm("/a/b//"), "/a/b/");
        // dot-prefixed names are ordinary segments, not dot-segments
        assert_eq!(norm("/.well-known/x"), "/.well-known/x");
        assert_eq!(norm("/a/...b/c"), "/a/...b/c");
    }

    #[test]
    fn test_normalize_percent_escapes() {
        // unreserved escapes decode (RFC 3986 §6.2.2.2) — this closes /%61dmin style evasion
        assert_eq!(norm("/%61dmin"), "/admin");
        assert_eq!(norm("/a/%2e%2e/admin"), "/admin");
        assert_eq!(norm("/a/%2E./admin"), "/admin");
        assert_eq!(norm("/%7Euser"), "/~user");
        assert_eq!(norm("/a%2Db"), "/a-b");
        // reserved stays encoded: %2F must NOT become a segment boundary
        assert_eq!(norm("/a%2Fb"), "/a%2Fb");
        assert_eq!(norm("/a%2f../b"), "/a%2f../b");
        assert_eq!(norm("/a%5C..%5Cb"), "/a%5C..%5Cb");
        assert_eq!(norm("/a%20b"), "/a%20b");
    }

    #[test]
    fn test_normalize_malformed_escapes_never_panic() {
        // truncated / non-hex escapes are copied literally — a crafted target must not abort a
        // worker (panic = abort + respawn under the supervisor).
        assert_eq!(norm("/foo%"), "/foo%");
        assert_eq!(norm("/foo%2"), "/foo%2");
        assert_eq!(norm("/%"), "/%");
        assert_eq!(norm("/%%"), "/%%");
        assert_eq!(norm("/%zz"), "/%zz");
        assert_eq!(norm("/%2%2"), "/%2%2");
        assert_eq!(norm("/a/%"), "/a/%");
        // `%2e` decodes to '.', the stray `%` stays literal — the segment is ".%", not a
        // dot-segment, so it is retained rather than collapsed.
        assert_eq!(norm("/%2e%"), "/.%");
        assert_eq!(norm("/%2e%2e%"), "/..%");
    }

    #[test]
    fn test_normalize_preserves_query_and_never_empties() {
        // query/fragment copied verbatim, path canonicalised
        assert_eq!(norm("/a/../b?x=1&y=//z"), "/b?x=1&y=//z");
        assert_eq!(norm("/a/..?q=%2e%2e"), "/?q=%2e%2e");
        assert_eq!(norm("//?"), "/?");
        // A `#` still terminates the path part here (defence in depth), but a request-target
        // carrying one never reaches this function: it is rejected with 400 before routing,
        // because an un-normalized tail would be a canonicalisation bypass.
        assert_eq!(norm("/a/../b#/../c"), "/b#/../c");
        // the result is always a valid origin-form target: non-empty and rooted
        for t in ["/", "/..", "/../..", "//", "/.", "//.", "/%2e", "/a/.."] {
            let n = norm(t);
            assert!(n.starts_with('/'), "{t:?} -> {n:?} lost its root");
            assert!(!n.is_empty());
        }
    }

    #[test]
    fn test_host_without_port() {
        assert_eq!(host_without_port("example.com"), "example.com");
        assert_eq!(host_without_port("example.com:8080"), "example.com");
        assert_eq!(host_without_port("localhost:443"), "localhost");
        assert_eq!(host_without_port("[::1]:80"), "[::1]"); // IPv6 + port
        assert_eq!(host_without_port("[::1]"), "[::1]"); // bare IPv6, not a port
        assert_eq!(host_without_port("host:notaport"), "host:notaport");
    }

    #[test]
    fn test_matcher_exact_prefix_regex() {
        use regex::Regex;
        // domains/validate: literal => exact equality (no substring, no prefix)
        let d = Matcher::exact_or_re(&Regex::new("localhost").unwrap());
        assert!(d.is_match("localhost"));
        assert!(!d.is_match("localhostx")); // not a substring match
        assert!(!d.is_match("xlocalhost"));
        assert!(!d.is_match("local"));
        // routes: literal => path prefix
        let r = Matcher::prefix_or_re(&Regex::new("/api").unwrap());
        assert!(r.is_match("/api"));
        assert!(r.is_match("/api/users")); // prefix match
        assert!(!r.is_match("/v1/api")); // not a prefix
                                         // regex (has metachars): engine, unanchored — same via either constructor
        let re_anchored = Matcher::exact_or_re(&Regex::new(r"^exact\.host$").unwrap());
        assert!(re_anchored.is_match("exact.host"));
        assert!(!re_anchored.is_match("exactXhost")); // escaped dot is literal
        assert!(!re_anchored.is_match("exact.host.evil")); // anchored
        let re_any = Matcher::prefix_or_re(&Regex::new(".*").unwrap());
        assert!(re_any.is_match("anything"));
        // pat_len drives the domain longest-match tie-break
        assert_eq!(
            Matcher::exact_or_re(&Regex::new("localhost").unwrap()).pat_len(),
            9
        );
    }

    #[test]
    fn test_contains_ci() {
        assert!(contains_ci(b"keep-alive, close", b"close"));
        assert!(contains_ci(b"CLOSE", b"close"));
        assert!(contains_ci(b"Upgrade", b"upgrade"));
        assert!(!contains_ci(b"keep-alive", b"close"));
        assert!(!contains_ci(b"clos", b"close")); // shorter than needle
        assert!(contains_ci(b"anything", b"")); // empty needle
    }

    #[test]
    fn test_build_response_head_framing() {
        // CL+TE: chunked wins, Content-Length must be dropped (no CL+TE ambiguity to the client).
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\n";
        let mut h = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut h);
        resp.parse(raw).unwrap();
        let mut out = vec![0u8; 256];
        let n = build_response_head(&mut out, &resp, true);
        let s = std::str::from_utf8(&out[..n]).unwrap();
        assert!(
            !s.to_ascii_lowercase().contains("content-length"),
            "CL must be dropped under chunked: {s}"
        );
        assert!(s
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked"));
        assert!(s.contains("X-A: 1"));

        // Duplicate Content-Length collapses to a single header.
        let raw2 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let mut h2 = [httparse::EMPTY_HEADER; 16];
        let mut resp2 = httparse::Response::new(&mut h2);
        resp2.parse(raw2).unwrap();
        let mut out2 = vec![0u8; 256];
        let n2 = build_response_head(&mut out2, &resp2, false);
        let s2 = std::str::from_utf8(&out2[..n2]).unwrap();
        assert_eq!(
            s2.to_ascii_lowercase().matches("content-length").count(),
            1,
            "dup CL must collapse: {s2}"
        );
    }

    #[test]
    fn test_te_is_chunked() {
        assert!(te_is_chunked("chunked"));
        assert!(te_is_chunked("gzip, chunked"));
        assert!(te_is_chunked("CHUNKED"));
        assert!(!te_is_chunked("chunked, gzip")); // chunked not last
        assert!(!te_is_chunked("chunkedX")); // substring, not a token
        assert!(!te_is_chunked("identity"));
    }

    #[test]
    fn test_eval_field_conditions() {
        let get = |k: &str| -> Option<Cow<str>> {
            match k {
                "exist_key" => Some(Cow::Borrowed("val1")),
                "int_key" => Some(Cow::Borrowed("123")),
                "empty_key" => Some(Cow::Borrowed("")),
                "enum_key" => Some(Cow::Borrowed("C")),
                _ => None,
            }
        };

        // exist
        assert!(eval_field_conditions("exist_key", get));
        assert!(!eval_field_conditions("missing_key", get));

        // exact match
        assert!(eval_field_conditions("exist_key=val1", get));
        assert!(!eval_field_conditions("exist_key=val2", get));

        // not exist
        assert!(eval_field_conditions("!missing_key", get));
        assert!(!eval_field_conditions("!exist_key", get));

        // int type
        assert!(eval_field_conditions("int_key=int", get));
        assert!(!eval_field_conditions("exist_key=int", get));

        // str type (not empty)
        assert!(eval_field_conditions("exist_key=str", get));
        assert!(!eval_field_conditions("empty_key=str", get));

        // enum
        assert!(eval_field_conditions("enum_key=enum(A,B,C)", get));
        assert!(!eval_field_conditions("enum_key=enum(A,B)", get));

        // combination (OR via pipe)
        assert!(eval_field_conditions("exist_key=val2|val1", get));

        // Multiple conditions
        assert!(eval_field_conditions("exist_key int_key=int !missing", get));
        assert!(!eval_field_conditions("exist_key int_key=str missing", get));
    }

    #[test]
    fn test_compile_headers_none() {
        let empty: Option<HashMap<String, String>> = None;
        let frags = compile_headers(&empty);
        assert!(frags.is_empty());
    }

    #[test]
    fn test_compile_headers_simple() {
        let mut hm = HashMap::new();
        hm.insert("X-Custom".to_string(), "value".to_string());
        let frags = compile_headers(&Some(hm));
        assert_eq!(frags.len(), 1);
        match &frags[0] {
            HeaderFragment::Text(t) => {
                assert_eq!(std::str::from_utf8(t).unwrap(), "X-Custom: value\r\n");
            }
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn test_compile_headers_client_ip_exact() {
        let mut hm = HashMap::new();
        hm.insert("X-Forwarded-For".to_string(), "$client_ip".to_string());
        let frags = compile_headers(&Some(hm));
        // Three fragments: Text("X-Forwarded-For: "), ClientIp, Text("\r\n")
        assert_eq!(frags.len(), 3);
        assert!(matches!(frags[1], HeaderFragment::ClientIp));
        // First fragment is the header prefix
        if let HeaderFragment::Text(t) = &frags[0] {
            assert_eq!(std::str::from_utf8(t).unwrap(), "X-Forwarded-For: ");
        } else {
            panic!("expected Text");
        }
    }

    #[test]
    fn test_compile_headers_client_ip_middle() {
        let mut hm = HashMap::new();
        hm.insert("X-Custom".to_string(), "ip=$client_ip;done".to_string());
        let frags = compile_headers(&Some(hm));
        assert_eq!(frags.len(), 3);
        assert!(matches!(frags[1], HeaderFragment::ClientIp));
    }

    #[test]
    fn test_compile_header_names() {
        let empty: Option<HashMap<String, String>> = None;
        assert!(compile_header_names(&empty).is_empty());

        let mut hm = HashMap::new();
        hm.insert("X-Custom".to_string(), "val".to_string());
        let names = compile_header_names(&Some(hm));
        assert_eq!(names.len(), 1);
        assert_eq!(std::str::from_utf8(&names[0]).unwrap(), "X-Custom");
    }

    #[test]
    fn test_buf_put_basic() {
        let mut x = vec![0u8; 4];
        let mut pos = 0;
        buf_put(&mut x, &mut pos, b"ab");
        assert_eq!(pos, 2);
        assert_eq!(&x[..2], b"ab");
        // bytes beyond pos are still the original zeros
        assert_eq!(x[2], 0);
        assert_eq!(x[3], 0);
    }

    #[test]
    fn test_buf_put_grow() {
        let mut x = vec![0u8; 4];
        let mut pos = 0;
        buf_put(&mut x, &mut pos, b"1234567890");
        assert_eq!(pos, 10);
        assert!(x.len() >= 10);
        assert_eq!(&x[..10], b"1234567890");
    }

    #[test]
    fn test_find_ci() {
        assert_eq!(find_ci(b"Content-Type", b"content-type"), Some(0));
        assert_eq!(find_ci(b"Content-Type", b"type"), Some(8));
        assert_eq!(find_ci(b"Content-Type", b"notfound"), None);
        assert_eq!(find_ci(b"anything", b""), Some(0));
        assert_eq!(find_ci(b"abc", b"abcd"), None);
    }

    #[test]
    fn test_build_upstream_head_normal() {
        let raw = b"GET /foo HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let mut x = Vec::new();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let n = build_upstream_head(&mut x, &req, "/foo", &[], &[], &ip, false, false, false);
        let head = String::from_utf8_lossy(&x[..n]);
        assert!(
            head.starts_with("GET /foo HTTP/1.1\r\n"),
            "bad request line: {head}"
        );
        assert!(head.contains("Host: example.com"), "missing Host: {head}");
        // Connection: close from client is hop-by-hop, stripped; then re-added by function
        assert!(
            head.contains("Connection: close"),
            "missing Connection: close: {head}"
        );
        assert_eq!(
            head.matches("Connection:").count(),
            1,
            "Connection dup: {head}"
        );
    }

    #[test]
    fn test_build_upstream_head_chunked() {
        let raw = b"POST /bar HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let mut x = Vec::new();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let n = build_upstream_head(&mut x, &req, "/bar", &[], &[], &ip, true, false, false);
        let head = String::from_utf8_lossy(&x[..n]);
        // is_chunked=true → Content-Length stripped, Transfer-Encoding added
        assert!(
            head.contains("Transfer-Encoding: chunked"),
            "missing TE: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("content-length"),
            "CL leaked: {head}"
        );
    }

    #[test]
    fn test_build_upstream_head_want_upgrade() {
        let raw = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let mut x = Vec::new();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let n = build_upstream_head(&mut x, &req, "/chat", &[], &[], &ip, false, false, true);
        let head = String::from_utf8_lossy(&x[..n]);
        // want_upgrade=true → Connection and Upgrade forwarded, no auto Connection header
        assert!(
            head.contains("Connection: Upgrade"),
            "missing Connection Upgrade: {head}"
        );
        assert!(
            head.contains("Upgrade: websocket"),
            "missing Upgrade: {head}"
        );
        // No Connection: close/keep-alive auto-injected
        assert!(
            !head.contains("Connection: close"),
            "unexpected close: {head}"
        );
    }

    #[test]
    fn test_build_upstream_head_strips_hop_by_hop() {
        // Every RFC 7230 §6.1 hop-by-hop header a client could send, plus a client-supplied
        // Transfer-Encoding (must never be forwarded verbatim — request smuggling primitive).
        let raw = b"GET /x HTTP/1.1\r\nHost: example.com\r\nTE: trailers\r\nTrailer: X-Foo\r\n\
Transfer-Encoding: chunked\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\n\
Proxy-Authorization: Basic xxx\r\nX-Custom: keep-me\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let mut x = Vec::new();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        // is_chunked=false: the client's own Transfer-Encoding must be gone, not replaced.
        let n = build_upstream_head(&mut x, &req, "/x", &[], &[], &ip, false, false, false);
        let head = String::from_utf8_lossy(&x[..n]).to_ascii_lowercase();
        for hop in [
            "te:",
            "trailer:",
            "transfer-encoding:",
            "keep-alive:",
            "proxy-authenticate:",
            "proxy-authorization:",
        ] {
            assert!(
                !head.contains(hop),
                "hop-by-hop header leaked ({hop}): {head}"
            );
        }
        assert!(
            head.contains("x-custom: keep-me"),
            "ordinary header dropped: {head}"
        );
    }

    #[test]
    fn test_build_upstream_head_dup_content_length_collapses() {
        let raw = b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let mut x = Vec::new();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let n = build_upstream_head(&mut x, &req, "/x", &[], &[], &ip, false, false, false);
        let head = String::from_utf8_lossy(&x[..n]).to_ascii_lowercase();
        assert_eq!(
            head.matches("content-length").count(),
            1,
            "dup CL must collapse: {head}"
        );
    }

    #[test]
    fn test_build_upstream_head_keepalive_true() {
        let raw = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let mut x = Vec::new();
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let n = build_upstream_head(&mut x, &req, "/x", &[], &[], &ip, false, true, false);
        let head = String::from_utf8_lossy(&x[..n]);
        assert!(
            head.contains("Connection: keep-alive"),
            "missing keep-alive: {head}"
        );
    }

    #[test]
    fn test_build_upstream_head_client_ip_injection() {
        let raw = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let frags = vec![
            HeaderFragment::Text(b"X-Forwarded-For: ".to_vec()),
            HeaderFragment::ClientIp,
            HeaderFragment::Text(b"\r\n".to_vec()),
        ];
        let mut x = Vec::new();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let n = build_upstream_head(&mut x, &req, "/x", &frags, &[], &ip, false, false, false);
        let head = String::from_utf8_lossy(&x[..n]);
        assert!(
            head.contains("X-Forwarded-For: 203.0.113.7\r\n"),
            "bad client-ip injection: {head}"
        );
    }

    #[test]
    fn test_build_upstream_head_inject_names_drops_client_supplied() {
        // Client sends its own X-Forwarded-For; the route also injects one via set_frags. The
        // client-supplied copy must be dropped (inject_names), or the backend sees two conflicting
        // values — the second of which an attacker fully controls (spoofing primitive).
        let raw = b"GET /x HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 6.6.6.6\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(raw).unwrap();

        let frags = vec![
            HeaderFragment::Text(b"X-Forwarded-For: ".to_vec()),
            HeaderFragment::ClientIp,
            HeaderFragment::Text(b"\r\n".to_vec()),
        ];
        let inject_names = vec![b"X-Forwarded-For".to_vec()];
        let mut x = Vec::new();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let n = build_upstream_head(
            &mut x,
            &req,
            "/x",
            &frags,
            &inject_names,
            &ip,
            false,
            false,
            false,
        );
        let head = String::from_utf8_lossy(&x[..n]);
        assert_eq!(
            head.matches("X-Forwarded-For:").count(),
            1,
            "client-spoofed XFF not deduped: {head}"
        );
        assert!(
            !head.contains("6.6.6.6"),
            "attacker-controlled XFF leaked through: {head}"
        );
        assert!(
            head.contains("203.0.113.7"),
            "real client ip missing: {head}"
        );
    }

    #[test]
    fn test_build_response_head_strips_hop_by_hop() {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\nKeep-Alive: timeout=5\r\n\
Proxy-Authenticate: Basic\r\nProxy-Authorization: Basic xxx\r\nUpgrade: h2c\r\n\
Trailer: X-Foo\r\nTE: trailers\r\nX-Custom: keep-me\r\n\r\n";
        let mut h = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut h);
        resp.parse(raw).unwrap();
        let mut out = vec![0u8; 256];
        let n = build_response_head(&mut out, &resp, true);
        let s = String::from_utf8_lossy(&out[..n]).to_ascii_lowercase();
        for hop in [
            "keep-alive:",
            "proxy-authenticate:",
            "proxy-authorization:",
            "upgrade:",
            "trailer:",
            "te:",
        ] {
            assert!(!s.contains(hop), "hop-by-hop header leaked ({hop}): {s}");
        }
        assert!(
            s.contains("x-custom: keep-me"),
            "ordinary header dropped: {s}"
        );
        // Connection must be OUR recomputed value, not the backend's forwarded one, and appear once.
        assert_eq!(
            s.matches("connection:").count(),
            1,
            "Connection dup or missing: {s}"
        );
    }

    #[test]
    fn test_build_response_head_connection_value_follows_client_keepalive() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";
        let mut h1 = [httparse::EMPTY_HEADER; 16];
        let mut r1 = httparse::Response::new(&mut h1);
        r1.parse(raw).unwrap();
        let mut out1 = vec![0u8; 256];
        let n1 = build_response_head(&mut out1, &r1, true);
        assert!(String::from_utf8_lossy(&out1[..n1]).contains("Connection: keep-alive"));

        let mut h2 = [httparse::EMPTY_HEADER; 16];
        let mut r2 = httparse::Response::new(&mut h2);
        r2.parse(raw).unwrap();
        let mut out2 = vec![0u8; 256];
        let n2 = build_response_head(&mut out2, &r2, false);
        assert!(String::from_utf8_lossy(&out2[..n2]).contains("Connection: close"));
    }

    // Per-request-weighted CPU-cycle report, not a correctness test (never
    // asserts). `#[ignore]`d: cargo test --release --features cycle_profile
    // cycle_profile_report -- --ignored --nocapture. See docs/DESIGN-NOTES.md#1.
    #[cfg(feature = "cycle_profile")]
    #[test]
    #[ignore]
    fn cycle_profile_report() {
        // 200k measured iterations (was 50k) + a 20k warmup pass so the branch
        // predictor / cache state is steady BEFORE the instrumented loop — the
        // old 50k run was noise-dominated (p50 fell in a 2x-wide bucket and was
        // tagged "within 3x measurement floor").
        const N: usize = 200_000;
        const WARMUP: usize = 20_000;

        // One simulated request+response per iteration — build_upstream_head and
        // build_response_head each called exactly once, matching their real per-request ratio.
        // Buffers reused across iterations (pooled in the real hot path too; both functions always
        // write from pos=0 and return the valid length, so a dirty reused buffer is safe — see
        // buf_put). Request/response shape varies per iteration so LTO can't fold the loop.
        let mut x_buf = Vec::with_capacity(BUF_SIZE);
        let mut resp_buf = Vec::with_capacity(BUF_SIZE);
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        // Warmup: same body, un-instrumented. CPU frequency scaling, cache
        // residency and the branch predictor settle here, not in the measured loop.
        for i in 0..WARMUP {
            let raw_req = format!(
                "GET /api/v1/widgets/{i} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench/1.0\r\n\
                 Accept: */*\r\nAccept-Encoding: gzip\r\nX-Request-Id: {i}\r\nConnection: keep-alive\r\n\r\n"
            );
            let mut req_headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut req_headers);
            req.parse(raw_req.as_bytes()).unwrap();
            let path = req.path.unwrap_or("/");
            std::hint::black_box(build_upstream_head(
                &mut x_buf,
                &req,
                path,
                &[],
                &[],
                &ip,
                false,
                true,
                false,
            ));

            let raw_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {i}\r\n\
                 X-Request-Id: {i}\r\n\r\n"
            );
            let mut resp_headers = [httparse::EMPTY_HEADER; 16];
            let mut resp = httparse::Response::new(&mut resp_headers);
            resp.parse(raw_resp.as_bytes()).unwrap();
            std::hint::black_box(build_response_head(&mut resp_buf, &resp, true));
        }

        for i in 0..N {
            let raw_req = format!(
                "GET /api/v1/widgets/{i} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench/1.0\r\n\
                 Accept: */*\r\nAccept-Encoding: gzip\r\nX-Request-Id: {i}\r\nConnection: keep-alive\r\n\r\n"
            );
            let mut req_headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut req_headers);
            req.parse(raw_req.as_bytes()).unwrap();
            let path = req.path.unwrap_or("/");
            let n = crate::profile_cycles!(
                crate::cycles::SITE_BUILD_UPSTREAM_HEAD,
                build_upstream_head(&mut x_buf, &req, path, &[], &[], &ip, false, true, false)
            );
            std::hint::black_box(n);

            let raw_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {i}\r\n\
                 X-Request-Id: {i}\r\n\r\n"
            );
            let mut resp_headers = [httparse::EMPTY_HEADER; 16];
            let mut resp = httparse::Response::new(&mut resp_headers);
            resp.parse(raw_resp.as_bytes()).unwrap();
            let m = crate::profile_cycles!(
                crate::cycles::SITE_BUILD_RESPONSE_HEAD,
                build_response_head(&mut resp_buf, &resp, true)
            );
            std::hint::black_box(m);
        }

        // jwt_claim_u64: separate loop, labeled — real traffic calls this 0 times per request
        // unless the matched route has JWT filtering configured, in which case it's exactly 2
        // (exp+nbf), which this reproduces.
        for i in 0..N {
            let payload = format!(
                r#"{{"sub":"user","exp":{},"nbf":1000}}"#,
                1_700_000_000u64 + i as u64
            );
            let exp = crate::profile_cycles!(
                crate::cycles::SITE_JWT_CLAIM_U64,
                jwt_claim_u64(payload.as_bytes(), b"exp")
            );
            let nbf = crate::profile_cycles!(
                crate::cycles::SITE_JWT_CLAIM_U64,
                jwt_claim_u64(payload.as_bytes(), b"nbf")
            );
            std::hint::black_box((exp, nbf));
        }

        // buf_put: measured in ISOLATION, not nested (see the comment on buf_put's definition —
        // nesting a full timed Site here was tried and reverted after it inflated
        // build_upstream_head's reported min ~28x). Representative call: a header-value-sized
        // write with no resize needed (the common case; resize is rare/amortized in real use, and
        // happens at most once here since pos is reset to a range already covered by capacity).
        let mut bp_buf = Vec::with_capacity(BUF_SIZE);
        let mut bp_pos = 0usize;
        for i in 0..N {
            let val = format!("value-{i}-abcdefgh");
            bp_pos = 0;
            crate::profile_cycles!(
                crate::cycles::SITE_BUF_PUT,
                buf_put(&mut bp_buf, &mut bp_pos, val.as_bytes())
            );
        }
        std::hint::black_box(bp_pos);

        // tsc_hz is specific to this test's per-request-weighted ns conversion; the per-site
        // table itself is cycles::report()'s generic dump (adds the floor-noise annotation and
        // raw recent-sample list that a bespoke printout here would just be duplicating).
        eprintln!("=== cycle_profile_report: N={N} simulated requests ===");
        eprintln!("tsc_hz={}", crate::cycles::tsc_hz());
        crate::cycles::report();
    }

    #[test]
    fn cache_header_rewrite_does_not_corrupt_body() {
        // Reproduce the bug reported 2026-08-16: the old
        // serve_cache_hit searched for "Connection: keep-alive" across the
        // ENTIRE cached blob (headers + body). If the body contains that
        // string (e.g. an HTTP log viewer, a JSON echo endpoint), the rewrite
        // would corrupt it. Now the search is bounded to the header section.
        let fake_response: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 13\r\n\
            Connection: keep-alive\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            response-body: Connection: keep-alive";

        let header_end = fake_response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap();
        let ka = b"Connection: keep-alive\r\n";
        assert!(
            crate::header_util::find_ci(&fake_response[..header_end], ka).is_some(),
            "Connection header should be found in the header section"
        );
        assert!(
            crate::header_util::find_ci(fake_response, ka).is_some(),
            "Connection string exists somewhere in the full blob"
        );
        // Crucially, if we ONLY search the header section, the body's copy
        // is not touched. This is the invariant serve_cache_hit now enforces.
        assert!(
            crate::header_util::find_ci(&fake_response[..header_end], ka)
                .map(|pos| pos < header_end)
                .unwrap_or(false)
        );
    }

    #[monoio::test(timer_enabled = true)]
    async fn cache_hit_rewrites_connection_close_when_header_is_last() {
        // Regression for a real bug found 2026-08-17: this is the SHAPE the
        // real cache actually stores (Connection: keep-alive is the LAST
        // header before the blank line -- see docs/DESIGN-NOTES.md#4 for why
        // serve_cache_hit stores it keep-alive-forced). The earlier version
        // of this test used a payload
        // with an extra header AFTER Connection, which never exercised this
        // boundary and passed even while the real end-to-end path was
        // broken: `&blob[..header_end]` (header_end = start of "\r\n\r\n")
        // truncates the last header's own trailing "\r\n" -- which IS the
        // first half of that same "\r\n\r\n" -- so the 24-byte KA pattern
        // could never match when Connection is the last header. Calls the
        // real serve_cache_hit end-to-end (not a reimplementation of its
        // boundary math) so a regression here fails this test directly.
        let blob = bytes::Bytes::from_static(
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\nresponse-body",
        );
        let mut dst = SinkBuf::default();
        let outcome = serve_cache_hit(&mut dst, 200, Some(blob), false, 5).await;
        assert!(matches!(outcome, CacheHitOutcome::Close));
        let written = String::from_utf8_lossy(&dst.0);
        assert!(
            written.contains("Connection: close"),
            "expected the close-rewrite to fire, got: {written}"
        );
        assert!(
            !written.contains("keep-alive"),
            "keep-alive must not reach a client that asked to close, got: {written}"
        );
        assert!(
            written.ends_with("response-body"),
            "body must survive the rewrite intact, got: {written}"
        );
    }
}
