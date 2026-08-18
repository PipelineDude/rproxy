//! Pure header/path-matching helpers extracted from `fast_proxy.rs` (2026-08-15,
//! review follow-up -- that file was 4400+ lines of routing state + I/O + this
//! stateless utility layer). Everything here is a pure function or a small
//! value type: no shared mutable state, no monoio, no I/O. Keeping them in
//! their own module makes the hot-path code readable and these helpers
//! independently unit-testable.

use std::collections::HashMap;

/// One piece of a header value that the proxy re-emits: a static byte chunk,
/// or the placeholder `$client_ip` (rendered per-connection).
#[derive(Clone)]
pub enum HeaderFragment {
    Text(Vec<u8>),
    ClientIp,
}

/// Compile a `set_headers` map into fragments, expanding `$client_ip` at the
/// per-connection render site (see `render_frags`). No I/O, no allocations
/// beyond the fragments themselves.
pub fn compile_headers(hm_opt: &Option<HashMap<String, String>>) -> Vec<HeaderFragment> {
    let mut frags = Vec::new();
    if let Some(hm) = hm_opt {
        for (k, v) in hm {
            let mut current_text = format!("{}: ", k).into_bytes();
            let mut pos = 0;
            while let Some(idx) = v[pos..].find("$client_ip") {
                current_text.extend_from_slice(&v.as_bytes()[pos..pos + idx]);
                frags.push(HeaderFragment::Text(std::mem::take(&mut current_text)));
                frags.push(HeaderFragment::ClientIp);
                pos += idx + "$client_ip".len();
            }
            current_text.extend_from_slice(&v.as_bytes()[pos..]);
            current_text.extend_from_slice(b"\r\n");
            frags.push(HeaderFragment::Text(current_text));
        }
    }
    frags
}

/// Lowercased-insensitive names of headers that `set_headers` will inject,
/// so client-supplied copies can be stripped before proxying (anti-spoofing).
pub fn compile_header_names(hm_opt: &Option<HashMap<String, String>>) -> Vec<Vec<u8>> {
    hm_opt
        .as_ref()
        .map(|hm| hm.keys().map(|k| k.as_bytes().to_vec()).collect())
        .unwrap_or_default()
}

#[inline]
// cycle_profile: deliberately NOT instrumented here at all, in either its timed (profile_cycles!)
// or count-only (count_call!) form, despite being the hot inner loop of build_upstream_head/
// build_response_head (~15-30 calls per request). Both were tried and reverted:
//   - profile_cycles! (nested timed Site): build_upstream_head's measured min jumped ~144 -> ~3987
//     ticks (28x). The self-time subtraction correctly cancels the read_tscp pair's own floor, but
//     not the push_frame/pop_frame/record bookkeeping around each nested call, which sits outside
//     the child's own bracket and so is never subtracted.
//   - count_call! (bare atomic increment, no timing): still measurable — build_upstream_head's min
//     rose ~144 -> ~658 ticks (4.6x) from 46 LazyLock-gated fetch_adds per request. Even "just a
//     counter" isn't free at this call frequency.
// buf_put's own cost is measured in isolation instead (SITE_BUF_PUT, called directly, not nested —
// see cycle_profile_report in fast_proxy.rs's test module); its real call frequency is counted
// analytically from its call sites, not at runtime.
pub(crate) fn buf_put(x: &mut Vec<u8>, pos: &mut usize, bytes: &[u8]) {
    let end = *pos + bytes.len();
    if end > x.len() {
        x.resize(end.next_power_of_two(), 0);
    }
    x[*pos..end].copy_from_slice(bytes);
    *pos = end;
}

/// RFC 7230: `chunked` is valid only as the final transfer-coding. Using `contains("chunked")`
/// mis-classifies values like `chunkedX` and enables request smuggling. Check the last token.
#[inline]
pub(crate) fn te_is_chunked(value: &str) -> bool {
    value
        .rsplit(',')
        .next()
        .map(|t| t.trim().eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
}

/// Case-insensitive substring search over raw header bytes — avoids the per-request
/// `to_lowercase()`/`to_ascii_lowercase()` heap allocations that crept into the hot path.
#[inline]
pub(crate) fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Case-insensitive substring search returning the byte offset of the first match (sibling of
/// `contains_ci`). Lets the hot path locate a token without allocating a lowercased copy.
#[inline]
pub(crate) fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// True if `pat` has no regex metacharacters, so it can be matched as a plain string instead of
/// compiling and running the regex engine.
pub(crate) fn is_plain_literal(pat: &str) -> bool {
    !pat.is_empty()
        && !pat.bytes().any(|b| {
            matches!(
                b,
                b'.' | b'^'
                    | b'$'
                    | b'*'
                    | b'+'
                    | b'?'
                    | b'('
                    | b')'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
                    | b'|'
                    | b'\\'
            )
        })
}

/// Strip a trailing `:port` from a Host value so exact domain matching is port-insensitive
/// (`example.com:8443` still matches a domain `example.com`). IPv6 literals like `[::1]:80` keep
/// their bracketed address — the digits-only check rejects the `1]` of a bare `[::1]`.
#[inline]
pub(crate) fn host_without_port(h: &str) -> &str {
    match h.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => h,
    }
}

/// A compiled config `match` pattern. A pattern with no regex metacharacters is matched as a plain
/// string — `Exact` (`==`) for identity matches (domains, validate values) and `Prefix`
/// (`starts_with`) for hierarchical paths (routes) — with no regex engine and no per-request
/// `RegexSet` allocation. Patterns containing regex syntax use the engine (unanchored `is_match`).
pub enum Matcher {
    Exact(String),
    Prefix(String),
    Re(regex::Regex),
}

impl Matcher {
    /// Domains and validate values: a literal means exact equality.
    pub(crate) fn exact_or_re(re: &regex::Regex) -> Self {
        let pat = re.as_str();
        if is_plain_literal(pat) {
            Matcher::Exact(pat.to_string())
        } else {
            Matcher::Re(re.clone())
        }
    }
    /// Routes: a literal means a path prefix.
    pub(crate) fn prefix_or_re(re: &regex::Regex) -> Self {
        let pat = re.as_str();
        if is_plain_literal(pat) {
            Matcher::Prefix(pat.to_string())
        } else {
            Matcher::Re(re.clone())
        }
    }
    #[inline]
    pub(crate) fn is_match(&self, hay: &str) -> bool {
        match self {
            Matcher::Exact(s) => hay == s.as_str(),
            Matcher::Prefix(s) => hay.starts_with(s.as_str()),
            Matcher::Re(re) => re.is_match(hay),
        }
    }
    /// Original pattern length — the domain longest-match specificity tie-break (unchanged behavior).
    #[inline]
    pub(crate) fn pat_len(&self) -> usize {
        match self {
            Matcher::Exact(s) | Matcher::Prefix(s) => s.len(),
            Matcher::Re(re) => re.as_str().len(),
        }
    }
}

/// Evaluate `key=val|int|enum(a,b)` / `!key` / `key` conditions against a key lookup.
/// Shared by query and POST-body filtering.
pub(crate) fn eval_field_conditions<'a>(
    conds: &str,
    get: impl Fn(&str) -> Option<std::borrow::Cow<'a, str>>,
) -> bool {
    for c in conds.split_whitespace() {
        if let Some(k) = c.strip_prefix('!') {
            if get(k).is_some() {
                return false;
            }
        } else if let Some(eq) = c.find('=') {
            let (k, ev) = (&c[..eq], &c[eq + 1..]);
            let actual_cow = get(k);
            let actual = actual_cow.as_deref().unwrap_or("");
            let matched = ev.split('|').any(|e| {
                if e == "int" {
                    actual.parse::<i64>().is_ok()
                } else if let Some(en) = e.strip_prefix("enum(").and_then(|s| s.strip_suffix(')')) {
                    en.split(',').any(|x| x == actual)
                } else {
                    e == actual || (e == "str" && !actual.is_empty())
                }
            });
            if !matched {
                return false;
            }
        } else if get(c).is_none() {
            return false;
        }
    }
    true
}

/// True when a request-target still needs canonicalising for routing: it carries a percent-escape,
/// an empty segment (`//`) or a dot-segment candidate (`/.`). Scans the path part only — a `?`/`#`
/// ends it, so query values can never trigger a rewrite of the path.
///
/// The overwhelming majority of real targets answer `false` here and are forwarded byte-for-byte,
/// so the hot path pays exactly one branchy pass over ~30 bytes and never allocates.
#[inline]
pub(crate) fn needs_path_normalize(target: &[u8]) -> bool {
    for (i, &b) in target.iter().enumerate() {
        match b {
            b'?' | b'#' => return false,
            b'%' => return true,
            b'/' => match target.get(i + 1) {
                Some(b'/') | Some(b'.') => return true,
                _ => {}
            },
            _ => {}
        }
    }
    false
}

/// True when the **path** part of a request-target carries a separator this proxy will not
/// treat as one but an upstream might: a percent-encoded `%2F`/`%5C` (either case), or a raw `\`
/// (not a legal `pchar` per RFC 3986 §3.3, yet accepted by parsers and treated as a separator by
/// Windows/IIS-family backends).
///
/// The query is deliberately excluded — encoded slashes in query values are legitimate and
/// ubiquitous (`redirect_uri`, signed URLs), so rejecting those would break ordinary traffic
/// without closing anything.
///
/// Used only when `reject_encoded_slash` is enabled: path normalization leaves reserved escapes
/// encoded (decoding them would invent a segment boundary the client never sent), so an upstream
/// that decodes them *before* resolving dot-segments still disagrees with the path this proxy
/// evaluated.
pub(crate) fn path_has_separator_evasion(target: &[u8]) -> bool {
    for (i, &b) in target.iter().enumerate() {
        match b {
            b'?' | b'#' => return false,
            b'\\' => return true,
            b'%' => match (target.get(i + 1), target.get(i + 2)) {
                (Some(b'2'), Some(b'F')) | (Some(b'2'), Some(b'f')) => return true, // '/'
                (Some(b'5'), Some(b'C')) | (Some(b'5'), Some(b'c')) => return true, // '\'
                _ => {}
            },
            _ => {}
        }
    }
    false
}

#[inline(always)]
pub(crate) fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// RFC 3986 §2.3 unreserved set. Percent-escapes of these decode to an equivalent URI, so decoding
/// them is a lossless normalisation — and it is what closes `/%61dmin` / `/%2e%2e/` style evasions.
/// Reserved bytes (notably `%2F` and `%5C`) are deliberately left encoded: decoding them would
/// invent segment boundaries the client did not send.
#[inline(always)]
pub(crate) fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Canonicalise an origin-form request-target into `out`: decode unreserved percent-escapes
/// (RFC 3986 §6.2.2.2), then remove dot-segments and collapse empty ones (§6.2.2.3 / §5.2.4).
/// The query/fragment part is copied verbatim.
///
/// The result always starts with `/`, never shrinks below `/`, and preserves a trailing slash
/// (`/a/b/`, `/a/b/.` and `/a/b/..` keep it, matching §5.2.4). Malformed escapes (`%`, `%2`, `%zz`)
/// are copied literally — never an index past the end, never a panic.
pub(crate) fn normalize_path_into(target: &str, out: &mut Vec<u8>) {
    let bytes = target.as_bytes();
    let split = bytes
        .iter()
        .position(|&b| b == b'?' || b == b'#')
        .unwrap_or(bytes.len());
    let (path, tail) = (&bytes[..split], &bytes[split..]);

    out.clear();
    out.reserve(bytes.len());

    // Phase 1: decode unreserved escapes. Output is never longer than the input.
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'%' && i + 2 < path.len() {
            if let (Some(h), Some(l)) = (hex_val(path[i + 1]), hex_val(path[i + 2])) {
                let b = (h << 4) | l;
                if is_unreserved(b) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(path[i]);
        i += 1;
    }

    // Phase 2: walk segments and compact in place. `w` only ever trails `i`, so `copy_within`
    // moves each retained segment backwards over already-consumed bytes.
    let len = out.len();
    let mut w = 0usize;
    let mut i = 0usize;
    let mut trailing_slash = false;
    while i < len {
        // out[i] == b'/' here (the target is origin-form, and every iteration lands on a slash).
        let start = i + 1;
        let mut end = start;
        while end < len && out[end] != b'/' {
            end += 1;
        }
        let seg = &out[start..end];
        if seg.is_empty() || seg == b"." {
            trailing_slash = true; // "//" and "/./" collapse, a final one keeps the slash
        } else if seg == b".." {
            // Pop the previous segment; at the root `..` is dropped (cannot escape upwards).
            if w > 0 {
                w -= 1;
                while w > 0 && out[w] != b'/' {
                    w -= 1;
                }
            }
            trailing_slash = true;
        } else {
            out[w] = b'/';
            w += 1;
            let n = end - start;
            out.copy_within(start..end, w);
            w += n;
            trailing_slash = false;
        }
        i = end;
    }
    if trailing_slash && (w == 0 || out[w - 1] != b'/') {
        out[w] = b'/';
        w += 1;
    }
    out.truncate(w);
    if out.is_empty() {
        out.push(b'/');
    }
    out.extend_from_slice(tail);
}
