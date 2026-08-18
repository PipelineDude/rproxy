//! Minimal JWT claim parsing (extracted from fast_proxy.rs 2026-08-16). Only
//! the numeric claims rproxy's JWT filter needs (exp / nbf) are parsed —
//! deliberately no JSON dependency.

/// Find `"<key>": <digits>` in a decoded JWT payload and return the number.
/// Avoids pulling in a JSON dependency for the one numeric claim we need (exp).
/// Also used for `nbf` (both are `u64` epoch seconds).
pub(crate) fn jwt_claim_u64(payload: &[u8], key: &[u8]) -> Option<u64> {
    // Build the quoted key pattern (`"key"`) on the stack — no per-call heap allocation.
    let mut patbuf = [0u8; 32];
    let plen = key.len() + 2;
    if plen > patbuf.len() {
        return None;
    }
    patbuf[0] = b'"';
    patbuf[1..1 + key.len()].copy_from_slice(key);
    patbuf[1 + key.len()] = b'"';
    let pb = &patbuf[..plen];
    let mut i = 0;
    while i + pb.len() <= payload.len() {
        if &payload[i..i + pb.len()] == pb {
            let mut j = i + pb.len();
            while j < payload.len() && (payload[j] == b' ' || payload[j] == b':') {
                j += 1;
            }
            let start = j;
            while j < payload.len() && payload[j].is_ascii_digit() {
                j += 1;
            }
            if j > start {
                return std::str::from_utf8(&payload[start..j])
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok());
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_claims_with_spaces_and_colons() {
        let payload = br#"{"sub":"user","exp": 1700000000, "nbf":1700000000}"#;
        assert_eq!(jwt_claim_u64(payload, b"exp"), Some(1700000000));
        assert_eq!(jwt_claim_u64(payload, b"nbf"), Some(1700000000));
    }

    #[test]
    fn missing_or_bad_claim_is_none() {
        assert_eq!(jwt_claim_u64(br#"{"sub":"user"}"#, b"exp"), None);
        assert_eq!(jwt_claim_u64(br#"{"exp":"tomorrow"}"#, b"exp"), None);
        assert_eq!(jwt_claim_u64(b"", b"exp"), None);
    }
}
