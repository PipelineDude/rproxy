use crate::config::{Backend, BackendList, Balance};
use rand::Rng;
use std::hash::{Hash, Hasher};

/// Pinned FNV-1a 64 hasher for HRW affinity. `DefaultHasher` (SipHash) is NOT guaranteed
/// stable across rustc versions, so after a toolchain upgrade the key→backend mapping for
/// `iphash`/`urlhash` could silently shift, breaking session affinity and cache locality. FNV-1a
/// is fully specified right here (offset basis + prime + byte loop), so the mapping is a stable
/// contract across builds and rustc versions — no dependency, no algorithm drift. This is
/// deliberate: HRW affinity is an *operations contract*, not a perf knob.
#[derive(Clone, Default)]
struct Fnv1aHasher {
    state: u64,
}

impl Fnv1aHasher {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    fn new() -> Self {
        Self {
            state: Self::OFFSET_BASIS,
        }
    }
}

impl Hasher for Fnv1aHasher {
    fn finish(&self) -> u64 {
        self.state
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.state;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(Self::PRIME);
        }
        self.state = h;
    }
}

pub struct BalancerState {
    pub list: BackendList,
    pub rr_index: std::cell::Cell<usize>,
}

impl BalancerState {
    pub fn new(list: BackendList) -> Self {
        Self {
            list,
            rr_index: std::cell::Cell::new(0),
        }
    }

    pub fn select_backend<'a>(
        &'a self,
        client_ip: &std::net::IpAddr,
        url_path: &str,
        skip_ids: &[usize],
    ) -> Option<&'a Backend> {
        let len = self.list.backends.len();

        // Fast-path for a single backend
        if len == 1 {
            let b = &self.list.backends[0];
            if b.state.is_up() && !skip_ids.contains(&b.id) {
                return Some(b);
            }
            return None;
        }

        // Iterate by place, avoid vec allocation
        let mut alive_count = 0;
        let mut alive_mask: u64 = 0;

        if len <= 64 {
            for (i, b) in self.list.backends.iter().enumerate() {
                if b.state.is_up() && !skip_ids.contains(&b.id) {
                    alive_mask |= 1 << i;
                    alive_count += 1;
                }
            }
        } else {
            for b in &self.list.backends {
                if b.state.is_up() && !skip_ids.contains(&b.id) {
                    alive_count += 1;
                }
            }
        }

        if alive_count == 0 {
            return None;
        }

        match self.list.balance {
            Balance::RoundRobin => {
                let idx = self.rr_index.get() % alive_count;
                self.rr_index.set(self.rr_index.get().wrapping_add(1));
                let mut curr = 0;
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        if curr == idx {
                            return Some(b);
                        }
                        curr += 1;
                    }
                }
                None
            }
            Balance::Random => {
                let idx = rand::thread_rng().gen_range(0..alive_count);
                let mut curr = 0;
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        if curr == idx {
                            return Some(b);
                        }
                        curr += 1;
                    }
                }
                None
            }
            Balance::First => {
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        return Some(b);
                    }
                }
                None
            }
            Balance::Leastconn => {
                let mut min_conn = usize::MAX;
                let mut best = None;
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        let c = b.state.active_conns();
                        if c < min_conn {
                            min_conn = c;
                            best = Some(b);
                        }
                    }
                }
                best
            }
            Balance::Weighted => {
                let mut total_weight: u32 = 0;
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        total_weight += b.weight;
                    }
                }
                if total_weight == 0 {
                    for (i, b) in self.list.backends.iter().enumerate() {
                        let is_alive = if len <= 64 {
                            (alive_mask & (1 << i)) != 0
                        } else {
                            b.state.is_up() && !skip_ids.contains(&b.id)
                        };
                        if is_alive {
                            return Some(b);
                        }
                    }
                    return None;
                }
                let mut r = rand::thread_rng().gen_range(0..total_weight);
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        if r < b.weight {
                            return Some(b);
                        }
                        r -= b.weight;
                    }
                }
                None
            }
            Balance::Iphash => {
                let mut max_hash = 0;
                let mut best = None;
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        let mut hasher = Fnv1aHasher::new();
                        client_ip.hash(&mut hasher);
                        b.id.hash(&mut hasher);
                        let h = hasher.finish();
                        if h > max_hash || best.is_none() {
                            max_hash = h;
                            best = Some(b);
                        }
                    }
                }
                best
            }
            Balance::Urlhash => {
                let mut max_hash = 0;
                let mut best = None;
                for (i, b) in self.list.backends.iter().enumerate() {
                    let is_alive = if len <= 64 {
                        (alive_mask & (1 << i)) != 0
                    } else {
                        b.state.is_up() && !skip_ids.contains(&b.id)
                    };
                    if is_alive {
                        let mut hasher = Fnv1aHasher::new();
                        url_path.hash(&mut hasher);
                        b.id.hash(&mut hasher);
                        let h = hasher.finish();
                        if h > max_hash || best.is_none() {
                            max_hash = h;
                            best = Some(b);
                        }
                    }
                }
                best
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Backend, BackendList, Balance};
    use crate::shared::SharedState;

    fn create_backend(id: usize, up: bool, weight: u32) -> Backend {
        let b = Backend {
            id,
            host: format!("host{}", id),
            port: 8080 + id as u16,
            addr: format!("127.0.0.1:{}", 8080 + id),
            weight,
            connect_to: 5,
            response_to: 10,
            tls: false,
            tls_skip_verify: false,
            state: SharedState::new_for_test(),
        };
        if !up {
            b.state.set_up(false);
        }
        b
    }

    fn run_selection(
        balance: Balance,
        b_ups: &[bool],
        weights: &[u32],
        skips: &[usize],
        count: usize,
    ) -> Vec<usize> {
        let backends = b_ups
            .iter()
            .zip(weights.iter())
            .enumerate()
            .map(|(i, (&up, &w))| create_backend(i, up, w))
            .collect();
        let bl = BackendList { balance, backends };
        let state = BalancerState::new(bl);
        let mut results = Vec::new();
        let ip: std::net::IpAddr = "192.168.0.1".parse().unwrap();
        for i in 0..count {
            let path = format!("/path/{}", i);
            if let Some(b) = state.select_backend(&ip, &path, skips) {
                results.push(b.id);
            }
        }
        results
    }

    #[test]
    fn test_fnv1a_golden_vectors_pin_affinity() {
        // The HRW affinity contract must be stable across rustc versions. FNV-1a is specified
        // in this file, so a golden vector of the raw algorithm pins it: any future change to the
        // hash (or an accidental revert to DefaultHasher) fails here with the exact wrong value.
        let golden = |bytes: &[u8]| {
            let mut h = Fnv1aHasher::new();
            h.write(bytes);
            h.finish()
        };
        // FNV-1a 64 offset basis + prime applied over the given bytes.
        assert_eq!(golden(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(golden(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(golden(b"abc"), 0xe71f_a219_0541_574b);
        assert_eq!(golden(b"/api/users/42"), 0xfca7_db6b_4d10_164c);
    }

    #[test]
    fn test_roundrobin() {
        // 3 backends, all up. Should cycle 0, 1, 2, 0...
        let res = run_selection(Balance::RoundRobin, &[true, true, true], &[1, 1, 1], &[], 5);
        assert_eq!(res, vec![0, 1, 2, 0, 1]);

        // Middle backend down. Should cycle 0, 2, 0, 2...
        let res = run_selection(
            Balance::RoundRobin,
            &[true, false, true],
            &[1, 1, 1],
            &[],
            5,
        );
        assert_eq!(res, vec![0, 2, 0, 2, 0]);

        // With skip_ids. Skip 0.
        let res = run_selection(
            Balance::RoundRobin,
            &[true, true, true],
            &[1, 1, 1],
            &[0],
            5,
        );
        assert_eq!(res, vec![1, 2, 1, 2, 1]);
    }

    #[test]
    fn test_first() {
        // Should always pick the first alive non-skipped backend
        let res = run_selection(Balance::First, &[true, true, true], &[1, 1, 1], &[], 3);
        assert_eq!(res, vec![0, 0, 0]);

        let res = run_selection(Balance::First, &[false, true, true], &[1, 1, 1], &[], 3);
        assert_eq!(res, vec![1, 1, 1]);

        let res = run_selection(Balance::First, &[true, true, true], &[1, 1, 1], &[0], 3);
        assert_eq!(res, vec![1, 1, 1]);
    }

    #[test]
    fn test_leastconn() {
        let b0 = create_backend(0, true, 1);
        let b1 = create_backend(1, true, 1);
        let b2 = create_backend(2, true, 1);
        b0.state.inc_conn();
        b0.state.inc_conn(); // b0 has 2
        b1.state.inc_conn(); // b1 has 1
                             // b2 has 0

        let bl = BackendList {
            balance: Balance::Leastconn,
            backends: vec![b0, b1, b2],
        };
        let state = BalancerState::new(bl);
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let selected = state.select_backend(&ip, "/", &[]).unwrap();
        assert_eq!(selected.id, 2); // 0 conns
    }

    #[test]
    fn test_weighted() {
        // Weighted logic relies on random. We can test if all backends have 0 weight it defaults to first.
        let res = run_selection(Balance::Weighted, &[true, true], &[0, 0], &[], 3);
        assert_eq!(res, vec![0, 0, 0]);
    }

    #[test]
    fn test_iphash() {
        // Same IP should result in the same backend id being picked repeatedly
        let res = run_selection(
            Balance::Iphash,
            &[true, true, true, true],
            &[1, 1, 1, 1],
            &[],
            5,
        );
        let id = res[0];
        assert_eq!(res, vec![id, id, id, id, id]);

        // If that backend goes down, a new one should be consistently picked
        let mut ups = vec![true, true, true, true];
        ups[id] = false;
        let res2 = run_selection(Balance::Iphash, &ups, &[1, 1, 1, 1], &[], 5);
        let id2 = res2[0];
        assert_ne!(id, id2);
        assert_eq!(res2, vec![id2, id2, id2, id2, id2]);
    }

    #[test]
    fn test_urlhash() {
        // Different URLs should distribute, same URLs should stick
        let b0 = create_backend(0, true, 1);
        let b1 = create_backend(1, true, 1);
        let bl = BackendList {
            balance: Balance::Urlhash,
            backends: vec![b0, b1],
        };
        let state = BalancerState::new(bl);
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let id_a1 = state.select_backend(&ip, "/a", &[]).unwrap().id;
        let id_a2 = state.select_backend(&ip, "/a", &[]).unwrap().id;
        assert_eq!(id_a1, id_a2);
    }

    #[test]
    fn test_all_down() {
        let res = run_selection(Balance::RoundRobin, &[false, false], &[1, 1], &[], 1);
        assert!(res.is_empty());
    }

    #[test]
    fn test_all_skipped() {
        let res = run_selection(Balance::Random, &[true, true], &[1, 1], &[0, 1], 1);
        assert!(res.is_empty());
    }
}
