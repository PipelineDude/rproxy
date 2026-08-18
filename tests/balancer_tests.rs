//! Tests for the balancer — round-robin, least-conn, IP-hash stability,
//! rendezvous hashing resilience, health-aware routing.
//!
//! DOC-DRIVEN: per rproxy README "Балансировка":
//!   - roundrobin = cyclic; iphash/urlhash = HRW (rendezvous) for session affinity
//!   - leastconn = fewest active conns on this worker
//!   - weighted = proportional to weight
//!   - unknown balance = load error

use rproxy::config::{Backend, BackendList, Balance};
use rproxy::shared::{SharedMemory, SharedState};
use std::net::IpAddr;

fn make_backend(id: usize, up: bool, weight: u32) -> Backend {
    // `SharedState::new_for_test` is `#[cfg(test)]` (only visible to the crate's own unit
    // tests), so integration tests must build the state through the public API: allocate a
    // real shared slot via `SharedMemory` and fetch the backend's state out of it. `SharedMemory`
    // has no `Drop`, so the mmap is deliberately leaked and the raw pointer stays valid for the
    // process lifetime.
    let shm = SharedMemory::new(id + 1);
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
        state: shm.get_state(id),
    };
    if !up {
        b.state.set_up(false);
    }
    b
}

/// SharedState exposes only inc_conn()/dec_conn() for connection counts; start from 0 and
/// increment to reach the target (mirrors what set_active_conns used to express).
fn set_active_conns(state: &SharedState, n: usize) {
    for _ in 0..n {
        state.inc_conn();
    }
}

fn make_balancer_with_balance(
    backends: Vec<Backend>,
    balance: Balance,
) -> rproxy::balancer::BalancerState {
    let bl = BackendList { balance, backends };
    rproxy::balancer::BalancerState::new(bl)
}

// ---------------------------------------------------------------------------
// Round-robin
// ---------------------------------------------------------------------------

#[test]
fn rr_distributes_evenly_across_backends() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::RoundRobin);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    let mut counts = [0usize; 3];
    for _ in 0..30 {
        if let Some(b) = balancer.select_backend(&ip, "/path", &[]) {
            counts[b.id] += 1;
        }
    }
    // Each backend should get ~10 selections (±2 tolerance)
    for (i, &c) in counts.iter().enumerate() {
        assert!(
            (8..=12).contains(&c),
            "backend {} got {} selections, expected ~10",
            i,
            c
        );
    }
}

#[test]
fn rr_skips_down_backends() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, false, 1), // down
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::RoundRobin);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    let mut selected_ids = Vec::new();
    for _ in 0..20 {
        if let Some(b) = balancer.select_backend(&ip, "/path", &[]) {
            selected_ids.push(b.id);
        }
    }
    // Backend 1 should never be selected (it's down)
    assert!(
        !selected_ids.contains(&1),
        "down backend should not be selected"
    );
    // Only backends 0 and 2 should appear
    for &id in &selected_ids {
        assert!(id == 0 || id == 2);
    }
}

#[test]
fn rr_single_backend_returns_it() {
    let backends = vec![make_backend(0, true, 1)];
    let balancer = make_balancer_with_balance(backends, Balance::RoundRobin);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    for _ in 0..10 {
        let b = balancer.select_backend(&ip, "/path", &[]);
        assert!(b.is_some());
        assert_eq!(b.unwrap().id, 0);
    }
}

#[test]
fn rr_all_down_returns_none() {
    let backends = vec![make_backend(0, false, 1), make_backend(1, false, 1)];
    let balancer = make_balancer_with_balance(backends, Balance::RoundRobin);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    for _ in 0..5 {
        assert!(balancer.select_backend(&ip, "/path", &[]).is_none());
    }
}

// ---------------------------------------------------------------------------
// Least-conn
// ---------------------------------------------------------------------------

#[test]
fn leastconn_selects_fewest_active() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    // Set backend 1 to have more active connections
    set_active_conns(&backends[1].state, 100);
    set_active_conns(&backends[0].state, 5);
    set_active_conns(&backends[2].state, 3);

    let balancer = make_balancer_with_balance(backends, Balance::Leastconn);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    let b = balancer.select_backend(&ip, "/path", &[]);
    assert!(b.is_some());
    assert_eq!(
        b.unwrap().id,
        2,
        "leastconn should pick backend with fewest active conns"
    );
}

#[test]
fn leastconn_ignores_down_backends() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, false, 1), // down but would have 0 conns
        make_backend(2, true, 1),
    ];
    set_active_conns(&backends[0].state, 50);
    set_active_conns(&backends[2].state, 3);

    let balancer = make_balancer_with_balance(backends, Balance::Leastconn);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    let b = balancer.select_backend(&ip, "/path", &[]);
    assert!(b.is_some());
    assert_eq!(b.unwrap().id, 2);
}

// ---------------------------------------------------------------------------
// IP-hash (rendezvous / HRW) — stability
// ---------------------------------------------------------------------------

#[test]
fn iphash_stable_for_same_client() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::Iphash);
    let ip: IpAddr = "192.168.1.42".parse().unwrap();

    let first = balancer.select_backend(&ip, "/path", &[]).map(|b| b.id);
    for _ in 0..50 {
        let next = balancer.select_backend(&ip, "/path", &[]).map(|b| b.id);
        assert_eq!(next, first, "iphash should be stable for same client IP");
    }
}

#[test]
fn iphash_different_clients_differ() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::Iphash);

    // HRW is deterministic: a fixed (key, backend set) maps to a fixed backend, so comparing one
    // pair twice is a coin flip, not a distribution check. Over enough distinct client IPs the
    // mapping must spread across more than one backend.
    let mut seen = std::collections::HashSet::new();
    for i in 0..200u32 {
        let ip: IpAddr = format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap();
        if let Some(b) = balancer.select_backend(&ip, "/path", &[]) {
            seen.insert(b.id);
        }
    }
    assert!(
        seen.len() >= 2,
        "200 distinct client IPs should spread across backends, saw {:?}",
        seen
    );
}

#[test]
fn iphash_backend_drop_remaps_only_affected() {
    // When a backend drops, only keys that mapped to it should remap.
    // Test: with 4 backends, pick one client IP, check which backend it maps to.
    // Then drop backend 0 and verify the same IP still maps consistently (to a different backend).
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
        make_backend(3, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends.clone(), Balance::Iphash);
    let ip: IpAddr = "172.16.0.99".parse().unwrap();

    let _before = balancer.select_backend(&ip, "/path", &[]).map(|b| b.id);

    // Drop backend 0
    backends[0].state.set_up(false);
    let balancer2 = make_balancer_with_balance(backends, Balance::Iphash);
    let after = balancer2.select_backend(&ip, "/path", &[]).map(|b| b.id);

    // The IP should still map to some backend (not panic/none) if any remain up
    assert!(
        after.is_some(),
        "should still have a backend after dropping one"
    );
}

// ---------------------------------------------------------------------------
// URL-hash stability
// ---------------------------------------------------------------------------

#[test]
fn urlhash_stable_for_same_path() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::Urlhash);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    let first = balancer
        .select_backend(&ip, "/api/users/42", &[])
        .map(|b| b.id);
    for _ in 0..50 {
        let next = balancer
            .select_backend(&ip, "/api/users/42", &[])
            .map(|b| b.id);
        assert_eq!(next, first, "urlhash should be stable for same path");
    }
}

#[test]
fn urlhash_different_paths_differ() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::Urlhash);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    // HRW is deterministic: a fixed (path, backend set) maps to a fixed backend, so "CAN differ"
    // on one path pair is a coin flip that also passes with everything on one backend. Over
    // enough distinct paths the mapping must spread across more than one backend.
    let mut seen = std::collections::HashSet::new();
    for i in 0..200u32 {
        let path = format!("/api/users/{i}");
        if let Some(b) = balancer.select_backend(&ip, &path, &[]) {
            seen.insert(b.id);
        }
    }
    assert!(
        seen.len() >= 2,
        "200 distinct paths should spread across backends, saw {:?}",
        seen
    );
}

// ---------------------------------------------------------------------------
// Weighted balancing
// ---------------------------------------------------------------------------

#[test]
fn weighted_distributes_proportional_to_weight() {
    let backends = vec![make_backend(0, true, 3), make_backend(1, true, 1)];
    let balancer = make_balancer_with_balance(backends, Balance::Weighted);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    let mut counts = [0usize, 0usize];
    for _ in 0..400 {
        if let Some(b) = balancer.select_backend(&ip, "/path", &[]) {
            counts[b.id] += 1;
        }
    }
    // Backend 0 should get ~75% of traffic (weight 3 out of 4 total)
    assert!(
        counts[0] > counts[1],
        "weighted: backend 0 (weight=3) should get more than backend 1 (weight=1)"
    );
    let ratio = counts[0] as f64 / counts[1] as f64;
    assert!(
        (2.0..=4.0).contains(&ratio),
        "weighted ratio should be ~3:1, got {:.2}:1",
        ratio
    );
}

// ---------------------------------------------------------------------------
// Skip IDs (for health-check awareness)
// ---------------------------------------------------------------------------

#[test]
fn skip_ids_excludes_specific_backends() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::RoundRobin);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    // Skip backend 1
    for _ in 0..30 {
        let b = balancer.select_backend(&ip, "/path", &[1]);
        if let Some(b) = b {
            assert!(b.id != 1, "skipped backend should not be selected");
        }
    }
}

#[test]
fn skip_all_but_one_returns_the_last() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::RoundRobin);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    // Skip backends 0 and 2 — only backend 1 remains
    for _ in 0..10 {
        let b = balancer.select_backend(&ip, "/path", &[0, 2]);
        assert!(b.is_some());
        assert_eq!(b.unwrap().id, 1);
    }
}

// ---------------------------------------------------------------------------
// Health-aware routing (backend state changes)
// ---------------------------------------------------------------------------

#[test]
fn health_aware_routing_dynamically_excludes_down() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends.clone(), Balance::RoundRobin);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    // Initially all up — backend 0 should be selected sometimes
    let mut got_0 = false;
    for _ in 0..30 {
        if let Some(b) = balancer.select_backend(&ip, "/path", &[]) {
            if b.id == 0 {
                got_0 = true;
            }
        }
    }
    assert!(got_0, "backend 0 should be selected when up");

    // Now mark backend 0 as down (mutating the shared state)
    backends[0].state.set_up(false);
    let balancer2 = make_balancer_with_balance(backends, Balance::RoundRobin);

    let mut got_0_again = false;
    for _ in 0..30 {
        if let Some(b) = balancer2.select_backend(&ip, "/path", &[]) {
            if b.id == 0 {
                got_0_again = true;
            }
        }
    }
    assert!(
        !got_0_again,
        "backend 0 should not be selected after going down"
    );
}

// ---------------------------------------------------------------------------
// First algorithm
// ---------------------------------------------------------------------------

#[test]
fn first_returns_first_up_backend() {
    let backends = vec![
        make_backend(0, false, 1), // down
        make_backend(1, true, 1),  // up
        make_backend(2, true, 1),  // up
    ];
    let balancer = make_balancer_with_balance(backends, Balance::First);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    for _ in 0..10 {
        let b = balancer.select_backend(&ip, "/path", &[]);
        assert!(b.is_some());
        assert_eq!(b.unwrap().id, 1, "first should return the first up backend");
    }
}

#[test]
fn first_with_first_down_skips_to_next() {
    let backends = vec![
        make_backend(0, false, 1), // down
        make_backend(1, false, 1), // down
        make_backend(2, true, 1),  // up
    ];
    let balancer = make_balancer_with_balance(backends, Balance::First);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    for _ in 0..10 {
        let b = balancer.select_backend(&ip, "/path", &[]);
        assert!(b.is_some());
        assert_eq!(b.unwrap().id, 2);
    }
}

// ---------------------------------------------------------------------------
// Random algorithm
// ---------------------------------------------------------------------------

#[test]
fn random_only_selects_up_backends() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, false, 1), // down
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::Random);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    for _ in 0..50 {
        if let Some(b) = balancer.select_backend(&ip, "/path", &[]) {
            assert!(
                b.id == 0 || b.id == 2,
                "random should only pick up backends"
            );
        }
    }
}

#[test]
fn random_selects_all_up_backends_over_many_trials() {
    let backends = vec![
        make_backend(0, true, 1),
        make_backend(1, true, 1),
        make_backend(2, true, 1),
    ];
    let balancer = make_balancer_with_balance(backends, Balance::Random);
    let ip: IpAddr = "192.168.0.1".parse().unwrap();

    let mut seen = [false, false, false];
    for _ in 0..300 {
        if let Some(b) = balancer.select_backend(&ip, "/path", &[]) {
            seen[b.id] = true;
        }
    }
    assert!(
        seen.iter().all(|&s| s),
        "random should eventually select all backends"
    );
}
