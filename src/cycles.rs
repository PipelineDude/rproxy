//! Per-call CPU-cycle profiling for selected hot-path functions (only linked
//! under `--features cycle_profile`). Design + what was tried and reverted:
//! `docs/DESIGN-NOTES.md#1`.

/// Wraps `$body` (a plain, non-yielding expression — see the module doc for why an `async fn`
/// call that `.await`s internally isn't meaningful to wrap this way) and records its cost into
/// `$site`, a `&'static cycles::Site`. `$body` may itself contain other `profile_cycles!` calls
/// (see the module doc on self vs. total). A no-op passthrough (`$body` unchanged, nothing
/// measured, `$site` never evaluated) when the `cycle_profile` feature is off, so call sites read
/// the same either way and cost nothing extra in the default build.
#[cfg(feature = "cycle_profile")]
#[macro_export]
macro_rules! profile_cycles {
    ($site:expr, $body:expr) => {{
        $crate::cycles::push_frame();
        let (__t0, __c0) = $crate::cycles::read_tscp();
        let __r = $body;
        let (__t1, __c1) = $crate::cycles::read_tscp();
        let __child = $crate::cycles::pop_frame();
        let __total = __t1.saturating_sub(__t0);
        if __c0 != __c1 {
            $site.record_dropped_migration();
        } else {
            $site.record(__total, __child);
        }
        // Propagated even on a dropped/migrated sample: attributing 0 would silently inflate the
        // enclosing call's *self* time by this call's entire (real, if noisy) cost instead.
        $crate::cycles::add_to_parent(__total);
        __r
    }};
}

#[cfg(not(feature = "cycle_profile"))]
#[macro_export]
macro_rules! profile_cycles {
    ($site:expr, $body:expr) => {
        $body
    };
}

// `report`/`calibrate`/`tsc_hz`/the `SITE_*` statics are consumed only by `cycle_profile_report`
// in fast_proxy.rs's test module — real, but invisible to a plain `cargo build --features
// cycle_profile` (no `--tests`), which correctly has nothing else in `main()` calling them. Not a
// bug to fix by wiring a live caller (see the module doc: this is a deliberate, test-only tool).
#[cfg(feature = "cycle_profile")]
#[allow(dead_code)]
mod imp {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
    use std::sync::LazyLock;

    const NUM_BUCKETS: usize = 64;
    const RING_LEN: usize = 1024;

    thread_local! {
        // Self-time accounting stack: index 0 is the outermost currently-active `profile_cycles!`
        // frame (if any). Each entry accumulates the total ticks reported by nested profiled
        // calls made while that frame is active; the frame's owner subtracts this from its own
        // total to get self-time. See the module doc.
        static FRAME_STACK: RefCell<Vec<u64>> = RefCell::new(Vec::new());
    }

    pub fn push_frame() {
        FRAME_STACK.with(|s| s.borrow_mut().push(0));
    }

    pub fn pop_frame() -> u64 {
        FRAME_STACK.with(|s| s.borrow_mut().pop().unwrap_or(0))
    }

    pub fn add_to_parent(cycles: u64) {
        FRAME_STACK.with(|s| {
            if let Some(top) = s.borrow_mut().last_mut() {
                *top += cycles;
            }
        });
    }

    pub struct Site {
        name: &'static str,
        count: AtomicU64,
        sum_total: AtomicU64,
        self_sum: AtomicU64,
        min: AtomicU64,
        max: AtomicU64,
        dropped_migrated: AtomicU64,
        buckets: [AtomicU64; NUM_BUCKETS],
        ring: [AtomicU64; RING_LEN],
        ring_next: AtomicUsize,
    }

    impl Site {
        fn new(name: &'static str) -> Self {
            Site {
                name,
                count: AtomicU64::new(0),
                sum_total: AtomicU64::new(0),
                self_sum: AtomicU64::new(0),
                min: AtomicU64::new(u64::MAX),
                max: AtomicU64::new(0),
                dropped_migrated: AtomicU64::new(0),
                buckets: [0u64; NUM_BUCKETS].map(AtomicU64::new),
                ring: [0u64; RING_LEN].map(AtomicU64::new),
                ring_next: AtomicUsize::new(0),
            }
        }

        /// Records one call: `total` is this call's own measured span; `child` is what
        /// [`pop_frame`] returned for it (ticks already claimed by nested profiled calls). Not
        /// part of the public measuring API — use [`profile_cycles!`](crate::profile_cycles),
        /// which does the entry/exit core-id check and frame bookkeeping before calling this.
        #[doc(hidden)]
        pub fn record(&self, total: u64, child: u64) {
            self.count.fetch_add(1, Relaxed);
            self.sum_total.fetch_add(total, Relaxed);
            self.self_sum
                .fetch_add(total.saturating_sub(child), Relaxed);
            self.min.fetch_min(total, Relaxed);
            self.max.fetch_max(total, Relaxed);
            let bucket = (63 - total.max(1).leading_zeros()) as usize;
            self.buckets[bucket.min(NUM_BUCKETS - 1)].fetch_add(1, Relaxed);
            let idx = self.ring_next.fetch_add(1, Relaxed) % RING_LEN;
            self.ring[idx].store(total, Relaxed);
        }

        #[doc(hidden)]
        pub fn record_dropped_migration(&self) {
            self.dropped_migrated.fetch_add(1, Relaxed);
        }

        pub fn name(&self) -> &'static str {
            self.name
        }
        pub fn count(&self) -> u64 {
            self.count.load(Relaxed)
        }
        pub fn sum_total(&self) -> u64 {
            self.sum_total.load(Relaxed)
        }
        pub fn self_sum(&self) -> u64 {
            self.self_sum.load(Relaxed)
        }
        pub fn min(&self) -> u64 {
            self.min.load(Relaxed)
        }
        pub fn max(&self) -> u64 {
            self.max.load(Relaxed)
        }
        pub fn dropped_migrated(&self) -> u64 {
            self.dropped_migrated.load(Relaxed)
        }

        /// Percentile of the *total* (inclusive) distribution, as a `[lower, upper)` log2 bucket
        /// range rather than a single number: the histogram only knows which power-of-two bucket
        /// a value landed in, and a bucket floor shown as if exact can land below the true min
        /// (e.g. min=144 and the p50 sample both fall in bucket [128,256), floor 128) — a range
        /// says "approximate" honestly instead of misreading as "p50 < min".
        pub fn percentile_bucket(&self, p: f64) -> (u64, u64) {
            let total: u64 = self.buckets.iter().map(|b| b.load(Relaxed)).sum();
            if total == 0 {
                return (0, 0);
            }
            let target = ((total as f64) * p).ceil() as u64;
            let mut seen = 0u64;
            for (i, b) in self.buckets.iter().enumerate() {
                seen += b.load(Relaxed);
                if seen >= target {
                    let upper = if i + 1 < 64 {
                        1u64 << (i + 1)
                    } else {
                        u64::MAX
                    };
                    return (1u64 << i, upper);
                }
            }
            let top = NUM_BUCKETS - 1;
            let upper = if top + 1 < 64 {
                1u64 << (top + 1)
            } else {
                u64::MAX
            };
            (1u64 << top, upper)
        }

        pub fn recent_samples(&self) -> Vec<u64> {
            let count = self.count();
            let ring_count = count.min(RING_LEN as u64) as usize;
            let next = self.ring_next.load(Relaxed);
            let start = if next as u64 >= RING_LEN as u64 {
                next % RING_LEN
            } else {
                0
            };
            (0..ring_count)
                .map(|i| self.ring[(start + i) % RING_LEN].load(Relaxed))
                .collect()
        }

        fn print_report(&self, floor: u64) {
            let count = self.count();
            if count == 0 {
                eprintln!("  {:<28} (no calls recorded)", self.name);
                return;
            }
            let min = self.min();
            let max = self.max();
            let mean = self.sum_total() / count;
            let self_mean = self.self_sum() / count;
            let (p50_lo, p50_hi) = self.percentile_bucket(0.50);
            let (p99_lo, p99_hi) = self.percentile_bucket(0.99);
            let dropped = self.dropped_migrated();
            // Keyed off p50, not min: min is one single (possibly atypical, e.g. pre-warmup)
            // sample, but p50 is the number a reader actually treats as "this function's cost" —
            // comparing that to the floor is what makes the 3x threshold mean something.
            let floor_note = if p50_lo < floor.saturating_mul(3) {
                "  (p50 is within 3x the measurement floor — treat as noise, not a real cost)"
            } else {
                ""
            };
            let p50_s = format!("[{p50_lo},{p50_hi})");
            let p99_s = format!("[{p99_lo},{p99_hi})");
            eprintln!(
                "  {:<28} n={:<10} min={:<8} p50={:<12} mean={:<8} self_mean={:<8} p99={:<12} max={:<10}{floor_note}",
                self.name, count, min, p50_s, mean, self_mean, p99_s, max
            );
            if dropped > 0 {
                eprintln!("    ({dropped} sample(s) dropped: entry/exit core differed — thread migrated mid-call)");
            }
            let samples = self.recent_samples();
            eprint!("    last {} raw call(s), oldest first:", samples.len());
            for s in &samples {
                eprint!(" {s}");
            }
            eprintln!();
        }
    }

    macro_rules! define_sites {
        ($($ident:ident => $name:literal),+ $(,)?) => {
            $(
                pub static $ident: LazyLock<Site> = LazyLock::new(|| Site::new($name));
            )+

            pub fn all_sites() -> Vec<&'static LazyLock<Site>> {
                vec![$(&$ident),+]
            }
        };
    }

    define_sites! {
        SITE_BUILD_UPSTREAM_HEAD => "build_upstream_head",
        SITE_BUILD_RESPONSE_HEAD => "build_response_head",
        SITE_JWT_CLAIM_U64 => "jwt_claim_u64",
        SITE_BUF_PUT => "buf_put",
    }

    /// `RDTSCP`: waits for prior instructions to retire before reading (unlike plain `RDTSC`,
    /// which can be reordered earlier by the CPU), and additionally returns the core id via `aux`
    /// so a migration mid-measurement can be detected by the caller.
    #[inline]
    pub fn read_tscp() -> (u64, u32) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let mut aux: u32 = 0;
            let tsc = core::arch::x86_64::__rdtscp(&mut aux);
            (tsc, aux)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            (0, 0)
        }
    }

    /// Measures the cost of the measurement itself: `iters` back-to-back empty `read_tscp` pairs,
    /// returning `(min, mean)` ticks. Call before reading `Site` reports — a per-call number close
    /// to this floor is measurement noise, not a real cost (see [`Site::print_report`]).
    pub fn calibrate(iters: u64) -> (u64, u64) {
        let mut min = u64::MAX;
        let mut sum = 0u64;
        let mut n = 0u64;
        for _ in 0..iters {
            let (t0, c0) = read_tscp();
            let (t1, c1) = read_tscp();
            if c0 == c1 && t1 >= t0 {
                let d = t1 - t0;
                min = min.min(d);
                sum += d;
                n += 1;
            }
        }
        (min, if n > 0 { sum / n } else { 0 })
    }

    /// Empirically calibrates TSC ticks per second by bracketing a 200ms sleep with `read_tscp`.
    /// Not exact — sleep duration has scheduler jitter — but accurate enough (~0.1-1%) to convert
    /// a report's tick counts into human-readable ns/us for comparison against wall-clock
    /// benchmarks (e.g. bench/BENCHMARK_RESULTS.md).
    pub fn tsc_hz() -> u64 {
        let (t0, _) = read_tscp();
        let wall0 = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let elapsed = wall0.elapsed();
        let (t1, _) = read_tscp();
        let ticks = t1.saturating_sub(t0);
        ((ticks as f64) / elapsed.as_secs_f64()) as u64
    }

    /// Prints a human-readable report of every profiled site to stderr: the calibration floor,
    /// then one line per site (count/min/p50/mean/self_mean/p99/max) plus its most recent raw
    /// samples. Intended for a deliberate, manually-run performance test (`cargo test --release
    /// --features cycle_profile -- --ignored --nocapture`), not routine logging — this is why it
    /// goes to stderr via `eprintln!` rather than through `tracing`, and why nothing calls it
    /// unless a test explicitly does. For the request-rate-weighted optimization-priority report
    /// (cycles per request, sorted), see `cycle_profile_report` in fast_proxy.rs — this
    /// function is the raw per-site dump, not that analysis.
    pub fn report() {
        let (floor_min, floor_mean) = calibrate(10_000);
        eprintln!("=== cycle_profile report ===");
        eprintln!("measurement floor (empty read_tscp pair, 10000 iters): min={floor_min} mean={floor_mean} ticks");
        eprintln!(
            "(TSC ticks, not literal core cycles — invariant-TSC assumed; see src/cycles.rs)"
        );
        for site in all_sites() {
            site.print_report(floor_min);
        }
    }
}

#[cfg(feature = "cycle_profile")]
pub use imp::*;
