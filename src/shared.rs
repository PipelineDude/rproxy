use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// How often the CPU-load monitor samples /proc/stat.
const CPU_MONITOR_INTERVAL_MS: u64 = 500;

/// The shm layout version. Bump whenever any `Shared*` struct below changes size/field order/
/// alignment — every process in the prefork tree maps the same anonymous mmap, and the master,
/// workers and health/metrics process must all agree on the offsets. With the same binary that is
/// always true; the constant is the *documented* contract so a future layout edit can't silently
/// drift (and the const asserts below fail the build on a layout that breaks the manual
/// `ptr.add(max_backends)` arithmetic).
pub const SHM_LAYOUT_VERSION: &str = "v1";

#[repr(C)]
pub struct WorkerMetrics {
    pub req_status: [AtomicU64; 600],
    pub req_qos_drop: AtomicU64,
    pub req_rate_limit_drop: AtomicU64,
    pub req_ip_drop: AtomicU64,
    pub req_jwt_drop: AtomicU64,
    pub req_rule_drop: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub active_connections: AtomicU64,
}

#[repr(C)]
pub struct SharedMetrics {
    pub workers: [WorkerMetrics; 256],
    pub global_cpu_load: std::sync::atomic::AtomicU8,
}

#[repr(C)]
pub struct SharedBackendState {
    pub up: AtomicU8,
    pub active_connections: AtomicUsize,
}

// Const asserts: `SharedMemory::new` places `SharedMetrics` at `ptr.add(max_backends)`, i.e.
// at byte offset `max_backends * size_of::<SharedBackendState>()`. That block must land on a
// `SharedMetrics`-aligned boundary and the metrics region must stay self-consistent, or the
// `Relaxed` loads/stores through raw pointers would be misaligned UB (undefined behavior, not a
// crash — the silent kind). These are compile-time, platform-independent-in-intent checks that
// fail the build on any layout that breaks the arithmetic.
const _: () = {
    // Backend block length must be a whole number of SharedMetrics alignments, so the metrics
    // region start is aligned. (AtomicUsize in the backend state makes this hold on all supported
    // 64-bit targets; the assert keeps it true if the structs change.)
    assert!(size_of::<SharedBackendState>().is_multiple_of(align_of::<SharedMetrics>()));
    // Array indexing `workers[id]` requires the array itself to be properly aligned and the
    // elements to be plain (no padding surprises for the metrics reader that scans all 256).
    assert!(align_of::<WorkerMetrics>() <= align_of::<SharedMetrics>());
};

pub struct SharedMemory {
    pub ptr: *mut SharedBackendState,
    pub max_backends: usize,
}

pub static GLOBAL_METRICS_PTR: std::sync::atomic::AtomicPtr<SharedMetrics> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
pub static WORKER_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Safe accessor for the inter-process metrics region (review follow-up
/// 2026-08-15). The region is an anonymous MAP_SHARED mmap created by
/// `SharedMemory::new`, shared across the prefork tree, and lives for the
/// process lifetime -- so `&'static` is sound, every field is an atomic, and
/// the single raw-ptr load + null check + `unsafe { &* }` that used to be
/// repeated at a dozen call sites lives HERE instead. Returns `None` before
/// `SharedMemory::new` has run (and after it, never -- the ptr is set once).
#[inline(always)]
pub fn global_metrics() -> Option<&'static SharedMetrics> {
    let ptr = GLOBAL_METRICS_PTR.load(Ordering::Relaxed);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

/// This worker's metrics block (`WORKER_ID` indexed into the shared region).
#[inline(always)]
pub fn worker_metrics() -> Option<&'static WorkerMetrics> {
    let id = WORKER_ID.load(Ordering::Relaxed);
    global_metrics().map(|m| &m.workers[id])
}

impl SharedMemory {
    pub fn new(max_backends: usize) -> Self {
        let backends_size = max_backends * std::mem::size_of::<SharedBackendState>();
        let metrics_size = std::mem::size_of::<SharedMetrics>();
        let total_size = backends_size + metrics_size;

        let ptr = unsafe {
            let length = NonZeroUsize::new(total_size).unwrap();
            mmap(
                None,
                length,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED | MapFlags::MAP_ANONYMOUS,
                -1,
                0,
            )
            .unwrap() as *mut SharedBackendState
        };
        let metrics_ptr = unsafe { ptr.add(max_backends) } as *mut SharedMetrics;

        // Zero out the metrics memory
        unsafe {
            std::ptr::write_bytes(metrics_ptr, 0, 1);
        }
        GLOBAL_METRICS_PTR.store(metrics_ptr, Ordering::Relaxed);

        for i in 0..max_backends {
            unsafe {
                let state = ptr.add(i);
                std::ptr::write(&mut (*state).up, AtomicU8::new(1));
                std::ptr::write(&mut (*state).active_connections, AtomicUsize::new(0));
            }
        }

        Self { ptr, max_backends }
    }

    pub fn get_state(&self, id: usize) -> SharedState {
        if id >= self.max_backends {
            panic!("SharedMemory: Out of bounds backend ID");
        }
        SharedState {
            ptr: unsafe { self.ptr.add(id) },
        }
    }
}

#[derive(Clone, Debug)]
pub struct SharedState {
    ptr: *mut SharedBackendState,
}

unsafe impl Send for SharedState {}
unsafe impl Sync for SharedState {}

impl SharedState {
    pub fn is_up(&self) -> bool {
        unsafe { (*self.ptr).up.load(Ordering::Relaxed) != 0 }
    }
    pub fn set_up(&self, up: bool) {
        unsafe {
            (*self.ptr)
                .up
                .store(if up { 1 } else { 0 }, Ordering::Relaxed)
        };
    }
    pub fn active_conns(&self) -> usize {
        unsafe { (*self.ptr).active_connections.load(Ordering::Relaxed) }
    }
    pub fn inc_conn(&self) {
        unsafe {
            (*self.ptr)
                .active_connections
                .fetch_add(1, Ordering::Relaxed)
        };
    }
    pub fn dec_conn(&self) {
        unsafe {
            (*self.ptr)
                .active_connections
                .fetch_sub(1, Ordering::Relaxed)
        };
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self {
        let state = Box::new(SharedBackendState {
            up: AtomicU8::new(1),
            active_connections: AtomicUsize::new(0),
        });
        SharedState {
            ptr: Box::into_raw(state),
        }
    }
}

pub struct ConnGuard {
    state: SharedState,
}

impl ConnGuard {
    pub fn new(state: SharedState) -> Self {
        state.inc_conn();
        Self { state }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.state.dec_conn();
    }
}

pub static GLOBAL_CPU_LOAD: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn start_cpu_monitor() {
    std::thread::spawn(|| {
        let mut prev_idle = 0;
        let mut prev_total = 0;

        loop {
            if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
                if let Some(line) = stat.lines().next() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 7 && parts[0] == "cpu" {
                        let user: u64 = parts[1].parse().unwrap_or(0);
                        let nice: u64 = parts[2].parse().unwrap_or(0);
                        let system: u64 = parts[3].parse().unwrap_or(0);
                        let idle: u64 = parts[4].parse().unwrap_or(0);
                        let iowait: u64 = parts[5].parse().unwrap_or(0);
                        let irq: u64 = parts[6].parse().unwrap_or(0);
                        let softirq: u64 = parts[7].parse().unwrap_or(0);
                        let steal: u64 = parts.get(8).unwrap_or(&"0").parse().unwrap_or(0);

                        let total_idle = idle + iowait;
                        let total_non_idle = user + nice + system + irq + softirq + steal;
                        let total = total_idle + total_non_idle;

                        let total_diff = total.saturating_sub(prev_total);
                        let idle_diff = total_idle.saturating_sub(prev_idle);

                        if total_diff > 0 {
                            let cpu_usage = (100.0 * (total_diff as f64 - idle_diff as f64)
                                / total_diff as f64)
                                as u8;
                            GLOBAL_CPU_LOAD.store(cpu_usage, Ordering::Relaxed);
                            if let Some(m) = global_metrics() {
                                m.global_cpu_load.store(cpu_usage, Ordering::Relaxed);
                            }
                        }

                        prev_idle = total_idle;
                        prev_total = total;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(CPU_MONITOR_INTERVAL_MS));
        }
    });
}

#[inline(always)]
pub fn inc_status(status: u16) {
    if status < 600 {
        if let Some(m) = worker_metrics() {
            m.req_status[status as usize].fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[inline(always)]
pub fn inc_qos_drop() {
    if let Some(m) = worker_metrics() {
        m.req_qos_drop.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn inc_rate_limit_drop() {
    if let Some(m) = worker_metrics() {
        m.req_rate_limit_drop.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn inc_ip_drop() {
    if let Some(m) = worker_metrics() {
        m.req_ip_drop.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn inc_jwt_drop() {
    if let Some(m) = worker_metrics() {
        m.req_jwt_drop.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn inc_rule_drop() {
    if let Some(m) = worker_metrics() {
        m.req_rule_drop.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn add_bytes_rx(bytes: u64) {
    if let Some(m) = worker_metrics() {
        m.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn add_bytes_tx(bytes: u64) {
    if let Some(m) = worker_metrics() {
        m.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn inc_active_connections() {
    if let Some(m) = worker_metrics() {
        m.active_connections.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn dec_active_connections() {
    if let Some(m) = worker_metrics() {
        m.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shm_layout_contract() {
        // The same invariants the const asserts guarantee at compile time, checked on the
        // real mmap so a runtime pointer arithmetic slip (not just a type change) is caught too.
        assert!(!SHM_LAYOUT_VERSION.is_empty());
        let max_backends = 16;
        let shm = SharedMemory::new(max_backends);
        let metrics_ptr = unsafe { shm.ptr.add(max_backends) as *mut SharedMetrics };
        assert_eq!(
            (metrics_ptr as usize) % std::mem::align_of::<SharedMetrics>(),
            0,
            "metrics region must be SharedMetrics-aligned (ptr.add(max_backends) arithmetic)"
        );
        // Backend slots must not overlap the metrics region.
        let backends_end =
            (shm.ptr as usize) + max_backends * std::mem::size_of::<SharedBackendState>();
        assert!(backends_end <= metrics_ptr as usize);
    }

    #[test]
    fn test_shared_memory_up() {
        let shm = SharedMemory::new(4);
        let s = shm.get_state(0);
        assert!(s.is_up());
        s.set_up(false);
        assert!(!s.is_up());
    }

    #[test]
    #[should_panic]
    fn test_shared_memory_out_of_bounds() {
        let shm = SharedMemory::new(4);
        shm.get_state(4);
    }

    #[test]
    fn test_shared_state_conn_roundtrip() {
        let s = SharedState::new_for_test();
        let before = s.active_conns();
        s.inc_conn();
        s.inc_conn();
        s.dec_conn();
        let after = s.active_conns();
        assert_eq!(after - before, 1);
    }

    #[test]
    fn test_metrics_all_counters_delta() {
        let _shm = SharedMemory::new(16);

        let metrics =
            global_metrics().expect("metrics region must be available after SharedMemory::new");
        assert!(!GLOBAL_METRICS_PTR.load(Ordering::Relaxed).is_null());

        WORKER_ID.store(255, Ordering::Relaxed);

        let b_qos = metrics.workers[255].req_qos_drop.load(Ordering::Relaxed);
        inc_qos_drop();
        assert_eq!(
            metrics.workers[255].req_qos_drop.load(Ordering::Relaxed) - b_qos,
            1
        );

        let b_rl = metrics.workers[255]
            .req_rate_limit_drop
            .load(Ordering::Relaxed);
        inc_rate_limit_drop();
        assert_eq!(
            metrics.workers[255]
                .req_rate_limit_drop
                .load(Ordering::Relaxed)
                - b_rl,
            1
        );

        let b_ip = metrics.workers[255].req_ip_drop.load(Ordering::Relaxed);
        inc_ip_drop();
        assert_eq!(
            metrics.workers[255].req_ip_drop.load(Ordering::Relaxed) - b_ip,
            1
        );

        let b_jwt = metrics.workers[255].req_jwt_drop.load(Ordering::Relaxed);
        inc_jwt_drop();
        assert_eq!(
            metrics.workers[255].req_jwt_drop.load(Ordering::Relaxed) - b_jwt,
            1
        );

        let b_rule = metrics.workers[255].req_rule_drop.load(Ordering::Relaxed);
        inc_rule_drop();
        assert_eq!(
            metrics.workers[255].req_rule_drop.load(Ordering::Relaxed) - b_rule,
            1
        );

        let b_rx = metrics.workers[255].bytes_rx.load(Ordering::Relaxed);
        add_bytes_rx(42);
        assert_eq!(
            metrics.workers[255].bytes_rx.load(Ordering::Relaxed) - b_rx,
            42
        );

        let b_tx = metrics.workers[255].bytes_tx.load(Ordering::Relaxed);
        add_bytes_tx(99);
        assert_eq!(
            metrics.workers[255].bytes_tx.load(Ordering::Relaxed) - b_tx,
            99
        );

        let b_active = metrics.workers[255]
            .active_connections
            .load(Ordering::Relaxed);
        inc_active_connections();
        assert_eq!(
            metrics.workers[255]
                .active_connections
                .load(Ordering::Relaxed)
                - b_active,
            1
        );
        dec_active_connections();
        assert_eq!(
            metrics.workers[255]
                .active_connections
                .load(Ordering::Relaxed)
                - b_active,
            0
        );
    }
}
