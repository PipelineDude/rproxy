//! Per-worker buffer pool (extracted from fast_proxy.rs 2026-08-16,
//! I/O-layer split). Zero-alloc hot path reuses fixed 16 KiB buffers instead
//! of allocating per request.

/// Fixed size of a pooled request/response buffer.
pub const BUF_SIZE: usize = 16384;
/// Cap on pooled buffers kept per worker (16 KiB × 10k = 160 MiB worst case,
/// but only buffers actually returned to the pool are held).
const BUF_POOL_MAX: usize = 10_000;

thread_local! {
    static BUF_POOL: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Take a pooled 16 KiB buffer, or allocate one if the pool is empty.
#[inline(always)]
pub(crate) fn get_buf() -> Vec<u8> {
    BUF_POOL.with(|p| p.borrow_mut().pop().unwrap_or_else(|| vec![0u8; BUF_SIZE]))
}

/// Return a buffer to the pool if it is large enough to be reusable.
#[inline(always)]
pub(crate) fn put_buf(mut buf: Vec<u8>) {
    if buf.capacity() >= BUF_SIZE {
        buf.clear(); // just in case, though we overwrite
        buf.resize(BUF_SIZE, 0);
        BUF_POOL.with(|p| {
            let mut pool = p.borrow_mut();
            if pool.len() < BUF_POOL_MAX {
                pool.push(buf);
            }
        });
    }
}

/// RAII wrapper that borrows a pooled buffer for the duration of a request
/// and returns it on drop.
pub(crate) struct PooledBuf {
    buf: Option<Vec<u8>>,
}
impl PooledBuf {
    pub(crate) fn new() -> Self {
        Self {
            buf: Some(get_buf()),
        }
    }
    pub(crate) fn take(&mut self) -> Vec<u8> {
        self.buf.take().unwrap_or_else(get_buf)
    }
    pub(crate) fn put(&mut self, b: Vec<u8>) {
        self.buf = Some(b);
    }
}
impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(b) = self.buf.take() {
            put_buf(b);
        }
    }
}
