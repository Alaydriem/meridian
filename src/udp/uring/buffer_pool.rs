/// Maximum packet size. Matches the full UDP payload capacity.
/// When UDP_GRO is enabled, the kernel can coalesce multiple segments,
/// so we need the full 65535-byte buffer.
const MAX_PACKET: usize = 65535;

/// A pool of pre-allocated buffers for io_uring operations.
///
/// Two logical pools are managed here:
/// - **Provided buffers** (for `RecvMsgMulti`): registered with the kernel via
///   `ProvideBuffers` so the kernel can select them automatically.
/// - **Send buffers**: application-managed pool for `SendMsg` SQEs.
pub struct BufferPool {
    /// The raw buffer storage. Each entry is `MAX_PACKET` bytes.
    storage: Vec<u8>,
    /// Number of buffers in the pool.
    count: usize,
    /// Tracks whether each buffer slot is free (true) or in-use (false).
    free: Vec<bool>,
    /// Number of currently free buffers.
    free_count: usize,
}

impl BufferPool {
    /// Create a new buffer pool with `count` buffers of `MAX_PACKET` bytes each.
    pub fn new(count: usize) -> Self {
        let storage = vec![0u8; count * MAX_PACKET];
        Self {
            storage,
            count,
            free: vec![true; count],
            free_count: count,
        }
    }

    /// Total number of buffers.
    pub fn capacity(&self) -> usize {
        self.count
    }

    /// Number of currently free buffers.
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// Size of each individual buffer.
    pub fn buffer_size(&self) -> usize {
        MAX_PACKET
    }

    /// Allocate a buffer, returning its index. Returns `None` if pool is exhausted.
    pub fn alloc(&mut self) -> Option<u16> {
        if self.free_count == 0 {
            return None;
        }
        for i in 0..self.count {
            if self.free[i] {
                self.free[i] = false;
                self.free_count -= 1;
                return Some(i as u16);
            }
        }
        None
    }

    /// Return a buffer to the pool.
    pub fn free(&mut self, id: u16) {
        let idx = id as usize;
        debug_assert!(idx < self.count, "buffer id out of range");
        debug_assert!(!self.free[idx], "double-free of buffer {id}");
        self.free[idx] = true;
        self.free_count += 1;
    }

    /// Get a shared reference to the buffer contents.
    pub fn get(&self, id: u16) -> &[u8] {
        let idx = id as usize;
        let start = idx * MAX_PACKET;
        &self.storage[start..start + MAX_PACKET]
    }

    /// Get a mutable reference to the buffer contents.
    pub fn get_mut(&mut self, id: u16) -> &mut [u8] {
        let idx = id as usize;
        let start = idx * MAX_PACKET;
        &mut self.storage[start..start + MAX_PACKET]
    }

    /// Get a raw pointer to a buffer (for passing to io_uring SQEs).
    pub fn ptr(&self, id: u16) -> *const u8 {
        let idx = id as usize;
        let start = idx * MAX_PACKET;
        unsafe { self.storage.as_ptr().add(start) }
    }

    /// Get a raw mutable pointer to a buffer (for passing to io_uring SQEs).
    pub fn ptr_mut(&mut self, id: u16) -> *mut u8 {
        let idx = id as usize;
        let start = idx * MAX_PACKET;
        unsafe { self.storage.as_mut_ptr().add(start) }
    }

    /// Copy data into a buffer. Returns the number of bytes copied.
    pub fn copy_into(&mut self, id: u16, data: &[u8]) -> usize {
        let buf = self.get_mut(id);
        let n = data.len().min(MAX_PACKET);
        buf[..n].copy_from_slice(&data[..n]);
        n
    }

    /// Check if the pool is under pressure (< 10% free).
    pub fn under_pressure(&self) -> bool {
        self.free_count * 10 < self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_free() {
        let mut pool = BufferPool::new(4);
        assert_eq!(pool.free_count(), 4);

        let a = pool.alloc().unwrap();
        assert_eq!(pool.free_count(), 3);

        let b = pool.alloc().unwrap();
        assert_ne!(a, b);
        assert_eq!(pool.free_count(), 2);

        pool.free(a);
        assert_eq!(pool.free_count(), 3);

        pool.free(b);
        assert_eq!(pool.free_count(), 4);
    }

    #[test]
    fn exhaust_pool() {
        let mut pool = BufferPool::new(2);
        let _a = pool.alloc().unwrap();
        let _b = pool.alloc().unwrap();
        assert!(pool.alloc().is_none());
    }

    #[test]
    fn copy_and_read() {
        let mut pool = BufferPool::new(1);
        let id = pool.alloc().unwrap();
        let data = b"hello world";
        let n = pool.copy_into(id, data);
        assert_eq!(n, data.len());
        assert_eq!(&pool.get(id)[..n], data);
    }

    #[test]
    fn under_pressure_threshold() {
        let mut pool = BufferPool::new(10);
        assert!(!pool.under_pressure());

        // Allocate 9 of 10 — only 1 free = 10%, at boundary
        for _ in 0..9 {
            pool.alloc().unwrap();
        }
        assert!(!pool.under_pressure()); // 1/10 = 10%, not strictly < 10%

        // Allocate the last one
        pool.alloc().unwrap();
        assert!(pool.under_pressure()); // 0/10 = 0%, definitely under pressure
    }
}
