use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Reassembles CRYPTO frame fragments from QUIC Initial packets.
///
/// QUIC ClientHellos can be too large for a single Initial packet and get
/// fragmented across multiple CRYPTO frames with non-zero offsets.
/// This buffer collects fragments by DCID until enough data is available
/// to extract the SNI.
pub struct CryptoReassemblyBuffer {
    entries: DashMap<Vec<u8>, ReassemblyEntry>,
    ttl: Duration,
}

struct ReassemblyEntry {
    data: Vec<u8>,
    created: Instant,
}

impl CryptoReassemblyBuffer {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Insert a CRYPTO fragment and return the reassembled data if complete enough
    /// to contain a ClientHello with SNI.
    pub fn insert(&self, dcid: &[u8], offset: u64, fragment: &[u8]) -> Option<Vec<u8>> {
        let offset = offset as usize;
        let end = offset + fragment.len();

        let mut entry = self
            .entries
            .entry(dcid.to_vec())
            .or_insert_with(|| ReassemblyEntry {
                data: Vec::new(),
                created: Instant::now(),
            });

        // Grow buffer if needed
        if entry.data.len() < end {
            entry.data.resize(end, 0);
        }

        // Copy fragment into buffer at the correct offset
        entry.data[offset..end].copy_from_slice(fragment);

        // Check if we have enough data: a ClientHello starts with 0x01,
        // then 3-byte length. If we have at least 4 bytes, we can read the length.
        if entry.data.len() >= 4 && entry.data[0] == 0x01 {
            let hello_len =
                ((entry.data[1] as usize) << 16) | ((entry.data[2] as usize) << 8) | (entry.data[3] as usize);
            let total_needed = 4 + hello_len;
            if entry.data.len() >= total_needed {
                return Some(entry.data[..total_needed].to_vec());
            }
        }

        None
    }

    /// Remove an entry after successful SNI extraction.
    #[allow(dead_code)]
    pub fn remove(&self, dcid: &[u8]) {
        self.entries.remove(dcid);
    }

    /// Clean up expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.entries
            .retain(|_, entry| now.duration_since(entry.created) < self.ttl);
    }
}
