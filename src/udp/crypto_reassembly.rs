use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;

/// Largest reassembled ClientHello we are willing to buffer, in bytes.
///
/// A real ClientHello is a few KB even with a large certificate chain and ECH.
/// The CRYPTO frame offset is attacker-controlled (a QUIC varint up to 2^62-1)
/// and Initial packets are encrypted with keys derived from the DCID using a
/// published salt, so any host can craft one. Without this bound the offset
/// drives `Vec::resize` directly.
const MAX_CLIENT_HELLO_SIZE: usize = 65_536;

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
    /// Coalesced half-open `[start, end)` ranges that have actually been written.
    /// `data` is zero-filled by `resize`, so length alone cannot tell us whether
    /// a byte is real or padding.
    filled: Vec<(usize, usize)>,
    created: Instant,
}

impl ReassemblyEntry {
    /// Record `[start, end)` as written, coalescing with any adjacent or
    /// overlapping ranges already present.
    fn mark_filled(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        self.filled.push((start, end));
        self.filled.sort_unstable();

        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.filled.len());
        for &(s, e) in &self.filled {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.filled = merged;
    }

    /// True when `[0, upto)` has been written with no holes.
    fn is_contiguous_to(&self, upto: usize) -> bool {
        matches!(self.filled.first(), Some(&(0, end)) if end >= upto)
    }
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
        // Reject before touching the map so a hostile offset cannot create an entry.
        let offset = usize::try_from(offset).ok()?;
        let end = offset.checked_add(fragment.len())?;
        if end > MAX_CLIENT_HELLO_SIZE {
            return None;
        }

        let mut entry = self
            .entries
            .entry(dcid.to_vec())
            .or_insert_with(|| ReassemblyEntry {
                data: Vec::new(),
                filled: Vec::new(),
                created: Instant::now(),
            });

        // Grow buffer if needed
        if entry.data.len() < end {
            entry.data.resize(end, 0);
        }

        // Copy fragment into buffer at the correct offset
        entry.data[offset..end].copy_from_slice(fragment);
        entry.mark_filled(offset, end);

        // The 4-byte handshake header must itself be present before its length
        // field can be trusted. `data` is zero-filled by `resize`, so a length
        // comparison alone would read padding as if it were real data.
        if !entry.is_contiguous_to(4) || entry.data[0] != 0x01 {
            return None;
        }

        let hello_len = ((entry.data[1] as usize) << 16)
            | ((entry.data[2] as usize) << 8)
            | (entry.data[3] as usize);
        let total_needed = 4 + hello_len;

        if total_needed <= entry.data.len() && entry.is_contiguous_to(total_needed) {
            return Some(entry.data[..total_needed].to_vec());
        }

        None
    }

    /// Remove an entry after successful SNI extraction.
    #[allow(dead_code)]
    pub fn remove(&self, dcid: &[u8]) {
        self.entries.remove(dcid);
    }

    /// Number of in-flight reassembly entries. Useful for tests and for
    /// exposing buffer pressure as a metric.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Clean up expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.entries
            .retain(|_, entry| now.duration_since(entry.created) < self.ttl);
    }

    /// Spawn a background task that periodically drops expired entries.
    ///
    /// Reclamation must not be coupled to successful SNI extraction: an attacker
    /// who never completes a ClientHello would otherwise accumulate entries
    /// under arbitrary DCIDs that nothing ever removes.
    pub fn spawn_cleanup(self: &Arc<Self>, shutdown: CancellationToken) {
        let buffer = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(buffer.ttl / 2);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => buffer.cleanup(),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf() -> CryptoReassemblyBuffer {
        CryptoReassemblyBuffer::new(Duration::from_secs(10))
    }

    /// A ClientHello-shaped payload: type 0x01, 3-byte length, then body.
    fn client_hello(body_len: usize) -> Vec<u8> {
        let mut v = vec![0x01];
        v.push(((body_len >> 16) & 0xff) as u8);
        v.push(((body_len >> 8) & 0xff) as u8);
        v.push((body_len & 0xff) as u8);
        v.extend(std::iter::repeat_n(0xAB, body_len));
        v
    }

    #[test]
    fn huge_offset_is_rejected_without_allocating() {
        let b = buf();
        // 2^40 would be a 1 TiB resize.
        assert!(b.insert(b"dcid", 1 << 40, &[0u8; 8]).is_none());
        assert_eq!(b.len(), 0, "no entry should be created for a bad offset");
    }

    #[test]
    fn overflowing_offset_is_rejected_without_panicking() {
        let b = buf();
        assert!(b.insert(b"dcid", u64::MAX - 4, &[0u8; 32]).is_none());
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn offset_exactly_at_cap_is_rejected() {
        let b = buf();
        assert!(
            b.insert(b"dcid", MAX_CLIENT_HELLO_SIZE as u64, &[0u8; 1])
                .is_none(),
            "an offset at the cap leaves no room for the fragment"
        );
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn single_complete_fragment_still_reassembles() {
        let b = buf();
        let hello = client_hello(16);
        let out = b.insert(b"dcid", 0, &hello).expect("should reassemble");
        assert_eq!(out, hello);
    }

    #[test]
    fn gapped_reassembly_is_not_accepted() {
        let b = buf();
        let hello = client_hello(64);
        // Write the 4-byte header plus 10 bytes, then jump forward leaving a hole.
        assert!(b.insert(b"dcid", 0, &hello[..14]).is_none());
        assert!(
            b.insert(b"dcid", 40, &hello[40..]).is_none(),
            "a buffer with a hole between 14 and 40 must not be treated as complete"
        );
    }

    #[test]
    fn out_of_order_fragments_reassemble_once_the_gap_closes() {
        let b = buf();
        let hello = client_hello(64);
        assert!(b.insert(b"dcid", 34, &hello[34..]).is_none());
        assert!(b.insert(b"dcid", 0, &hello[..20]).is_none());
        let out = b
            .insert(b"dcid", 20, &hello[20..34])
            .expect("closing the gap should complete the ClientHello");
        assert_eq!(out, hello);
    }

    #[test]
    fn duplicate_overlapping_fragments_are_harmless() {
        let b = buf();
        let hello = client_hello(32);
        assert!(b.insert(b"dcid", 0, &hello[..20]).is_none());
        assert!(b.insert(b"dcid", 0, &hello[..20]).is_none());
        let out = b.insert(b"dcid", 10, &hello[10..]).expect("should reassemble");
        assert_eq!(out, hello);
    }

    #[tokio::test]
    async fn entries_expire_with_no_successful_handshake() {
        let b = Arc::new(CryptoReassemblyBuffer::new(Duration::from_millis(50)));
        let shutdown = CancellationToken::new();
        b.spawn_cleanup(shutdown.clone());

        // Incomplete ClientHellos under attacker-chosen DCIDs. None will ever
        // complete, so nothing will ever call cleanup() on the success path.
        for i in 0u16..32 {
            assert!(
                b.insert(&i.to_be_bytes(), 0, &[0x01, 0x00, 0xff, 0xff])
                    .is_none()
            );
        }
        assert_eq!(b.len(), 32);

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            b.len(),
            0,
            "background reclamation must not depend on a successful handshake"
        );

        shutdown.cancel();
    }
}
