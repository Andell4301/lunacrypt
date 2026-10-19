use std::collections::BTreeMap;

use crate::errors::VaultError;

/// Tracks unused chunks in the vault's file-data area.
///
/// Each file needs its chunks next to each other. So, having enough free chunks
/// in total doesn't necessarily mean a file will fit. We keep the free ranges
/// sorted by their starting chunk and use the first one that's large enough.
///
/// Chunk numbers here start at zero within the file-data area. The catalog
/// copies have their own space and don't compete with files for these chunks.
#[derive(Debug)]
pub(super) struct ChunkAllocator {
    total_chunks: u64,
    free: BTreeMap<u64, u64>, // First free chunk -> number of consecutive free chunks.
}

impl ChunkAllocator {
    /// Starts with all chunks marked as free. When opening an existing vault,
    /// we then walk through the catalog and reserve the chunks its files use.
    pub(super) fn new(total_chunks: u64) -> Self {
        let mut free = BTreeMap::new();
        if total_chunks != 0 {
            free.insert(0, total_chunks);
        }
        Self { total_chunks, free }
    }

    /// Finds the start of the first free range large enough for `chunks`.
    /// Looking for space does not mark any chunks as used.
    pub(super) fn find_free_extent(&self, chunks: u64) -> Result<u64, VaultError> {
        if chunks == 0 {
            return Err(VaultError::FileError(
                "cannot allocate a zero-length extent".to_string(),
            ));
        }
        let Some((&start, _)) = self.free.iter().find(|(_, length)| **length >= chunks) else {
            return Err(VaultError::FileError(
                "vault does not have enough contiguous free space".to_string(),
            ));
        };
        Ok(start)
    }

    /// Marks `chunks` consecutive chunks starting at `start` as used.
    /// Does nothing if `chunks` is zero. Otherwise, the whole range must be free
    /// and inside the data area. This catches catalog entries that assign the
    /// same chunk to different files.
    pub(super) fn reserve(&mut self, start: u64, chunks: u64) -> Result<(), VaultError> {
        if chunks == 0 {
            return Ok(());
        }
        let end = self.checked_end(start, chunks)?;
        // Find the free range that starts closest to `start`, without going past it.
        // If ranges start at 0 and 10, `start = 12` selects the range at 10.
        // This is the only range that could contain our starting chunk.
        let Some((&free_start, &free_len)) = self.free.range(..=start).next_back() else {
            return Err(VaultError::corrupt("overlapping file extents"));
        };
        let free_end = free_start
            .checked_add(free_len)
            .ok_or_else(|| VaultError::corrupt("invalid free extent"))?;
        // All requested chunks must fit inside this one free range.
        if start < free_start || end > free_end {
            return Err(VaultError::corrupt("overlapping file extents"));
        }

        // The reservation can split a free range into two. For example, taking
        // chunks 5..10 from a free range of 0..20 leaves 0..5 and 10..20.
        // Remove the old range, then put back whichever pieces are left.
        self.free.remove(&free_start);
        if free_start < start {
            self.free.insert(free_start, start - free_start);
        }
        if end < free_end {
            self.free.insert(end, free_end - end);
        }
        Ok(())
    }

    /// Counts all unused file-data chunks across the free ranges.
    pub(super) fn free_chunks(&self) -> u64 {
        self.free.values().copied().sum()
    }

    /// Calculates the end of a range and checks that it stays inside the data area.
    /// The returned end is excluded from the range.
    fn checked_end(&self, start: u64, chunks: u64) -> Result<u64, VaultError> {
        let end = start
            .checked_add(chunks)
            .ok_or_else(|| VaultError::corrupt("chunk range overflow"))?;
        if start > self.total_chunks || end > self.total_chunks {
            return Err(VaultError::corrupt(
                "chunk range lies outside the data area",
            ));
        }
        Ok(end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_space_leaves_it_free_and_reserving_used_chunks_fails() {
        let mut allocator = ChunkAllocator::new(20);
        allocator.reserve(5, 5).unwrap();
        assert_eq!(allocator.find_free_extent(5).unwrap(), 0);
        assert_eq!(allocator.free_chunks(), 15);
        allocator.reserve(0, 5).unwrap();
        assert_eq!(allocator.find_free_extent(3).unwrap(), 10);
        allocator.reserve(10, 3).unwrap();
        assert!(allocator.reserve(6, 1).is_err());
        assert!(allocator.reserve(12, 2).is_err());
        assert_eq!(allocator.free_chunks(), 7);
        assert!(allocator.find_free_extent(8).is_err());
        assert!(allocator.find_free_extent(0).is_err());
    }

    #[test]
    fn a_file_must_fit_in_one_continuous_piece_of_free_space() {
        let mut allocator = ChunkAllocator::new(10);
        allocator.reserve(3, 4).unwrap();
        assert_eq!(allocator.free_chunks(), 6);
        assert!(allocator.find_free_extent(4).is_err());
        assert_eq!(allocator.find_free_extent(3).unwrap(), 0);
    }

    #[test]
    fn reserved_chunks_must_stay_within_the_data_area() {
        let mut allocator = ChunkAllocator::new(20);
        assert!(allocator.reserve(19, 2).is_err());
        assert!(allocator.reserve(u64::MAX, 2).is_err());
        assert_eq!(allocator.free_chunks(), 20);
    }
}
