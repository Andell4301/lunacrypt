use super::{
    chunk_io::expected_file_len,
    metadata::{METADATA_COPY_COUNT, metadata_copy_chunks_are_supported},
};
use crate::errors::VaultError;

/// Smallest supported chunk size before encryption, in bytes (4 KiB).
pub const MIN_CHUNK_SIZE: u32 = 4096;
/// Largest supported chunk size before encryption, in bytes (16 MiB).
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
/// Recommended chunk size before encryption, in bytes (64 KiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
/// Maximum number of chunks reserved for file contents.
pub const MAX_DATA_CHUNKS: u64 = 100_000_000;
/// Maximum space for file contents before encryption, in bytes (256 TiB).
pub const MAX_DATA_BYTES: u64 = 1u64 << 48;
pub(super) const MAX_CONTAINER_FILE_BYTES: u64 = 1u64 << 49;

pub(super) fn validate_chunk_size(chunk_size: u32) -> Result<(), VaultError> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) || !chunk_size.is_power_of_two() {
        return Err(VaultError::FileError(format!(
            "chunk size must be a power of two between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
        )));
    }
    Ok(())
}

/// First file-data chunk after both catalog copies.
/// Chunk numbers start at zero after the headers.
pub(super) fn file_data_start_chunk(metadata_copy_chunks: u64) -> Result<u64, VaultError> {
    metadata_copy_chunks
        .checked_mul(METADATA_COPY_COUNT as u64)
        .ok_or_else(|| VaultError::corrupt("metadata geometry overflow"))
}

fn total_physical_chunks(
    metadata_copy_chunks: u64,
    data_chunk_count: u64,
) -> Result<u64, VaultError> {
    file_data_start_chunk(metadata_copy_chunks)?
        .checked_add(data_chunk_count)
        .ok_or_else(|| VaultError::corrupt("vault geometry overflow"))
}

/// Checks that the chunk size and counts are within the limits we support,
/// then calculates how long the vault file should be. When opening a vault,
/// the caller compares this with its actual length to catch missing or extra bytes.
pub(super) fn validate_geometry(
    chunk_size: u32,
    data_chunk_count: u64,
    metadata_copy_chunks: u64,
) -> Result<u64, VaultError> {
    validate_chunk_size(chunk_size).map_err(|_| VaultError::corrupt("invalid chunk size"))?;
    if data_chunk_count == 0 || data_chunk_count > MAX_DATA_CHUNKS {
        return Err(VaultError::corrupt("invalid data chunk count"));
    }
    let data_capacity = data_chunk_count
        .checked_mul(chunk_size as u64)
        .ok_or_else(|| VaultError::corrupt("data capacity overflow"))?;
    if data_capacity > MAX_DATA_BYTES {
        return Err(VaultError::corrupt(
            "data capacity exceeds the supported limit",
        ));
    }
    if !metadata_copy_chunks_are_supported(metadata_copy_chunks, chunk_size)? {
        return Err(VaultError::corrupt("invalid metadata arena size"));
    }
    let total = total_physical_chunks(metadata_copy_chunks, data_chunk_count)?;
    let expected = expected_file_len(total, chunk_size)?;
    if expected > MAX_CONTAINER_FILE_BYTES {
        return Err(VaultError::corrupt(
            "vault file exceeds the supported limit",
        ));
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::metadata::{MIN_METADATA_CAPACITY, choose_metadata_copy_chunks};

    #[test]
    fn accepts_the_maximum_data_capacity_and_rejects_one_chunk_more() {
        let chunk_size = MAX_CHUNK_SIZE;
        let metadata_chunks =
            choose_metadata_copy_chunks(1, chunk_size, Some(MIN_METADATA_CAPACITY)).unwrap();
        let max_data_chunks = MAX_DATA_BYTES / u64::from(chunk_size);
        assert!(validate_geometry(chunk_size, max_data_chunks, metadata_chunks).is_ok());
        assert!(validate_geometry(chunk_size, max_data_chunks + 1, metadata_chunks).is_err());
    }
}
