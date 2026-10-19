use std::fs::File;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    chunk_io::{metadata_chunk_aad, read_record, write_record},
    file_table::{Catalog, DecodedCatalog, MAX_ENCODED_CATALOG_BYTES},
};
use crate::{cipher::Cipher, errors::VaultError, header::CONTAINER_ID_LEN};

pub(super) const METADATA_COPY_COUNT: usize = 2;
/// Smallest catalog capacity callers may request when creating a vault.
pub const MIN_METADATA_CAPACITY: u64 = 1024 * 1024;
/// Minimum catalog capacity chosen when callers do not request a size.
pub const DEFAULT_METADATA_CAPACITY_FLOOR: u64 = 16 * 1024 * 1024;
/// Largest saved catalog size supported by this implementation, before encryption.
pub const MAX_METADATA_CAPACITY: u64 = MAX_ENCODED_CATALOG_BYTES as u64;

// Two metadata bytes per 1024 data bytes is exactly 2 MiB per GiB.
const METADATA_SCALE_DIVISOR: u64 = 512;

const MAGIC: [u8; 8] = *b"LUNAMET1";
const VERSION: u16 = 1;
const HEAD_LEN: usize = 72;

/// Once writing the head begins, the new catalog might become visible during
/// recovery. Keep track of this so a failed write can report whether the
/// update may already have taken effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SnapshotWritePhase {
    BeforeHead,
    PublishingHead,
}

#[derive(Debug)]
pub(super) struct SnapshotWriteError {
    pub error: VaultError,
    pub phase: SnapshotWritePhase,
}

#[cfg(test)]
std::thread_local! {
    static SNAPSHOT_FAILURE: std::cell::Cell<Option<(usize, SnapshotWritePhase)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) struct SnapshotFailureGuard;

#[cfg(test)]
impl Drop for SnapshotFailureGuard {
    fn drop(&mut self) {
        SNAPSHOT_FAILURE.with(|failure| failure.set(None));
    }
}

#[cfg(test)]
pub(super) fn inject_snapshot_failure(
    slot: usize,
    phase: SnapshotWritePhase,
) -> SnapshotFailureGuard {
    SNAPSHOT_FAILURE.with(|failure| failure.set(Some((slot, phase))));
    SnapshotFailureGuard
}

#[cfg(test)]
fn take_snapshot_failure(slot: usize, phase: SnapshotWritePhase) -> Option<SnapshotWriteError> {
    SNAPSHOT_FAILURE.with(|failure| {
        if failure.get() != Some((slot, phase)) {
            return None;
        }
        failure.set(None);
        Some(SnapshotWriteError {
            error: VaultError::FileError("injected metadata snapshot failure".to_string()),
            phase,
        })
    })
}

pub(super) struct PreparedMetadata {
    bytes: Zeroizing<Vec<u8>>,
    digest: [u8; 32],
    chunk_count: u64,
}

pub(super) struct MetadataCandidate {
    pub slot: usize,
    pub generation: u64,
    pub digest: [u8; 32],
    bytes: Zeroizing<Vec<u8>>,
}

impl MetadataCandidate {
    /// Supplies copy details for recovery tests, without actual catalog bytes.
    #[cfg(test)]
    pub(super) fn for_selection_test(slot: usize, generation: u64, digest: [u8; 32]) -> Self {
        Self {
            slot,
            generation,
            digest,
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    /// Rebuilds the catalog from the authenticated copy chosen during recovery.
    ///
    /// We only need the saved bytes until the catalog has been rebuilt. Taking
    /// ownership here releases them before repair needs to make another copy.
    pub(super) fn decode(
        self,
        data_chunk_count: u64,
        chunk_size: u32,
    ) -> Result<DecodedCatalog, VaultError> {
        decode_catalog(self.bytes.as_slice(), data_chunk_count, chunk_size)
    }
}

/// Result of reading one reserved catalog copy.
///
/// The first chunk, or head, describes the whole catalog copy. It can pass
/// authentication even if the rest of the copy is damaged. We need to keep
/// that distinction: if the checked head shows a newer update, choosing an
/// older catalog would silently hide it.
pub(super) enum MetadataCopyState {
    /// The first chunk could not be read or failed authentication.
    Unreadable(VaultError),
    /// The first chunk passes authentication, but the catalog copy is invalid.
    /// Trust its update number (generation) only after checking all head fields,
    /// declared sizes, and zero padding. Only then can its saved hash (digest)
    /// be used to compare the two copies.
    AuthenticatedInvalid {
        generation: Option<u64>,
        digest: [u8; 32],
        error: VaultError,
    },
    /// All chunks pass authentication, padding is zero, and the saved hash
    /// matches the catalog bytes. Rebuild the catalog only after recovery
    /// chooses a copy, so both copies do not expand into catalogs in memory.
    Authenticated(MetadataCandidate),
}

#[cfg(test)]
std::thread_local! {
    static CATALOG_DECODE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn decode_catalog(
    bytes: &[u8],
    data_chunk_count: u64,
    chunk_size: u32,
) -> Result<DecodedCatalog, VaultError> {
    #[cfg(test)]
    CATALOG_DECODE_COUNT.with(|count| count.set(count.get() + 1));
    Catalog::decode(bytes, data_chunk_count, chunk_size)
}

#[cfg(test)]
pub(super) fn reset_catalog_decode_count() {
    CATALOG_DECODE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn catalog_decode_count() -> usize {
    CATALOG_DECODE_COUNT.with(std::cell::Cell::get)
}

/// Returns the default usable catalog capacity for a requested data capacity.
///
/// Reserves roughly 2 MiB per GiB of data, with a minimum of 16 MiB and a
/// maximum set by the supported catalog size. At 128 saved bytes per entry,
/// this allows about 16,000 entries per GiB of data.
/// The result is a capacity in bytes for each catalog copy;
/// creation rounds the reservation up to whole chunks. This
/// function does not validate the requested data capacity.
pub fn recommended_metadata_capacity(requested_data_bytes: u64) -> u64 {
    requested_data_bytes
        .div_ceil(METADATA_SCALE_DIVISOR)
        .clamp(DEFAULT_METADATA_CAPACITY_FLOOR, MAX_METADATA_CAPACITY)
}

pub(super) fn choose_metadata_copy_chunks(
    requested_data_bytes: u64,
    chunk_size: u32,
    requested_metadata_capacity: Option<u64>,
) -> Result<u64, VaultError> {
    let target = requested_metadata_capacity
        .unwrap_or_else(|| recommended_metadata_capacity(requested_data_bytes));
    if !(MIN_METADATA_CAPACITY..=MAX_METADATA_CAPACITY).contains(&target) {
        return Err(VaultError::FileError(format!(
            "metadata capacity must be between {MIN_METADATA_CAPACITY} and {MAX_METADATA_CAPACITY} bytes"
        )));
    }
    let required = target
        .checked_add(HEAD_LEN as u64)
        .ok_or_else(|| VaultError::FileError("metadata sizing overflow".to_string()))?;
    Ok(required.div_ceil(chunk_size as u64).max(1))
}

pub(super) fn metadata_capacity(copy_chunks: u64, chunk_size: u32) -> Result<u64, VaultError> {
    if copy_chunks == 0 || chunk_size as usize <= HEAD_LEN {
        return Err(VaultError::corrupt("invalid metadata arena geometry"));
    }
    copy_chunks
        .checked_mul(chunk_size as u64)
        .and_then(|bytes| bytes.checked_sub(HEAD_LEN as u64))
        .map(|capacity| capacity.min(MAX_METADATA_CAPACITY))
        .ok_or_else(|| VaultError::corrupt("metadata capacity overflow"))
}

pub(super) fn metadata_copy_chunks_are_supported(
    copy_chunks: u64,
    chunk_size: u32,
) -> Result<bool, VaultError> {
    if copy_chunks == 0 || chunk_size as usize <= HEAD_LEN {
        return Ok(false);
    }
    let minimum_chunks = MIN_METADATA_CAPACITY
        .checked_add(HEAD_LEN as u64)
        .ok_or_else(|| VaultError::corrupt("metadata sizing overflow"))?
        .div_ceil(chunk_size as u64);
    let maximum_chunks = MAX_METADATA_CAPACITY
        .checked_add(HEAD_LEN as u64)
        .ok_or_else(|| VaultError::corrupt("metadata sizing overflow"))?
        .div_ceil(chunk_size as u64);
    Ok((minimum_chunks..=maximum_chunks).contains(&copy_chunks))
}

fn copy_start(slot: usize, copy_chunks: u64) -> Result<u64, VaultError> {
    if slot >= METADATA_COPY_COUNT {
        return Err(VaultError::corrupt("invalid metadata copy index"));
    }
    (slot as u64)
        .checked_mul(copy_chunks)
        .ok_or_else(|| VaultError::corrupt("metadata offset overflow"))
}

fn expected_chunk_count(total_len: u64, chunk_size: u32) -> Result<u64, VaultError> {
    let head_payload = (chunk_size as usize)
        .checked_sub(HEAD_LEN)
        .ok_or_else(|| VaultError::corrupt("chunk is too small for metadata"))?
        as u64;
    if total_len <= head_payload {
        Ok(1)
    } else {
        Ok(1 + (total_len - head_payload).div_ceil(chunk_size as u64))
    }
}

fn validated_snapshot_len(
    total_len: u64,
    chunk_count: u64,
    copy_chunks: u64,
    chunk_size: u32,
) -> Result<usize, VaultError> {
    if total_len == 0
        || total_len > metadata_capacity(copy_chunks, chunk_size)?
        || chunk_count != expected_chunk_count(total_len, chunk_size)?
        || chunk_count > copy_chunks
    {
        return Err(VaultError::corrupt("invalid metadata snapshot length"));
    }
    total_len
        .try_into()
        .map_err(|_| VaultError::corrupt("metadata snapshot is too large"))
}

pub(super) fn prepare_catalog_snapshot(
    catalog: &Catalog,
    copy_chunks: u64,
    chunk_size: u32,
) -> Result<PreparedMetadata, VaultError> {
    let bytes = catalog.to_bytes()?;
    if bytes.len() > MAX_ENCODED_CATALOG_BYTES {
        return Err(VaultError::FileError(
            "the catalog exceeds the supported canonical encoding limit".to_string(),
        ));
    }
    let capacity = metadata_capacity(copy_chunks, chunk_size)?;
    if bytes.len() as u64 > capacity {
        return Err(VaultError::FileError(format!(
            "the catalog needs {} bytes but this vault has {} bytes of metadata capacity",
            bytes.len(),
            capacity
        )));
    }
    let digest: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    let chunk_count = expected_chunk_count(bytes.len() as u64, chunk_size)?;
    if chunk_count > copy_chunks {
        return Err(VaultError::FileError(
            "the vault catalog has exhausted its dedicated metadata capacity".to_string(),
        ));
    }
    Ok(PreparedMetadata {
        bytes,
        digest,
        chunk_count,
    })
}

// Passing the sizes and copy position directly makes the write order easy to
// check at each call site.
#[allow(clippy::too_many_arguments)]
pub(super) fn write_snapshot(
    file: &File,
    cipher: &Cipher,
    container_id: &[u8; CONTAINER_ID_LEN],
    chunk_size: u32,
    copy_chunks: u64,
    slot: usize,
    generation: u64,
    prepared: &PreparedMetadata,
) -> Result<(), SnapshotWriteError> {
    if generation == 0 {
        return Err(SnapshotWriteError {
            error: VaultError::corrupt("metadata generation must be non-zero"),
            phase: SnapshotWritePhase::BeforeHead,
        });
    }
    #[cfg(test)]
    if let Some(failure) = take_snapshot_failure(slot, SnapshotWritePhase::BeforeHead) {
        return Err(failure);
    }
    let start = copy_start(slot, copy_chunks).map_err(|error| SnapshotWriteError {
        error,
        phase: SnapshotWritePhase::BeforeHead,
    })?;
    let head_payload = chunk_size as usize - HEAD_LEN;
    let mut consumed = prepared.bytes.len().min(head_payload);
    let mut plaintext = Zeroizing::new(vec![0u8; chunk_size as usize]);

    // The head tells recovery which update this copy contains. If we wrote it
    // first, an interruption could leave a new head pointing at old or missing
    // catalog bytes. So write the later chunks and synchronize them to storage
    // before replacing the head.
    for logical in 1..prepared.chunk_count {
        let physical = start + logical;
        plaintext.fill(0);
        let remaining = prepared.bytes.len() - consumed;
        let take = remaining.min(chunk_size as usize);
        plaintext[..take].copy_from_slice(&prepared.bytes[consumed..consumed + take]);
        consumed += take;
        let aad = metadata_chunk_aad(container_id, slot, logical, physical, chunk_size);
        write_record(
            file,
            cipher,
            chunk_size,
            physical,
            &aad,
            plaintext.as_slice(),
        )
        .map_err(|error| SnapshotWriteError {
            error,
            phase: SnapshotWritePhase::BeforeHead,
        })?;
    }
    file.sync_data().map_err(|error| SnapshotWriteError {
        error: VaultError::from_io("failed to synchronize metadata body records", error),
        phase: SnapshotWritePhase::BeforeHead,
    })?;

    // Reuse the buffer for the first chunk: its description and catalog bytes.
    let mut head = plaintext;
    head.fill(0);
    head[0..8].copy_from_slice(&MAGIC);
    head[8..10].copy_from_slice(&VERSION.to_be_bytes());
    head[10..12].copy_from_slice(&(HEAD_LEN as u16).to_be_bytes());
    head[12..20].copy_from_slice(&generation.to_be_bytes());
    head[20..28].copy_from_slice(&(prepared.bytes.len() as u64).to_be_bytes());
    head[28..36].copy_from_slice(&prepared.chunk_count.to_be_bytes());
    head[36..68].copy_from_slice(&prepared.digest);
    // 68..72 is reserved and remains zero.
    let head_take = prepared.bytes.len().min(head_payload);
    head[HEAD_LEN..HEAD_LEN + head_take].copy_from_slice(&prepared.bytes[..head_take]);
    let aad = metadata_chunk_aad(container_id, slot, 0, start, chunk_size);
    #[cfg(test)]
    if let Some(failure) = take_snapshot_failure(slot, SnapshotWritePhase::PublishingHead) {
        return Err(failure);
    }
    write_record(file, cipher, chunk_size, start, &aad, head.as_slice()).map_err(|error| {
        SnapshotWriteError {
            error,
            phase: SnapshotWritePhase::PublishingHead,
        }
    })?;
    file.sync_data().map_err(|error| SnapshotWriteError {
        error: VaultError::from_io("failed to synchronize the metadata commit record", error),
        phase: SnapshotWritePhase::PublishingHead,
    })?;
    Ok(())
}

// Pass the sizes and copy position directly so recovery can check this copy
// without depending on changes to Volume's state.
#[allow(clippy::too_many_arguments)]
fn parse_authenticated_candidate(
    file: &File,
    cipher: &Cipher,
    container_id: &[u8; CONTAINER_ID_LEN],
    chunk_size: u32,
    copy_chunks: u64,
    slot: usize,
    start: u64,
    head: Zeroizing<Vec<u8>>,
) -> Result<MetadataCandidate, (Option<u64>, [u8; 32], VaultError)> {
    let observed_digest: [u8; 32] = head[36..68].try_into().expect("fixed slice");

    // This hash covers the catalog bytes, not the head fields or padding.
    // So matching hashes alone don't mean two copies are safe to use. Check
    // the head's format first, then let recovery use its hash to compare copies.
    let parse_head = || -> Result<(u64, usize, u64, usize), VaultError> {
        if head[0..8] != MAGIC {
            return Err(VaultError::corrupt("invalid metadata magic"));
        }
        if u16::from_be_bytes(head[8..10].try_into().expect("fixed slice")) != VERSION {
            return Err(VaultError::corrupt("unsupported metadata version"));
        }
        if u16::from_be_bytes(head[10..12].try_into().expect("fixed slice")) as usize != HEAD_LEN {
            return Err(VaultError::corrupt("invalid metadata header length"));
        }
        if head[68..72].iter().any(|byte| *byte != 0) {
            return Err(VaultError::corrupt("non-zero metadata reserved bytes"));
        }
        let generation = u64::from_be_bytes(head[12..20].try_into().expect("fixed slice"));
        if generation == 0 {
            return Err(VaultError::corrupt("invalid zero metadata generation"));
        }
        let total_len = u64::from_be_bytes(head[20..28].try_into().expect("fixed slice"));
        let chunk_count = u64::from_be_bytes(head[28..36].try_into().expect("fixed slice"));
        let total_len_usize =
            validated_snapshot_len(total_len, chunk_count, copy_chunks, chunk_size)?;
        let head_payload = chunk_size as usize - HEAD_LEN;
        let head_take = total_len_usize.min(head_payload);
        if head[HEAD_LEN + head_take..].iter().any(|byte| *byte != 0) {
            return Err(VaultError::corrupt("non-zero metadata head padding"));
        }
        Ok((generation, total_len_usize, chunk_count, head_take))
    };
    let (generation, total_len_usize, chunk_count, head_take) =
        parse_head().map_err(|error| (None, observed_digest, error))?;

    let parse_snapshot = || -> Result<MetadataCandidate, VaultError> {
        let digest = observed_digest;
        let mut bytes = Zeroizing::new(Vec::with_capacity(total_len_usize));
        bytes.extend_from_slice(&head[HEAD_LEN..HEAD_LEN + head_take]);
        for logical in 1..chunk_count {
            let physical = start
                .checked_add(logical)
                .ok_or_else(|| VaultError::corrupt("metadata chunk offset overflow"))?;
            let aad = metadata_chunk_aad(container_id, slot, logical, physical, chunk_size);
            let body = read_record(file, cipher, chunk_size, physical, &aad)?;
            let remaining = total_len_usize - bytes.len();
            let take = remaining.min(chunk_size as usize);
            bytes.extend_from_slice(&body[..take]);
            if body[take..].iter().any(|byte| *byte != 0) {
                return Err(VaultError::corrupt("non-zero metadata body padding"));
            }
        }
        if bytes.len() != total_len_usize {
            return Err(VaultError::corrupt("metadata snapshot is truncated"));
        }
        let actual_digest: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        if actual_digest != digest {
            return Err(VaultError::corrupt("metadata snapshot digest mismatch"));
        }
        Ok(MetadataCandidate {
            slot,
            generation,
            digest,
            bytes,
        })
    };

    parse_snapshot().map_err(|error| (Some(generation), observed_digest, error))
}

pub(super) fn read_copy(
    file: &File,
    cipher: &Cipher,
    container_id: &[u8; CONTAINER_ID_LEN],
    chunk_size: u32,
    copy_chunks: u64,
    slot: usize,
) -> MetadataCopyState {
    let start = match copy_start(slot, copy_chunks) {
        Ok(start) => start,
        Err(error) => return MetadataCopyState::Unreadable(error),
    };
    let head_aad = metadata_chunk_aad(container_id, slot, 0, start, chunk_size);
    let head = match read_record(file, cipher, chunk_size, start, &head_aad) {
        Ok(head) => head,
        Err(error) => return MetadataCopyState::Unreadable(error),
    };
    match parse_authenticated_candidate(
        file,
        cipher,
        container_id,
        chunk_size,
        copy_chunks,
        slot,
        start,
        head,
    ) {
        Ok(candidate) => MetadataCopyState::Authenticated(candidate),
        Err((generation, digest, error)) => MetadataCopyState::AuthenticatedInvalid {
            generation,
            digest,
            error,
        },
    }
}

pub(super) fn validate_catalog_copy(
    file: &File,
    cipher: &Cipher,
    container_id: &[u8; CONTAINER_ID_LEN],
    chunk_size: u32,
    copy_chunks: u64,
    data_chunk_count: u64,
    slot: usize,
) -> Result<(), VaultError> {
    match read_copy(file, cipher, container_id, chunk_size, copy_chunks, slot) {
        MetadataCopyState::Authenticated(candidate) => {
            candidate.decode(data_chunk_count, chunk_size)?;
            Ok(())
        }
        MetadataCopyState::Unreadable(error)
        | MetadataCopyState::AuthenticatedInvalid { error, .. } => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_space_grows_with_vault_size_within_minimum_and_maximum() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(
            recommended_metadata_capacity(1),
            DEFAULT_METADATA_CAPACITY_FLOOR
        );
        assert_eq!(
            recommended_metadata_capacity(8 * GIB),
            DEFAULT_METADATA_CAPACITY_FLOOR
        );
        assert_eq!(recommended_metadata_capacity(9 * GIB), 18 * 1024 * 1024);
        assert_eq!(
            recommended_metadata_capacity(u64::MAX),
            MAX_METADATA_CAPACITY
        );
    }

    #[test]
    fn requested_catalog_space_rounds_up_and_rejects_sizes_outside_limits() {
        let requested = 8 * 1024 * 1024 + 1;
        let chunks = choose_metadata_copy_chunks(1, 4096, Some(requested)).unwrap();
        let actual = metadata_capacity(chunks, 4096).unwrap();
        assert!(actual >= requested);
        assert!(actual < requested + 4096);

        assert!(choose_metadata_copy_chunks(1, 4096, Some(MIN_METADATA_CAPACITY - 1)).is_err());
        assert!(choose_metadata_copy_chunks(1, 4096, Some(MAX_METADATA_CAPACITY + 1)).is_err());
    }

    #[test]
    fn catalog_chunk_counts_must_stay_within_creation_limits() {
        for chunk_size in [4096, 64 * 1024, 16 * 1024 * 1024] {
            let minimum =
                choose_metadata_copy_chunks(1, chunk_size, Some(MIN_METADATA_CAPACITY)).unwrap();
            let maximum =
                choose_metadata_copy_chunks(1, chunk_size, Some(MAX_METADATA_CAPACITY)).unwrap();
            assert!(metadata_copy_chunks_are_supported(minimum, chunk_size).unwrap());
            assert!(metadata_copy_chunks_are_supported(maximum, chunk_size).unwrap());
            assert!(!metadata_copy_chunks_are_supported(minimum - 1, chunk_size).unwrap());
            assert!(!metadata_copy_chunks_are_supported(maximum + 1, chunk_size).unwrap());
        }
    }

    #[test]
    fn catalogs_above_the_saved_size_limit_are_rejected() {
        let chunk_size = 4096;
        let copy_chunks = MAX_METADATA_CAPACITY
            .checked_add(HEAD_LEN as u64)
            .unwrap()
            .div_ceil(chunk_size as u64);
        let oversized = MAX_ENCODED_CATALOG_BYTES as u64 + 1;
        let chunk_count = expected_chunk_count(oversized, chunk_size).unwrap();
        let raw_arena_capacity = copy_chunks * chunk_size as u64 - HEAD_LEN as u64;

        assert!(oversized <= raw_arena_capacity);
        assert!(matches!(
            validated_snapshot_len(oversized, chunk_count, copy_chunks, chunk_size),
            Err(VaultError::Corrupt(message)) if message == "invalid metadata snapshot length"
        ));
    }
}
