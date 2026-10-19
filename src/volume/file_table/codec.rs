//! Converts the catalog to bytes and rebuilds it when opening the vault.
//!
//! Paths are sorted, so neighboring paths often share the same beginning.
//! We save how many bytes match the previous path, followed by the remaining
//! bytes. For example, after `docs/a.txt`, `docs/b.txt` only needs a shared
//! length of 5 and the ending `b.txt`. Loading joins those pieces back together.

use zeroize::Zeroizing;

use super::{
    Catalog, ChunkAllocator, DecodedCatalog, EntryKind, FILE_ID_LEN, FileEntry,
    MAX_CATALOG_ENTRIES, path::MAX_PATH_LEN,
};
use crate::errors::VaultError;

const MAGIC: [u8; 8] = *b"LUNACAT1";
const VERSION: u16 = 1;
pub(super) const HEADER_LEN: usize = 8 + 2 + 4;
pub(super) const ENTRY_FIXED_LEN: usize = 2 + 2 + 1 + FILE_ID_LEN + 8 + 8 + 8;
const MIN_ENTRY_LEN: usize = ENTRY_FIXED_LEN + 1;

/// Largest saved catalog that can fit within the entry and path-memory limits.
///
/// We only save the part of each path that differs from the previous one, so
/// the saved names can't take more bytes than the full paths. In memory, each
/// full path is kept at least twice: in the map key and in `FileEntry::path`.
/// This means half the path-memory limit is enough to cover the saved names.
/// We then add space for the entry fields and catalog header.
pub(in crate::volume) const MAX_ENCODED_CATALOG_BYTES: usize =
    HEADER_LEN + MAX_CATALOG_ENTRIES * ENTRY_FIXED_LEN + super::MAX_CATALOG_STORED_PATH_BYTES / 2;

fn shared_prefix_len(previous: &[u8], current: &[u8]) -> usize {
    previous
        .iter()
        .zip(current)
        .take_while(|(left, right)| left == right)
        .count()
}

/// Takes the next field only if all its bytes are present. All catalog fields,
/// including path endings of different lengths, use this check.
fn take_bytes<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], VaultError> {
    let (field, remaining) = input
        .split_at_checked(len)
        .ok_or_else(|| VaultError::corrupt("catalog is truncated"))?;
    *input = remaining;
    Ok(field)
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], VaultError> {
    Ok(take_bytes(input, N)?
        .try_into()
        .expect("checked field length"))
}

impl Catalog {
    pub(in crate::volume) fn encoded_len(&self) -> Result<usize, VaultError> {
        let mut length = HEADER_LEN;
        let mut previous_path: &[u8] = &[];
        for entry in self.entries.values() {
            let path = entry.path.as_bytes();
            let shared = shared_prefix_len(previous_path, path);
            let suffix_len = path.len() - shared;
            length = length
                .checked_add(ENTRY_FIXED_LEN)
                .and_then(|value| value.checked_add(suffix_len))
                .ok_or_else(|| VaultError::FileError("catalog size overflow".to_string()))?;
            previous_path = path;
        }
        Ok(length)
    }

    pub(in crate::volume) fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let count: u32 = self
            .entries
            .len()
            .try_into()
            .map_err(|_| VaultError::FileError("catalog has too many entries".to_string()))?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.encoded_len()?));
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());

        let mut previous_path: &[u8] = &[];
        for entry in self.entries.values() {
            let path = entry.path.as_bytes();
            let shared = shared_prefix_len(previous_path, path);
            let suffix = &path[shared..];
            let shared: u16 = shared.try_into().map_err(|_| {
                VaultError::FileError("catalog path prefix is too long".to_string())
            })?;
            let suffix_len: u16 = suffix.len().try_into().map_err(|_| {
                VaultError::FileError("catalog path suffix is too long".to_string())
            })?;
            bytes.extend_from_slice(&shared.to_be_bytes());
            bytes.extend_from_slice(&suffix_len.to_be_bytes());
            bytes.extend_from_slice(suffix);
            bytes.push(entry.kind as u8);
            bytes.extend_from_slice(&entry.file_id);
            bytes.extend_from_slice(&entry.size.to_be_bytes());
            bytes.extend_from_slice(&entry.start_chunk.to_be_bytes());
            bytes.extend_from_slice(&entry.num_chunks.to_be_bytes());
            previous_path = path;
        }
        Ok(bytes)
    }

    pub(in crate::volume) fn decode(
        mut bytes: &[u8],
        data_chunk_count: u64,
        chunk_size: u32,
    ) -> Result<DecodedCatalog, VaultError> {
        if bytes.len() > MAX_ENCODED_CATALOG_BYTES {
            return Err(VaultError::corrupt(
                "catalog exceeds the encoded size limit",
            ));
        }
        if chunk_size == 0 {
            return Err(VaultError::corrupt("invalid zero chunk size"));
        }
        if take::<8>(&mut bytes)? != MAGIC {
            return Err(VaultError::corrupt("invalid catalog magic"));
        }
        if u16::from_be_bytes(take(&mut bytes)?) != VERSION {
            return Err(VaultError::corrupt("unsupported catalog version"));
        }
        let count = u32::from_be_bytes(take(&mut bytes)?) as usize;
        if count > MAX_CATALOG_ENTRIES || count > bytes.len() / MIN_ENTRY_LEN {
            return Err(VaultError::corrupt("invalid catalog entry count"));
        }

        let mut catalog = Self::new();
        let mut allocator = ChunkAllocator::new(data_chunk_count);
        for _ in 0..count {
            // We need the previous path to rebuild this one. It's already in
            // the catalog, so borrow it from there instead of keeping another copy.
            let previous_path = catalog
                .entries
                .last_key_value()
                .map(|(_, entry)| entry.path.as_bytes())
                .unwrap_or_default();
            let shared = u16::from_be_bytes(take(&mut bytes)?) as usize;
            let suffix_len = u16::from_be_bytes(take(&mut bytes)?) as usize;
            if shared > previous_path.len() || suffix_len == 0 {
                return Err(VaultError::corrupt("invalid front-coded catalog path"));
            }
            let path_len = shared + suffix_len;
            if path_len > MAX_PATH_LEN {
                return Err(VaultError::corrupt("invalid catalog path length"));
            }
            let suffix = take_bytes(&mut bytes, suffix_len)?;
            let mut path_bytes = Zeroizing::new(Vec::with_capacity(path_len));
            path_bytes.extend_from_slice(&previous_path[..shared]);
            path_bytes.extend_from_slice(suffix);
            if shared_prefix_len(previous_path, &path_bytes) != shared {
                return Err(VaultError::corrupt(
                    "catalog path does not use canonical front coding",
                ));
            }
            // String::from_utf8 takes ownership of the bytes, even when it
            // returns an error. That error doesn't wipe them. So, check UTF-8
            // while the bytes are still inside Zeroizing, then convert them.
            std::str::from_utf8(&path_bytes)
                .map_err(|_| VaultError::corrupt("catalog path is not UTF-8"))?;
            let mut path = Zeroizing::new(
                String::from_utf8(std::mem::take(&mut *path_bytes)).expect("validated UTF-8 path"),
            );
            if !previous_path.is_empty() && path.as_bytes() <= previous_path {
                return Err(VaultError::corrupt(
                    "catalog paths are not in strictly increasing canonical order",
                ));
            }
            let kind = EntryKind::from_u8(take::<1>(&mut bytes)?[0])?;
            let file_id: [u8; FILE_ID_LEN] = take(&mut bytes)?;
            let size = u64::from_be_bytes(take(&mut bytes)?);
            let start_chunk = u64::from_be_bytes(take(&mut bytes)?);
            let num_chunks = u64::from_be_bytes(take(&mut bytes)?);

            match kind {
                EntryKind::Directory => {
                    if size != 0 || start_chunk != 0 || num_chunks != 0 {
                        return Err(VaultError::corrupt(
                            "directory entry has non-canonical storage fields",
                        ));
                    }
                }
                EntryKind::File if size == 0 => {
                    if start_chunk != 0 || num_chunks != 0 {
                        return Err(VaultError::corrupt(
                            "empty file has non-canonical storage fields",
                        ));
                    }
                }
                EntryKind::File => {
                    let expected_chunks = size.div_ceil(chunk_size as u64);
                    if num_chunks != expected_chunks {
                        return Err(VaultError::corrupt(
                            "file extent does not exactly match its size",
                        ));
                    }
                    allocator.reserve(start_chunk, num_chunks)?;
                }
            }

            catalog
                .insert(FileEntry {
                    path: std::mem::take(&mut *path),
                    kind,
                    file_id,
                    size,
                    start_chunk,
                    num_chunks,
                })
                .map_err(|error| VaultError::corrupt(format!("invalid catalog entry: {error}")))?;
        }

        if !bytes.is_empty() {
            return Err(VaultError::corrupt("catalog has trailing bytes"));
        }
        Ok(DecodedCatalog { catalog, allocator })
    }

    #[cfg(test)]
    pub(super) fn from_bytes(
        bytes: &[u8],
        data_chunk_count: u64,
        chunk_size: u32,
    ) -> Result<Self, VaultError> {
        Self::decode(bytes, data_chunk_count, chunk_size).map(|decoded| decoded.catalog)
    }
}
