use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, HashSet},
};

use getrandom::fill;
use zeroize::{Zeroize, Zeroizing};

use super::allocator::ChunkAllocator;
use crate::errors::VaultError;

mod codec;
mod path;

use path::{PortablePathKey, parent_path, portable_key};
pub use path::{normalize_path, validate_path};

pub(super) const FILE_ID_LEN: usize = 16;
pub const MAX_CATALOG_ENTRIES: usize = 250_000;

// A saved catalog can be quite small because paths share their beginnings.
// Loading it rebuilds the full paths, and we keep them in the map keys, file
// entries, and keys used to compare names. So, we also limit how much memory
// those strings use together. Limiting the saved size alone wouldn't catch this.
const MAX_CATALOG_STORED_PATH_BYTES: usize = 64 * 1024 * 1024;

pub(super) use codec::MAX_ENCODED_CATALOG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryKind {
    File = 1,
    Directory = 2,
}

impl EntryKind {
    fn from_u8(value: u8) -> Result<Self, VaultError> {
        match value {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            _ => Err(VaultError::corrupt("unknown catalog entry kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileEntry {
    pub path: String,
    pub kind: EntryKind,
    pub file_id: [u8; FILE_ID_LEN],
    pub size: u64,
    /// First chunk of this file, counting from the start of the file-data area.
    pub start_chunk: u64,
    pub num_chunks: u64,
}

impl Drop for FileEntry {
    fn drop(&mut self) {
        self.path.zeroize();
        self.file_id.zeroize();
        self.size.zeroize();
        self.start_chunk.zeroize();
        self.num_chunks.zeroize();
    }
}

impl FileEntry {
    pub(super) fn new_file(
        path: String,
        size: u64,
        start_chunk: u64,
        num_chunks: u64,
    ) -> Result<Self, VaultError> {
        // Validation or random ID generation can fail. Put the path in the
        // entry first, so FileEntry's Drop erases it on those early returns too.
        let mut entry = Self {
            path,
            kind: EntryKind::File,
            file_id: [0; FILE_ID_LEN],
            size,
            start_chunk,
            num_chunks,
        };
        validate_path(&entry.path)?;
        entry.file_id = random_file_id()?;
        Ok(entry)
    }

    pub(super) fn new_directory(path: String) -> Result<Self, VaultError> {
        let mut entry = Self {
            path,
            kind: EntryKind::Directory,
            file_id: [0; FILE_ID_LEN],
            size: 0,
            start_chunk: 0,
            num_chunks: 0,
        };
        validate_path(&entry.path)?;
        entry.file_id = random_file_id()?;
        Ok(entry)
    }
}

/// The map key owns a separate copy of the path, so FileEntry's cleanup won't
/// erase it. This wrapper gives that copy its own cleanup when it's dropped.
/// We have to wait until the key is removed or the map is dropped: changing a
/// key while it's still in the map would break the order used for lookups.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CatalogPath(String);

impl Borrow<str> for CatalogPath {
    // Lets the map look up a path using &str, without making a new CatalogPath.
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Drop for CatalogPath {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// A new file can reuse a deleted file's path and chunks. Its ID also goes into
// the authentication check, so giving it a fresh ID prevents old encrypted
// chunks from being accepted as contents of the replacement file.
fn random_file_id() -> Result<[u8; FILE_ID_LEN], VaultError> {
    let mut id = [0u8; FILE_ID_LEN];
    fill(&mut id)
        .map_err(|_| VaultError::CryptoError("failed to generate a file identity".to_string()))?;
    Ok(id)
}

#[derive(Debug, Clone, Default)]
pub(super) struct Catalog {
    entries: BTreeMap<CatalogPath, FileEntry>,
    ids: HashSet<[u8; FILE_ID_LEN]>,
    portable_paths: BTreeSet<PortablePathKey>,
    stored_path_bytes: usize,
}

pub(super) struct DecodedCatalog {
    pub catalog: Catalog,
    pub allocator: ChunkAllocator,
}

impl Catalog {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn find(&self, path: &str) -> Option<&FileEntry> {
        self.entries.get(path)
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = &FileEntry> {
        self.entries.values()
    }

    pub(super) fn descendants<'a>(
        &'a self,
        directory: &str,
    ) -> impl Iterator<Item = &'a FileEntry> {
        let mut prefix = Zeroizing::new(String::with_capacity(directory.len() + 1));
        prefix.push_str(directory);
        prefix.push('/');
        self.entries
            .range::<str, _>((
                std::ops::Bound::Included(prefix.as_str()),
                std::ops::Bound::Unbounded,
            ))
            .map(|(_, entry)| entry)
            .take_while(move |entry| entry.path.starts_with(prefix.as_str()))
    }

    pub(super) fn insert(&mut self, entry: FileEntry) -> Result<(), VaultError> {
        if self.entries.len() >= MAX_CATALOG_ENTRIES {
            return Err(VaultError::FileError(
                "catalog entry limit reached".to_string(),
            ));
        }
        validate_path(&entry.path)?;
        if self.entries.contains_key(entry.path.as_str()) {
            return Err(VaultError::FileError(format!(
                "'{}' already exists",
                entry.path
            )));
        }
        let key = portable_key(&entry.path);
        let stored_path_bytes = self
            .stored_path_bytes
            .checked_add(entry.path.len().saturating_mul(2))
            .and_then(|bytes| bytes.checked_add(key.0.len()))
            .ok_or_else(|| VaultError::FileError("catalog path storage overflow".to_string()))?;
        if stored_path_bytes > MAX_CATALOG_STORED_PATH_BYTES {
            return Err(VaultError::FileError(format!(
                "catalog paths exceed the {MAX_CATALOG_STORED_PATH_BYTES}-byte in-memory limit"
            )));
        }
        if self.portable_paths.contains(&key) {
            return Err(VaultError::FileError(
                "that path conflicts with an existing path on a case-insensitive filesystem"
                    .to_string(),
            ));
        }
        if self.ids.contains(&entry.file_id) {
            return Err(VaultError::corrupt("duplicate file identity"));
        }
        if let Some(parent) = parent_path(&entry.path) {
            if !self
                .entries
                .get(parent)
                .is_some_and(|entry| entry.kind == EntryKind::Directory)
            {
                return Err(VaultError::FileError(format!(
                    "parent directory '{parent}' does not exist"
                )));
            }
        }

        self.ids.insert(entry.file_id);
        self.portable_paths.insert(key);
        self.stored_path_bytes = stored_path_bytes;
        self.entries.insert(CatalogPath(entry.path.clone()), entry);
        Ok(())
    }

    pub(super) fn remove(&mut self, path: &str) -> Option<FileEntry> {
        let entry = self.entries.remove(path)?;
        self.ids.remove(&entry.file_id);
        let key = portable_key(path);
        self.portable_paths.remove(&key);
        self.stored_path_bytes = self
            .stored_path_bytes
            .saturating_sub(path.len().saturating_mul(2).saturating_add(key.0.len()));
        Some(entry)
    }

    pub(super) fn missing_ancestors<'a>(&self, path: &'a str) -> Result<Vec<&'a str>, VaultError> {
        let mut missing = Vec::new();
        let mut current = path;
        while let Some(parent) = parent_path(current) {
            match self.find(parent) {
                Some(entry) if entry.kind == EntryKind::Directory => break,
                Some(_) => {
                    return Err(VaultError::FileError(format!(
                        "'{parent}' exists as a file"
                    )));
                }
                None => missing.push(parent),
            }
            current = parent;
        }
        missing.reverse();
        Ok(missing)
    }

    // The catalog already tells us which chunks belong to each file, so we can
    // rebuild the free-space map from it. Reserving each range also catches two
    // entries claiming the same chunks.
    pub(super) fn build_allocator(&self, total_chunks: u64) -> Result<ChunkAllocator, VaultError> {
        let mut allocator = ChunkAllocator::new(total_chunks);
        for entry in self.entries.values() {
            if entry.kind == EntryKind::File && entry.num_chunks != 0 {
                allocator.reserve(entry.start_chunk, entry.num_chunks)?;
            }
        }
        Ok(allocator)
    }
}

#[cfg(test)]
mod tests;
