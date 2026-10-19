//! This module brings together the pieces needed to read and change a vault.
//! The CLI and applications using the library go through these same operations.
//!
//! The layout is [Header A | Header B | Catalog A | Catalog B | File Data].
//! The headers store the vault settings and protect its master key. The catalog
//! tells us which files exist, how big they are, and where their chunks are stored.

mod allocator;
mod chunk_io;
mod content;
mod extraction;
mod file_table;
mod geometry;
mod import;
mod lifecycle;
mod metadata;
mod operations;
mod password;
mod path_io;
mod persistence;
mod reader;
mod transport;
mod types;

#[cfg(test)]
mod tests;

use std::{fs::File, sync::Arc};

use allocator::ChunkAllocator;
use file_table::Catalog;
pub use file_table::{
    normalize_path as normalize_vault_path, validate_path as validate_vault_path,
};
use geometry::file_data_start_chunk;
pub use geometry::{
    DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MAX_DATA_BYTES, MAX_DATA_CHUNKS, MIN_CHUNK_SIZE,
};
use metadata::metadata_capacity;
pub use metadata::{
    DEFAULT_METADATA_CAPACITY_FLOOR, MAX_METADATA_CAPACITY, MIN_METADATA_CAPACITY,
    recommended_metadata_capacity,
};
pub use reader::{MAX_RANDOM_ACCESS_READ, VaultFileCursor, VaultFileReader};
pub use types::{
    AccessMode, CreateOptions, FileInfo, ImportReport, VaultInfo, VaultLocation, VerificationReport,
};

use crate::{
    cipher::Cipher,
    errors::VaultError,
    header::{CONTAINER_ID_LEN, HeaderPayload},
};

/// An open vault for reading files and, when allowed, making changes.
///
/// Opening checks the headers and catalog for damage or tampering. We check file
/// contents as they're read, so opening a large vault doesn't require reading
/// all of its files first. Use [`Self::verify`] to check every current file.
///
/// Paths inside the vault are relative and use `/`, such as `docs/notes.txt`.
/// They must already follow the rules in [`validate_vault_path`].
/// [`normalize_vault_path`] makes equivalent Unicode spellings consistent;
/// operations do not do this automatically.
///
/// Several read-only volumes can share a file lock. A writable volume needs the
/// vault to itself, so another writer can't change the catalog or reuse chunks
/// while we're working with them. Other applications must respect these locks too.
/// Before reporting success, the library waits for the operating system to save
/// changes to storage. Trying to change a read-only volume returns
/// [`VaultError::ReadOnly`].
///
/// A write can fail partway through. We may then be unable to tell which changes
/// reached storage, so further operations return [`VaultError::Poisoned`].
/// Close and reopen the vault to let recovery check the saved copies.
/// [`VaultError::CommitUncertain`] means a change may already have been saved;
/// check the recovered state before retrying it.
///
/// Dropping the volume stops its [`VaultFileReader`] handles from reading,
/// wipes its protected keys, and releases its file lock. Plaintext already
/// returned to callers and file information still held by reader handles are
/// owned separately and are not erased by dropping the volume.
///
/// Calls block until they finish. GUI applications should run password
/// derivation and file reads or writes on a worker thread to keep the interface
/// responsive.
pub struct Volume {
    // The open file, shared with readers through Arc.
    file: Arc<File>,
    // A filesystem path or an application-supplied document label.
    location: VaultLocation,
    // Whether this volume allows changes or only reading.
    access_mode: AccessMode,
    // Bytes each chunk holds before encryption.
    chunk_size: u32,
    // Total chunks reserved for file contents, including unused chunks.
    data_chunk_count: u64,
    // Chunks reserved for each of the two catalog copies.
    metadata_copy_chunks: u64,
    // Identifies this vault when checking encrypted chunks.
    container_id: [u8; CONTAINER_ID_LEN],
    // Separate encryption keys for file contents and the catalog.
    data_cipher: Cipher,
    metadata_cipher: Cipher,
    // The decrypted header, including vault settings and the master key.
    header_payload: HeaderPayload,
    // The header's update number; increases when the password changes.
    header_generation: u64,
    // The file catalog, checked for damage or tampering when opened.
    catalog: Catalog,
    // Tracks unused file-data chunks and finds space for new files.
    allocator: ChunkAllocator,
    // The catalog's update number; increases when files or directories change.
    metadata_generation: u64,
    // Whether a header or catalog copy needs repair.
    redundancy_degraded: bool,
    // None while usable; otherwise, the failure that requires closing this volume.
    poisoned: Option<String>,
    // Lets the volume stop readers after changes, failures, or closure.
    reader_session: Arc<reader::ReaderSession>,
}

impl Volume {
    /// Returns space usage, access mode, and whether stored copies need repair.
    pub fn info(&self) -> Result<VaultInfo, VaultError> {
        self.ensure_readable()?;
        let data_capacity = self
            .data_chunk_count
            .checked_mul(self.chunk_size as u64)
            .ok_or_else(|| VaultError::corrupt("data capacity overflow"))?;
        let free_space = self
            .allocator
            .free_chunks()
            .checked_mul(self.chunk_size as u64)
            .ok_or_else(|| VaultError::corrupt("free-space overflow"))?;
        let data_used = data_capacity
            .checked_sub(free_space)
            .ok_or_else(|| VaultError::corrupt("used-space underflow"))?;
        let metadata_capacity = metadata_capacity(self.metadata_copy_chunks, self.chunk_size)?;
        let metadata_used = u64::try_from(self.catalog.encoded_len()?)
            .map_err(|_| VaultError::corrupt("metadata usage overflow"))?;
        Ok(VaultInfo {
            location: self.location.clone(),
            access_mode: self.access_mode,
            cipher: self.header_payload.fields().cipher_id,
            data_capacity,
            data_used,
            free_space,
            metadata_capacity,
            metadata_used,
            chunk_size: self.chunk_size,
            file_count: self.catalog.len(),
            header_generation: self.header_generation,
            metadata_generation: self.metadata_generation,
            redundancy_degraded: self.redundancy_degraded,
        })
    }

    /// Returns the location of this open vault.
    pub fn location(&self) -> &VaultLocation {
        &self.location
    }

    /// Converts a chunk number within the file-data area to its position among
    /// all chunks after the headers. If the two catalogs use chunks 0 through
    /// 199, file-data chunk 3 is chunk 203 in the vault.
    pub(super) fn physical_chunk_for_data_chunk(&self, relative: u64) -> Result<u64, VaultError> {
        if relative >= self.data_chunk_count {
            return Err(VaultError::corrupt(
                "data chunk lies outside the data region",
            ));
        }
        file_data_start_chunk(self.metadata_copy_chunks)?
            .checked_add(relative)
            .ok_or_else(|| VaultError::corrupt("data chunk offset overflow"))
    }

    pub(super) fn ensure_readable(&self) -> Result<(), VaultError> {
        if let Some(reason) = &self.poisoned {
            return Err(VaultError::Poisoned(reason.clone()));
        }
        Ok(())
    }

    pub(super) fn ensure_writable(&self) -> Result<(), VaultError> {
        self.ensure_readable()?;
        if self.access_mode != AccessMode::ReadWrite {
            return Err(VaultError::ReadOnly);
        }
        Ok(())
    }

    pub(super) fn poison(&mut self, reason: impl Into<String>) {
        if self.poisoned.is_none() {
            self.reader_session.poison();
            self.poisoned = Some(reason.into());
        }
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        self.reader_session.close();
        // The readers have now finished any reads already in progress. Just
        // dropping our file reference might leave a duplicate handle holding
        // the lock, so explicitly unlock it before this volume goes away.
        let _ = fs2::FileExt::unlock(self.file.as_ref());
    }
}
