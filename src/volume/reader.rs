//! Reads authenticated file ranges for previews, with access controlled by Volume.

use std::{
    fmt,
    fs::File,
    io::{Error as IoError, ErrorKind, Read, Seek, SeekFrom},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use zeroize::{Zeroize, Zeroizing};

use super::{
    Volume,
    content::ContentReader,
    file_data_start_chunk,
    file_table::{EntryKind, FileEntry},
};
use crate::{
    Plaintext,
    cipher::Cipher,
    errors::VaultError,
    kdf::hkdf::{KeyDomain, expand_key},
};

/// Maximum plaintext length accepted by [`Volume::read_range`] in one call.
pub const MAX_RANDOM_ACCESS_READ: usize = 64 * 1024 * 1024;

struct ReaderBacking {
    file: Arc<File>,
    cipher: Cipher,
}

/// State shared by all file readers created from one open volume.
///
/// A caller can keep a reader after dropping the volume. So the reader's file
/// reference and extra data key live here, where the volume can release them
/// even while those old reader handles still exist.
///
/// Each read holds the shared lock until it finishes using the file and key.
/// Stopping readers takes the write lock, which waits for those reads to finish
/// before releasing either resource.
pub(super) struct ReaderSession {
    epoch: AtomicU64,
    closed: AtomicBool,
    poisoned: AtomicBool,
    backing: RwLock<Option<ReaderBacking>>,
}

impl ReaderSession {
    pub(super) fn new() -> Self {
        Self {
            epoch: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            backing: RwLock::new(None),
        }
    }

    fn lock_backing_for_write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, Option<ReaderBacking>>, VaultError> {
        self.backing.write().map_err(|_| {
            VaultError::ReaderRevoked("preview session state was poisoned".to_string())
        })
    }

    fn lock_backing_for_read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, Option<ReaderBacking>>, VaultError> {
        self.backing.read().map_err(|_| {
            VaultError::ReaderRevoked("preview session state was poisoned".to_string())
        })
    }

    pub(super) fn activate<F>(&self, source: &Arc<File>, build: F) -> Result<u64, VaultError>
    where
        F: FnOnce() -> Result<Cipher, VaultError>,
    {
        let mut backing = self.lock_backing_for_write()?;
        if self.closed.load(Ordering::Acquire) {
            return Err(VaultError::ReaderRevoked(
                "the vault session is closed".to_string(),
            ));
        }
        if self.poisoned.load(Ordering::Acquire) {
            return Err(VaultError::ReaderRevoked(
                "the vault session is no longer trustworthy".to_string(),
            ));
        }
        if backing.is_none() {
            *backing = Some(ReaderBacking {
                // We need the same OS file handle that owns the vault lock.
                // A duplicated Windows handle can behave differently for locks
                // and file access, so share the existing handle through Arc.
                file: Arc::clone(source),
                cipher: build()?,
            });
        }
        Ok(self.epoch.load(Ordering::Acquire))
    }

    /// Stops all current readers and releases their file reference and key.
    pub(super) fn invalidate(&self) {
        let mut backing = self
            .backing
            .write()
            .unwrap_or_else(|error| error.into_inner());
        self.bump_epoch();
        *backing = None;
    }

    /// Permanently stops readers after a storage failure makes the volume unusable.
    pub(super) fn poison(&self) {
        let mut backing = self
            .backing
            .write()
            .unwrap_or_else(|error| error.into_inner());
        self.poisoned.store(true, Ordering::Release);
        self.bump_epoch();
        *backing = None;
    }

    /// Permanently stops readers and releases their file reference and key,
    /// even if callers keep old reader handles.
    pub(super) fn close(&self) {
        // A panic while holding this lock must not prevent cleanup, even when
        // callers still own reader handles.
        let mut backing = self
            .backing
            .write()
            .unwrap_or_else(|error| error.into_inner());
        self.closed.store(true, Ordering::Release);
        self.bump_epoch();
        *backing = None;
    }

    fn bump_epoch(&self) {
        // Each reader remembers the counter value from when it was opened.
        // Changing it makes every existing reader out of date, even if a new
        // file reference and key are later added to this session.
        let previous = self.epoch.fetch_add(1, Ordering::AcqRel);
        if previous == u64::MAX {
            // If this counter ever wraps around, an old reader could match the
            // new number. Close the session permanently to prevent that.
            self.closed.store(true, Ordering::Release);
        }
    }
}

/// A file reader that authenticates bytes and reads at caller-chosen offsets.
///
/// The reader never creates a plaintext file. It decrypts only chunks that
/// overlap the requested range and writes verified bytes into the supplied
/// buffer. It stops working when the source [`Volume`] is dropped, becomes
/// unusable after an error, or starts saving a catalog or password update.
/// Stopping readers waits for reads already in progress and releases their
/// shared encryption key.
///
/// Clones can read at the same time and stop working together. The path, size,
/// and catalog update number remain available after reading is disabled.
/// Dropping each handle erases its copied path and file metadata. Already
/// returned plaintext remains the caller's responsibility.
#[derive(Clone)]
pub struct VaultFileReader {
    session: Arc<ReaderSession>,
    epoch: u64,
    entry: FileEntry,
    chunk_size: u32,
    data_region_start: u64,
    data_chunk_count: u64,
    container_id: [u8; 16],
    catalog_generation: u64,
}

impl fmt::Debug for VaultFileReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultFileReader")
            .field("size", &self.entry.size)
            .field("catalog_generation", &self.catalog_generation)
            .finish_non_exhaustive()
    }
}

impl VaultFileReader {
    /// Returns the slash-separated relative vault path recorded when opened.
    pub fn path(&self) -> &str {
        &self.entry.path
    }

    /// Returns the file length in plaintext bytes.
    pub fn len(&self) -> u64 {
        self.entry.size
    }

    /// Returns whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.entry.size == 0
    }

    /// Returns the catalog update number recorded when this reader was opened.
    pub fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Reads authenticated plaintext starting at `offset` into `destination`.
    ///
    /// Returns the number of bytes read. Reads at or beyond the end of the file
    /// return zero. Reads that cross the end are shortened; the unused part of
    /// `destination` is left unchanged on success.
    /// A later chunk can fail after earlier bytes have already been copied.
    /// So on failure, we wipe the entire destination before returning the error.
    /// On success, the caller owns the plaintext and is responsible for erasing
    /// the destination and any copies. Multiple threads may read through this
    /// handle at the same time.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::ReaderRevoked`] after the reader is stopped,
    /// including for empty reads and reads at the end of the file. Storage
    /// errors, failed authentication, and invalid stored data also fail the
    /// entire call and wipe the destination.
    pub fn read_at(&self, offset: u64, destination: &mut [u8]) -> Result<usize, VaultError> {
        match self.read_at_inner(offset, destination) {
            Ok(read) => Ok(read),
            Err(error) => {
                destination.zeroize();
                Err(error)
            }
        }
    }

    fn read_at_inner(&self, offset: u64, destination: &mut [u8]) -> Result<usize, VaultError> {
        let backing = self.session.lock_backing_for_read()?;
        self.ensure_current()?;
        let backing = backing.as_ref().ok_or_else(|| {
            VaultError::ReaderRevoked("the native preview backing is closed".to_string())
        })?;

        if destination.is_empty() || offset >= self.entry.size {
            return Ok(0);
        }
        let available = self
            .entry
            .size
            .checked_sub(offset)
            .ok_or_else(|| VaultError::corrupt("random-access range underflow"))?;
        let requested = u64::try_from(destination.len())
            .map_err(|_| VaultError::FileError("read buffer is too large".to_string()))?;
        let total = available.min(requested) as usize;
        let chunk_size = u64::from(self.chunk_size);
        let mut logical = offset / chunk_size;
        let mut in_chunk = (offset % chunk_size) as usize;
        let mut written = 0usize;

        let content = ContentReader::new(
            &backing.file,
            &backing.cipher,
            &self.container_id,
            self.chunk_size,
            self.data_region_start,
            self.data_chunk_count,
        );
        while written < total {
            let plaintext = content.read_chunk(&self.entry, logical)?;
            let available = plaintext.get(in_chunk..).ok_or_else(|| {
                VaultError::corrupt("requested offset exceeds the authenticated file chunk")
            })?;
            let take = (total - written).min(available.len());
            destination[written..written + take].copy_from_slice(&available[..take]);
            written += take;
            logical += 1;
            in_chunk = 0;
        }

        Ok(written)
    }

    /// Creates a `Read + Seek` cursor starting at byte zero. It remembers the
    /// next byte to read, so callers don't have to supply an offset each time.
    pub fn cursor(self) -> VaultFileCursor {
        VaultFileCursor {
            reader: self,
            position: 0,
        }
    }

    fn ensure_current(&self) -> Result<(), VaultError> {
        if self.session.closed.load(Ordering::Acquire) {
            return Err(VaultError::ReaderRevoked(
                "the vault was locked or closed".to_string(),
            ));
        }
        if self.session.poisoned.load(Ordering::Acquire) {
            return Err(VaultError::ReaderRevoked(
                "the vault entered an uncertain persistence state".to_string(),
            ));
        }
        if self.session.epoch.load(Ordering::Acquire) != self.epoch {
            return Err(VaultError::ReaderRevoked(
                "the vault catalog changed".to_string(),
            ));
        }
        Ok(())
    }
}

/// A cursor that remembers the next byte to read and supports `Read + Seek`.
///
/// A clone starts at the same position, then tracks its own position separately.
/// Both cursors use the same reader and stop working together. Seeking can
/// move past the end of the file; it does not read or authenticate data. If the
/// reader is stopped, the next read returns an [`std::io::Error`] containing
/// the [`VaultError`].
#[derive(Debug, Clone)]
pub struct VaultFileCursor {
    reader: VaultFileReader,
    position: u64,
}

impl VaultFileCursor {
    /// Returns the reader used by this cursor.
    pub fn reader(&self) -> &VaultFileReader {
        &self.reader
    }

    /// Takes ownership of the cursor and returns its reader.
    pub fn into_reader(self) -> VaultFileReader {
        self.reader
    }
}

impl Read for VaultFileCursor {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self
            .reader
            .read_at(self.position, buffer)
            .map_err(vault_error_to_io)?;
        self.position = self
            .position
            .checked_add(read as u64)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "cursor position overflow"))?;
        Ok(read)
    }
}

impl Seek for VaultFileCursor {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => checked_signed_offset(self.position, delta),
            SeekFrom::End(delta) => checked_signed_offset(self.reader.len(), delta),
        }
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "invalid seek before byte zero"))?;
        self.position = next;
        Ok(next)
    }
}

fn checked_signed_offset(base: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub(delta.unsigned_abs())
    }
}

fn vault_error_to_io(error: VaultError) -> IoError {
    IoError::other(error)
}

impl Volume {
    /// Opens a reader for authenticated reads at chosen offsets in one file.
    ///
    /// The reader uses the current catalog. It stops working when the volume
    /// starts saving catalog or password changes, becomes unusable after an
    /// error, or is dropped. These events also release the readers' shared
    /// file reference and erase their extra data key. Opening a reader does
    /// not read file contents; each chunk is authenticated when read.
    ///
    /// # Errors
    ///
    /// Fails if `path` is absent or names a directory, the volume is unusable,
    /// or the shared reader key cannot be derived or protected in memory.
    pub fn open_file_reader(&self, path: &str) -> Result<VaultFileReader, VaultError> {
        self.ensure_readable()?;
        let entry = self
            .catalog
            .find(path)
            .ok_or_else(|| VaultError::FileError(format!("'{path}' not found")))?;
        if entry.kind != EntryKind::File {
            return Err(VaultError::FileError(format!("'{path}' is a directory")));
        }

        let epoch = self.reader_session.activate(&self.file, || {
            let key = expand_key(self.header_payload.master_key(), KeyDomain::FileData)?;
            Ok(Cipher::new(self.header_payload.fields().cipher_id, key))
        })?;

        Ok(VaultFileReader {
            session: Arc::clone(&self.reader_session),
            epoch,
            entry: entry.clone(),
            chunk_size: self.chunk_size,
            data_region_start: file_data_start_chunk(self.metadata_copy_chunks)?,
            data_chunk_count: self.data_chunk_count,
            container_id: self.container_id,
            catalog_generation: self.metadata_generation,
        })
    }

    /// Reads part of a file into a new plaintext buffer.
    ///
    /// `length` must not exceed [`MAX_RANDOM_ACCESS_READ`]. A range crossing
    /// the end of the file is shortened; one starting at or beyond it returns
    /// an empty buffer. The returned buffer is wiped on drop. Copies made by
    /// the caller need their own cleanup.
    /// Applications that reuse read buffers should use
    /// [`Volume::open_file_reader`].
    ///
    /// # Errors
    ///
    /// Rejects lengths above the limit. Other errors follow
    /// [`Self::open_file_reader`] and [`VaultFileReader::read_at`].
    pub fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: usize,
    ) -> Result<Plaintext, VaultError> {
        if length > MAX_RANDOM_ACCESS_READ {
            return Err(VaultError::FileError(format!(
                "random-access reads are limited to {MAX_RANDOM_ACCESS_READ} bytes per call"
            )));
        }
        let reader = self.open_file_reader(path)?;
        let available = reader.len().saturating_sub(offset);
        let capacity = usize::try_from(available.min(length as u64))
            .map_err(|_| VaultError::FileError("requested range is too large".to_string()))?;
        let mut output = Zeroizing::new(vec![0u8; capacity]);
        let read = reader.read_at(offset, &mut output)?;
        output.truncate(read);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_key::SecretKey;

    #[test]
    fn stopping_readers_releases_the_file_and_key_even_after_a_panic() {
        let source = Arc::new(File::open(std::env::current_exe().unwrap()).unwrap());
        for revoke in [
            ReaderSession::invalidate,
            ReaderSession::poison,
            ReaderSession::close,
        ] {
            let session = ReaderSession::new();
            let epoch = session
                .activate(&source, || {
                    let mut key = SecretKey::zeroed()?;
                    key.expose_secret_mut().fill(7);
                    Ok(Cipher::new(crate::CipherId::default(), key))
                })
                .unwrap();
            assert!(Arc::ptr_eq(
                &session.backing.read().unwrap().as_ref().unwrap().file,
                &source,
            ));
            assert_eq!(Arc::strong_count(&source), 2);
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = session.backing.write().unwrap();
                panic!("simulate a panic while the reader backing is locked");
            }));
            assert!(panic.is_err());
            assert!(session.backing.is_poisoned());

            revoke(&session);

            let backing = session
                .backing
                .read()
                .unwrap_or_else(|error| error.into_inner());
            assert!(backing.is_none(), "revocation retained the file and key");
            assert_eq!(Arc::strong_count(&source), 1);
            assert_ne!(session.epoch.load(Ordering::Acquire), epoch);
            assert!(session.lock_backing_for_read().is_err());
        }
    }
}
