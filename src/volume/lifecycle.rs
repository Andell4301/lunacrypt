use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    ops::{Deref, DerefMut},
    path::Path,
    sync::Arc,
};

use fs2::FileExt;
use getrandom::fill;

use super::{
    AccessMode, CreateOptions, VaultLocation, Volume,
    allocator::ChunkAllocator,
    file_table::Catalog,
    geometry::{
        MAX_CONTAINER_FILE_BYTES, MAX_DATA_BYTES, MAX_DATA_CHUNKS, validate_chunk_size,
        validate_geometry,
    },
    metadata::{
        METADATA_COPY_COUNT, choose_metadata_copy_chunks, prepare_catalog_snapshot,
        validate_catalog_copy, write_snapshot,
    },
    path_io::PendingFile,
};
use crate::{
    Password,
    cipher::Cipher,
    errors::VaultError,
    header::{
        DATA_AREA_OFFSET, HeaderPayload, OpenedHeader, build_pair, open_pair, repair_pair,
        write_slot,
    },
    kdf::{
        KdfParams,
        hkdf::{KeyDomain, expand_key},
        validate_password_length,
    },
};

const RANDOM_FILL_BUFFER_SIZE: usize = 1024 * 1024;

/// We lock the file before all the opening or creation checks have finished.
/// If a later check fails, this wrapper explicitly unlocks it. Just closing
/// our handle might leave the lock alive if another handle shares it.
struct LockedFile(Option<File>);

impl LockedFile {
    fn into_file(mut self) -> File {
        self.0.take().expect("locked file has not been transferred")
    }
}

impl Deref for LockedFile {
    type Target = File;

    fn deref(&self) -> &File {
        self.0
            .as_ref()
            .expect("locked file has not been transferred")
    }
}

impl DerefMut for LockedFile {
    fn deref_mut(&mut self) -> &mut File {
        self.0
            .as_mut()
            .expect("locked file has not been transferred")
    }
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        if let Some(file) = &self.0 {
            let _ = FileExt::unlock(file);
        }
    }
}

fn build_ciphers(payload: &HeaderPayload) -> Result<(Cipher, Cipher), VaultError> {
    let id = payload.fields().cipher_id;
    let data_key = expand_key(payload.master_key(), KeyDomain::FileData)?;
    let metadata_key = expand_key(payload.master_key(), KeyDomain::Metadata)?;
    Ok((Cipher::new(id, data_key), Cipher::new(id, metadata_key)))
}

fn fill_with_random_bytes(file: &mut File, offset: u64, length: u64) -> Result<(), VaultError> {
    file.seek(SeekFrom::Start(offset)).map_err(|error| {
        VaultError::from_io("failed to seek while filling the new vault", error)
    })?;
    let mut remaining = length;
    let mut buffer = vec![0u8; RANDOM_FILL_BUFFER_SIZE];
    while remaining != 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        fill(&mut buffer[..take]).map_err(|_| {
            VaultError::CryptoError(
                "failed to obtain random bytes while filling the new vault".to_string(),
            )
        })?;
        file.write_all(&buffer[..take])
            .map_err(|error| VaultError::from_io("failed to fill the new vault", error))?;
        remaining -= take as u64;
    }
    Ok(())
}

fn checked_display_name(display_name: String) -> Result<String, VaultError> {
    let display_name = display_name.trim().to_string();
    if display_name.is_empty() {
        return Err(VaultError::FileError(
            "external document display name cannot be empty".to_string(),
        ));
    }
    if display_name.chars().any(char::is_control) {
        return Err(VaultError::FileError(
            "external document display name contains control characters".to_string(),
        ));
    }
    Ok(display_name)
}

fn validate_file_access(file: &File, access_mode: AccessMode) -> Result<(), VaultError> {
    use cap_fs_ext::IsFileReadWrite;

    let (readable, writable) = file
        .is_file_read_write()
        .map_err(|error| VaultError::from_io("failed to inspect vault handle access", error))?;
    if !readable || (access_mode == AccessMode::ReadWrite && !writable) {
        return Err(VaultError::FileError(
            "vault handle does not provide the requested read/write access".to_string(),
        ));
    }
    if access_mode == AccessMode::ReadWrite {
        // On Linux, append mode makes pwrite write at the end, ignoring its
        // requested byte offset. Reject it before any operation changes the file.
        #[cfg(unix)]
        let append_only = rustix::fs::fcntl_getfl(file)
            .map_err(|error| {
                VaultError::from_io("failed to inspect vault handle flags", error.into())
            })?
            .contains(rustix::fs::OFlags::APPEND);

        #[cfg(windows)]
        let append_only = {
            use std::os::windows::io::AsHandle;
            !winx::file::query_access_information(file.as_handle())
                .map_err(|error| {
                    VaultError::from_io("failed to inspect vault handle flags", error)
                })?
                .contains(winx::file::AccessMode::FILE_WRITE_DATA)
        };

        #[cfg(any(unix, windows))]
        if append_only {
            return Err(VaultError::FileError(
                "append-only file handles cannot back writable vaults".to_string(),
            ));
        }
    }
    Ok(())
}

impl Volume {
    /// Creates a writable vault at a new path using default creation options.
    ///
    /// See [`Self::create_container_with_options`] for sizing, saving, and
    /// error behavior.
    pub fn create_container(
        path: &Path,
        password: &Password,
        requested_data_bytes: u64,
        chunk_size: u32,
    ) -> Result<Self, VaultError> {
        Self::create_container_with_options(
            path,
            password,
            requested_data_bytes,
            chunk_size,
            CreateOptions::default(),
        )
    }

    /// Creates a writable vault that appears at the destination only when complete.
    ///
    /// `requested_data_bytes` is the desired plaintext data capacity, rounded
    /// up to whole chunks. Headers, both catalog copies, and encryption overhead
    /// add to the resulting file size. `chunk_size` must be a power of two
    /// between [`super::MIN_CHUNK_SIZE`] and [`super::MAX_CHUNK_SIZE`]. The
    /// destination's parent must already exist; existing targets are never
    /// replaced. New vault files have mode 0600 on Unix.
    ///
    /// We build the vault in a temporary file in the destination directory,
    /// then make the completed file visible at the requested path. So a
    /// failure before that final step doesn't leave a partly created vault
    /// at the destination.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid passwords or sizing, an existing target,
    /// unavailable protected key memory, or failed storage or cryptographic
    /// operations. [`VaultError::CommitUncertain`] can mean the complete vault
    /// appeared at the destination, but saving its directory entry to storage
    /// could not be confirmed.
    pub fn create_container_with_options(
        path: &Path,
        password: &Password,
        requested_data_bytes: u64,
        chunk_size: u32,
        options: CreateOptions,
    ) -> Result<Self, VaultError> {
        Self::create_container_with_kdf_and_options(
            path,
            password,
            requested_data_bytes,
            chunk_size,
            options,
            KdfParams::default(),
        )
    }

    #[cfg(test)]
    pub(crate) fn create_container_with_kdf(
        path: &Path,
        password: &Password,
        requested_data_bytes: u64,
        chunk_size: u32,
        kdf_params: KdfParams,
    ) -> Result<Self, VaultError> {
        Self::create_container_with_kdf_and_options(
            path,
            password,
            requested_data_bytes,
            chunk_size,
            CreateOptions::default(),
            kdf_params,
        )
    }

    pub(crate) fn create_container_with_kdf_and_options(
        path: &Path,
        password: &Password,
        requested_data_bytes: u64,
        chunk_size: u32,
        options: CreateOptions,
        kdf_params: KdfParams,
    ) -> Result<Self, VaultError> {
        kdf_params.validate()?;
        let (pending, file) = PendingFile::create(path)?;
        let volume = Self::initialize_new_file(
            file,
            VaultLocation::Path(path.to_path_buf()),
            password,
            requested_data_bytes,
            chunk_size,
            options,
            kdf_params,
        )?;

        pending.publish()?;
        Ok(volume)
    }

    /// Creates a writable vault directly in a file supplied by the application.
    ///
    /// The file must be empty and support reading, writing at chosen byte
    /// offsets, and saving writes to storage. It must be a regular file, not a
    /// pipe or device, and support an exclusive lock honored by cooperating
    /// applications. Append mode is not allowed.
    /// The function takes ownership of the handle. The caller controls when
    /// the document becomes visible and should delete it if creation fails.
    /// `display_name` is a nonempty label without control characters.
    ///
    /// Capacity, chunk sizing, and creation errors follow
    /// [`Self::create_container_with_options`], with default options. There is
    /// no temporary file or final move for a caller-supplied handle.
    pub fn create_container_on_file(
        file: File,
        display_name: impl Into<String>,
        password: &Password,
        requested_data_bytes: u64,
        chunk_size: u32,
    ) -> Result<Self, VaultError> {
        Self::create_container_on_file_with_options(
            file,
            display_name,
            password,
            requested_data_bytes,
            chunk_size,
            CreateOptions::default(),
        )
    }

    /// Creates a vault directly in an application-supplied file with explicit
    /// creation options.
    ///
    /// The handle requirements and partial-write behavior are the same as for
    /// [`Self::create_container_on_file`].
    pub fn create_container_on_file_with_options(
        file: File,
        display_name: impl Into<String>,
        password: &Password,
        requested_data_bytes: u64,
        chunk_size: u32,
        options: CreateOptions,
    ) -> Result<Self, VaultError> {
        let display_name = checked_display_name(display_name.into())?;
        Self::initialize_new_file(
            file,
            VaultLocation::ExternalDocument { display_name },
            password,
            requested_data_bytes,
            chunk_size,
            options,
            KdfParams::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn initialize_new_file(
        file: File,
        location: VaultLocation,
        password: &Password,
        requested_data_bytes: u64,
        chunk_size: u32,
        options: CreateOptions,
        kdf_params: KdfParams,
    ) -> Result<Self, VaultError> {
        validate_password_length(password)?;
        // Callers can build these password derivation settings directly, so
        // we can't assume they've already been checked. Validate them before
        // changing the size or contents of the supplied file.
        kdf_params.validate()?;
        validate_chunk_size(chunk_size)?;
        if requested_data_bytes == 0 || requested_data_bytes > MAX_DATA_BYTES {
            return Err(VaultError::FileError(format!(
                "requested data capacity must be between 1 byte and {MAX_DATA_BYTES} bytes"
            )));
        }

        validate_file_access(&file, AccessMode::ReadWrite)?;

        FileExt::try_lock_exclusive(&file)
            .map_err(|error| VaultError::from_io("failed to lock the new vault", error))?;
        let mut file = LockedFile(Some(file));
        let initial_metadata = file.metadata().map_err(|error| {
            VaultError::from_io("failed to inspect the new vault backing", error)
        })?;
        if !initial_metadata.is_file() {
            return Err(VaultError::FileError(
                "vault backing must be a regular, seekable file".to_string(),
            ));
        }
        if initial_metadata.len() != 0 {
            return Err(VaultError::FileError(
                "direct vault creation requires an empty file".to_string(),
            ));
        }

        let data_chunk_count = requested_data_bytes.div_ceil(chunk_size as u64);
        if data_chunk_count == 0 || data_chunk_count > MAX_DATA_CHUNKS {
            return Err(VaultError::FileError(
                "requested vault requires too many chunks".to_string(),
            ));
        }
        let metadata_copy_chunks = choose_metadata_copy_chunks(
            requested_data_bytes,
            chunk_size,
            options.metadata_capacity,
        )?;
        let expected_len = validate_geometry(chunk_size, data_chunk_count, metadata_copy_chunks)?;
        file.set_len(expected_len)
            .map_err(|error| VaultError::from_io("failed to size the new vault", error))?;
        if options.fill_data_area {
            let fill_len = expected_len
                .checked_sub(DATA_AREA_OFFSET)
                .ok_or_else(|| VaultError::corrupt("invalid vault fill geometry"))?;
            fill_with_random_bytes(&mut file, DATA_AREA_OFFSET, fill_len)?;
        }

        let payload = HeaderPayload::create(
            options.cipher,
            chunk_size,
            data_chunk_count,
            metadata_copy_chunks,
        )?;
        let header_pair = build_pair(1, password, kdf_params, &payload)?;
        for (slot, raw) in header_pair.iter().enumerate() {
            write_slot(&file, slot, raw)?;
        }
        let (data_cipher, metadata_cipher) = build_ciphers(&payload)?;
        let catalog = Catalog::new();
        let prepared = prepare_catalog_snapshot(&catalog, metadata_copy_chunks, chunk_size)?;
        for slot in 0..METADATA_COPY_COUNT {
            write_snapshot(
                &file,
                &metadata_cipher,
                &payload.fields().container_id,
                chunk_size,
                metadata_copy_chunks,
                slot,
                1,
                &prepared,
            )
            .map_err(|failure| failure.error)?;
        }
        file.sync_all()
            .map_err(|error| VaultError::from_io("failed to synchronize the new vault", error))?;

        for slot in 0..METADATA_COPY_COUNT {
            validate_catalog_copy(
                &file,
                &metadata_cipher,
                &payload.fields().container_id,
                chunk_size,
                metadata_copy_chunks,
                data_chunk_count,
                slot,
            )?;
        }

        Ok(Self {
            file: Arc::new(file.into_file()),
            location,
            access_mode: AccessMode::ReadWrite,
            chunk_size,
            data_chunk_count,
            metadata_copy_chunks,
            container_id: payload.fields().container_id,
            data_cipher,
            metadata_cipher,
            header_payload: payload,
            header_generation: 1,
            catalog,
            allocator: ChunkAllocator::new(data_chunk_count),
            metadata_generation: 1,
            redundancy_degraded: false,
            poisoned: None,
            reader_session: Arc::new(super::reader::ReaderSession::new()),
        })
    }

    /// Opens a vault for reading and writing, acquiring an exclusive lock.
    ///
    /// Authenticates the headers and catalog, repairing damaged or older copies
    /// when another copy can safely restore them. File data is authenticated
    /// when read or by [`Self::verify`], so opening doesn't have to scan every
    /// file in the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or locked, the password
    /// cannot authenticate a usable header, the vault is malformed, protected
    /// key memory is unavailable, or required repair fails. Lock acquisition
    /// does not wait for another handle to release its lock.
    pub fn open_container(path: &Path, password: &Password) -> Result<Self, VaultError> {
        Self::open_internal(path, password, AccessMode::ReadWrite)
    }

    /// Opens a vault for reading, acquiring a shared lock without waiting.
    ///
    /// Performs the authentication and validation of [`Self::open_container`]
    /// without repairing or writing any bytes. If a header or catalog copy
    /// needs repair, [`VaultInfo::redundancy_degraded`](super::VaultInfo::redundancy_degraded)
    /// reports it. Methods that change the vault return [`VaultError::ReadOnly`].
    pub fn open_container_read_only(path: &Path, password: &Password) -> Result<Self, VaultError> {
        Self::open_internal(path, password, AccessMode::ReadOnly)
    }

    /// Opens a user-selected platform document for writable vault access.
    ///
    /// The file handle must support reading, writing at chosen byte offsets,
    /// saving writes to storage, and an exclusive lock honored by cooperating
    /// applications. Append mode is not allowed. If a document provider cannot
    /// support these operations, import the encrypted vault into the
    /// application's private storage.
    ///
    /// Takes ownership of the handle. `display_name` must be a nonempty label
    /// without control characters. Authentication, repair, and error behavior
    /// otherwise follow [`Self::open_container`].
    pub fn open_container_file(
        file: File,
        display_name: impl Into<String>,
        password: &Password,
    ) -> Result<Self, VaultError> {
        let display_name = checked_display_name(display_name.into())?;
        Self::open_file_internal(
            file,
            VaultLocation::ExternalDocument { display_name },
            password,
            AccessMode::ReadWrite,
        )
    }

    /// Opens a user-selected platform document for read-only vault access.
    ///
    /// Takes ownership of a readable regular file that supports reading at
    /// chosen byte offsets and shared locks honored by cooperating applications.
    /// `display_name` must be a nonempty label without control characters.
    /// Authentication and error behavior follow
    /// [`Self::open_container_read_only`]; no repair writes are attempted.
    pub fn open_container_file_read_only(
        file: File,
        display_name: impl Into<String>,
        password: &Password,
    ) -> Result<Self, VaultError> {
        let display_name = checked_display_name(display_name.into())?;
        Self::open_file_internal(
            file,
            VaultLocation::ExternalDocument { display_name },
            password,
            AccessMode::ReadOnly,
        )
    }

    fn open_internal(
        path: &Path,
        password: &Password,
        access_mode: AccessMode,
    ) -> Result<Self, VaultError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(access_mode == AccessMode::ReadWrite);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A named pipe (FIFO) can wait forever for a writer when opened for
            // reading. Open without waiting so the file-type check can reject it.
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        let file = options
            .open(path)
            .map_err(|error| VaultError::from_io("failed to open the vault", error))?;
        Self::open_file_internal(
            file,
            VaultLocation::Path(path.to_path_buf()),
            password,
            access_mode,
        )
    }

    pub(super) fn open_file_internal(
        file: File,
        location: VaultLocation,
        password: &Password,
        access_mode: AccessMode,
    ) -> Result<Self, VaultError> {
        validate_password_length(password)?;
        validate_file_access(&file, access_mode)?;
        match access_mode {
            AccessMode::ReadOnly => FileExt::try_lock_shared(&file),
            AccessMode::ReadWrite => FileExt::try_lock_exclusive(&file),
        }
        .map_err(|error| VaultError::from_io("failed to acquire the vault lock", error))?;
        let file = LockedFile(Some(file));

        let file_metadata = file
            .metadata()
            .map_err(|error| VaultError::from_io("failed to inspect the vault", error))?;
        if !file_metadata.is_file() {
            return Err(VaultError::FileError(
                "vault backing must be a regular, seekable file".to_string(),
            ));
        }
        let actual_len = file_metadata.len();
        if actual_len < DATA_AREA_OFFSET {
            return Err(VaultError::corrupt("vault is truncated"));
        }
        if actual_len > MAX_CONTAINER_FILE_BYTES {
            return Err(VaultError::corrupt(
                "vault file exceeds the supported size limit",
            ));
        }
        if access_mode == AccessMode::ReadWrite && location.is_external_document() {
            file.sync_all().map_err(|error| {
                VaultError::from_io(
                    "external document does not provide required synchronization semantics",
                    error,
                )
            })?;
        }

        let OpenedHeader {
            payload,
            generation: header_generation,
            degraded: header_degraded,
            kdf_params: header_kdf_params,
            healthy_slots: header_healthy_slots,
        } = open_pair(&file, password)?;
        let fields = payload.fields();
        let expected_len = validate_geometry(
            fields.chunk_size,
            fields.data_chunk_count,
            fields.metadata_copy_chunks,
        )?;
        if actual_len != expected_len {
            return Err(VaultError::corrupt(format!(
                "vault length is {actual_len} bytes, expected {expected_len}"
            )));
        }
        let (data_cipher, metadata_cipher) = build_ciphers(&payload)?;
        let mut volume = Self {
            file: Arc::new(file.into_file()),
            location,
            access_mode,
            chunk_size: fields.chunk_size,
            data_chunk_count: fields.data_chunk_count,
            metadata_copy_chunks: fields.metadata_copy_chunks,
            container_id: fields.container_id,
            data_cipher,
            metadata_cipher,
            header_payload: payload,
            header_generation,
            catalog: Catalog::new(),
            allocator: ChunkAllocator::new(fields.data_chunk_count),
            metadata_generation: 0,
            redundancy_degraded: header_degraded,
            poisoned: None,
            reader_session: Arc::new(super::reader::ReaderSession::new()),
        };
        let loaded = volume.load_metadata(access_mode == AccessMode::ReadWrite)?;
        if access_mode == AccessMode::ReadWrite && header_degraded {
            repair_pair(
                &volume.file,
                password,
                header_generation,
                &volume.header_payload,
                header_kdf_params,
                header_healthy_slots,
            )?;
            volume.redundancy_degraded = false;
        }
        volume.catalog = loaded.catalog;
        volume.allocator = loaded.allocator;
        volume.metadata_generation = loaded.generation;
        volume.redundancy_degraded |= loaded.degraded;
        Ok(volume)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TEST_CIPHERS, TestPath, password};

    #[test]
    fn invalid_password_derivation_settings_leave_supplied_files_empty() {
        for cipher in TEST_CIPHERS {
            let backing = TestPath::file("invalid-kdf-external-create");
            let file = backing.create_file();
            let observer = file.try_clone().unwrap();
            let result = Volume::initialize_new_file(
                file,
                VaultLocation::ExternalDocument {
                    display_name: "vault.luna".to_string(),
                },
                &password(b"test password"),
                4096,
                4096,
                CreateOptions {
                    cipher,
                    metadata_capacity: Some(crate::MIN_METADATA_CAPACITY),
                    fill_data_area: true,
                },
                KdfParams::Argon2id {
                    memory_cost: 0,
                    time_cost: 1,
                    parallelism: 1,
                },
            );

            assert!(matches!(result, Err(VaultError::KdfError(_))));
            assert_eq!(observer.metadata().unwrap().len(), 0);
        }
    }
}
