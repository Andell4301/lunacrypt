//! Importing and exporting complete encrypted vaults.
//!
//! These functions copy encrypted vault bytes without writing plaintext to
//! disk. Imports authenticate the header before copying the body and verify all
//! file contents before making the destination visible. The stream APIs also
//! support mobile document providers and desktop save/open dialogs.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use super::{AccessMode, VaultLocation, Volume, geometry::validate_geometry, path_io::PendingFile};
use crate::{
    Password,
    errors::VaultError,
    header::{DATA_AREA_OFFSET, open_pair},
    io::read_exact_at,
    kdf::validate_password_length,
};

const COPY_BUFFER_SIZE: usize = 1024 * 1024;

fn copy_vault_with_header_check<R: Read>(
    source: &mut R,
    destination: &mut File,
    password: &Password,
) -> Result<(), VaultError> {
    // A source could send a huge amount of data with a wrong password or an
    // invalid header. Check the fixed-size header first, so rejected input
    // can't fill the temporary file before we find out it's unusable.
    let mut header = [0u8; DATA_AREA_OFFSET as usize];
    source
        .read_exact(&mut header)
        .map_err(|error| VaultError::from_io("failed to read the encrypted vault header", error))?;
    destination.write_all(&header).map_err(|error| {
        VaultError::from_io("failed to stage the encrypted vault header", error)
    })?;
    let opened = open_pair(destination, password)?;
    let fields = opened.payload.fields();
    let expected = validate_geometry(
        fields.chunk_size,
        fields.data_chunk_count,
        fields.metadata_copy_chunks,
    )?;
    drop(opened);

    destination
        .seek(SeekFrom::Start(DATA_AREA_OFFSET))
        .map_err(|error| VaultError::from_io("failed to seek the import destination", error))?;
    let mut remaining = expected - DATA_AREA_OFFSET;
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    while remaining != 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        source.read_exact(&mut buffer[..take]).map_err(|error| {
            VaultError::from_io("failed to read the encrypted vault body", error)
        })?;
        destination
            .write_all(&buffer[..take])
            .map_err(|error| VaultError::from_io("failed to write the imported vault", error))?;
        remaining -= take as u64;
    }

    // The authenticated header tells us exactly how long the vault should be.
    // One extra byte is enough to detect trailing data, so we don't need to
    // keep reading a source that could carry on indefinitely.
    let mut extra = [0u8; 1];
    loop {
        match source.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(VaultError::corrupt("encrypted vault has trailing bytes")),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(VaultError::from_io(
                    "failed to read the end of the encrypted vault",
                    error,
                ));
            }
        }
    }
}

fn copy_exact_to_writer<W: Write>(
    source: &File,
    destination: &mut W,
    expected: u64,
) -> Result<u64, VaultError> {
    let mut remaining = expected;
    let mut copied = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    while remaining != 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        read_exact_at(source, &mut buffer[..take], copied)?;
        destination
            .write_all(&buffer[..take])
            .map_err(|error| VaultError::from_io("failed to write the encrypted vault", error))?;
        copied = copied
            .checked_add(take as u64)
            .ok_or_else(|| VaultError::FileError("vault export length overflow".to_string()))?;
        remaining -= take as u64;
    }
    destination.flush().map_err(|error| {
        VaultError::from_io("failed to flush the encrypted vault export", error)
    })?;
    Ok(copied)
}

impl Volume {
    /// Imports and verifies an encrypted vault from an existing temporary file.
    ///
    /// We open `staged` and copy its bytes into our own temporary file, then
    /// verify that copy. If we verified the source and then moved it by path,
    /// the path could be replaced between those steps. We'd then publish bytes
    /// we hadn't checked. Using our own copy keeps those steps on the same file.
    /// This function never removes the caller's source file.
    ///
    /// The source must resolve to a regular file, not a pipe or device.
    /// Destination requirements, returned access mode, and other errors follow
    /// [`Self::import_container_from_reader`].
    pub fn import_container_from_staged_path(
        staged: &Path,
        destination: &Path,
        password: &Password,
    ) -> Result<Self, VaultError> {
        validate_password_length(password)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A named pipe (FIFO) must open without waiting for a writer so the
            // file-type check below can reject it.
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        let mut source = options.open(staged).map_err(|error| {
            VaultError::from_io("failed to open the imported vault staging file", error)
        })?;
        if !source
            .metadata()
            .map_err(|error| VaultError::from_io("failed to inspect the staged vault", error))?
            .is_file()
        {
            return Err(VaultError::FileError(
                "staged vault must be a regular file".to_string(),
            ));
        }
        Self::import_container_from_file(&mut source, destination, password)
    }

    /// Imports an encrypted vault stream into a new filesystem file.
    ///
    /// The source may be a file or a one-way document-provider pipe. The header
    /// is authenticated before reading the rest. The library copies exactly
    /// the declared vault length into a private temporary file, saves it to
    /// storage, and verifies it fully. The completed file then appears at the
    /// destination in one step, without replacing an existing file. A failed
    /// password check or malformed source leaves no destination vault behind.
    ///
    /// Reads from the source's current position and requires it to end
    /// immediately after the declared vault length. The destination's parent
    /// directory must already exist. Returns a writable volume holding an
    /// exclusive lock on the imported vault. The caller keeps ownership of the source.
    ///
    /// # Errors
    ///
    /// Fails for invalid passwords, missing or extra input bytes, failed
    /// authentication, unavailable protected key memory, or errors reading,
    /// saving, or making the destination visible. [`VaultError::CommitUncertain`]
    /// can mean the verified vault is visible at the destination, but saving
    /// its directory entry to storage could not be confirmed.
    pub fn import_container_from_reader<R: Read>(
        source: &mut R,
        destination: &Path,
        password: &Password,
    ) -> Result<Self, VaultError> {
        validate_password_length(password)?;
        let (pending, mut temp_file) = PendingFile::create(destination)?;

        copy_vault_with_header_check(source, &mut temp_file, password)?;
        temp_file.sync_all().map_err(|error| {
            VaultError::from_io("failed to synchronize the imported vault", error)
        })?;

        // Checking the header was enough to start the copy, but it doesn't
        // prove the catalog or files are valid. Open the completed copy using
        // the usual authentication and repair checks, then verify its files.
        // This derives the password key again so imports and ordinary opens
        // use the same checks. Volume keeps this exact locked file when we
        // make it visible at the final destination.
        let volume = Self::open_file_internal(
            temp_file,
            VaultLocation::Path(destination.to_path_buf()),
            password,
            AccessMode::ReadWrite,
        )?;
        volume.verify()?;
        pending.publish()?;
        Ok(volume)
    }

    /// Imports an encrypted vault file into a new filesystem file.
    ///
    /// Seeks `source` to byte zero and leaves its position after the bytes read.
    /// Verification, saving, and error behavior otherwise follow
    /// [`Self::import_container_from_reader`].
    pub fn import_container_from_file(
        source: &mut File,
        destination: &Path,
        password: &Password,
    ) -> Result<Self, VaultError> {
        source
            .seek(SeekFrom::Start(0))
            .map_err(|error| VaultError::from_io("failed to seek the selected vault", error))?;
        Self::import_container_from_reader(source, destination, password)
    }

    /// Copies the complete encrypted vault to `destination`.
    ///
    /// Returns the number of encrypted bytes written and flushes the writer.
    /// Copying encrypted bytes doesn't tell us whether their contents have
    /// been damaged. This method doesn't decrypt or verify them; call
    /// [`Self::verify`] first to check every current file before exporting.
    ///
    /// This supports document-provider pipes. The caller must make the
    /// destination visible, save it to storage, close it, and clean up after
    /// errors, which can leave a partial encrypted copy in the writer.
    ///
    /// # Errors
    ///
    /// Fails if the volume is unusable after an earlier error, its file length
    /// or type changed, or reading, writing, or flushing the encrypted bytes fails.
    pub fn export_container_to_writer<W: Write>(
        &self,
        destination: &mut W,
    ) -> Result<u64, VaultError> {
        self.ensure_readable()?;
        let expected = validate_geometry(
            self.chunk_size,
            self.data_chunk_count,
            self.metadata_copy_chunks,
        )?;
        let metadata = self
            .file
            .metadata()
            .map_err(|error| VaultError::from_io("failed to inspect the open vault", error))?;
        if !metadata.is_file() || metadata.len() != expected {
            return Err(VaultError::corrupt(
                "open vault backing length or type changed",
            ));
        }
        copy_exact_to_writer(&self.file, destination, expected)
    }

    /// Copies the complete encrypted vault into an empty file and saves it to
    /// storage before returning. The file must support seeking to chosen offsets.
    ///
    /// On error, the caller should delete the partially created external
    /// document. Providers that expose only a write pipe should use
    /// [`Volume::export_container_to_writer`] and let the platform close the
    /// provider stream to finish saving the document.
    ///
    /// Returns the number of encrypted bytes copied. Rejects destinations that
    /// are nonempty or are not regular files. Verification behavior and other
    /// errors follow [`Self::export_container_to_writer`], with additional
    /// errors possible while seeking, sizing, and synchronizing the destination.
    pub fn export_container_to_file(&self, destination: &mut File) -> Result<u64, VaultError> {
        let destination_metadata = destination.metadata().map_err(|error| {
            VaultError::from_io("failed to inspect the export destination", error)
        })?;
        if !destination_metadata.is_file() {
            return Err(VaultError::FileError(
                "seekable export destination must be a regular file".to_string(),
            ));
        }
        if destination_metadata.len() != 0 {
            return Err(VaultError::FileError(
                "export destination is not empty; refusing to overwrite it".to_string(),
            ));
        }
        destination
            .seek(SeekFrom::Start(0))
            .map_err(|error| VaultError::from_io("failed to seek the export destination", error))?;
        let copied = self.export_container_to_writer(destination)?;
        destination.set_len(copied).map_err(|error| {
            VaultError::from_io("failed to finalize the exported vault length", error)
        })?;
        destination.sync_all().map_err(|error| {
            VaultError::from_io("failed to synchronize the exported vault", error)
        })?;
        Ok(copied)
    }

    /// Exports the complete encrypted vault through a temporary file in the
    /// destination directory. The completed file appears at its final path in
    /// one step, without replacing an existing target.
    ///
    /// The destination's parent must already exist. Returns the number of
    /// encrypted bytes copied. Verification behavior follows
    /// [`Self::export_container_to_writer`]. Existing targets are never
    /// replaced; [`VaultError::CommitUncertain`] can mean the destination
    /// appeared, but saving its directory entry to storage could not be confirmed.
    pub fn export_container_to_path(&self, destination: &Path) -> Result<u64, VaultError> {
        let (pending, mut temp_file) = PendingFile::create(destination)?;
        let copied = self.export_container_to_file(&mut temp_file)?;
        pending.publish()?;
        Ok(copied)
    }
}
