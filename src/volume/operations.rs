use std::io::{Cursor, Read, Write};

use zeroize::Zeroizing;

use super::{
    FileInfo, VerificationReport, Volume,
    chunk_io::{data_chunk_aad, write_record},
    file_table::{EntryKind, FileEntry, validate_path},
};
use crate::{Plaintext, errors::VaultError};

const MAX_IN_MEMORY_EXTRACTION: u64 = 256 * 1024 * 1024;

impl Volume {
    fn write_data_chunk(
        &mut self,
        relative_chunk: u64,
        file_id: &[u8; 16],
        logical_chunk: u64,
        plaintext: &[u8],
    ) -> Result<(), VaultError> {
        let physical = self.physical_chunk_for_data_chunk(relative_chunk)?;
        let aad = data_chunk_aad(
            &self.container_id,
            file_id,
            logical_chunk,
            physical,
            self.chunk_size,
        );
        write_record(
            &self.file,
            &self.data_cipher,
            self.chunk_size,
            physical,
            &aad,
            plaintext,
        )
    }

    /// Adds plaintext without taking ownership of it. The caller must erase
    /// `data` and any other copies of the source.
    ///
    /// Missing parent directories are created; existing entries are never
    /// replaced. Capacity and error behavior follow [`Self::add_file_from_reader`].
    pub fn add_file(&mut self, path: &str, data: &[u8]) -> Result<(), VaultError> {
        let mut reader = Cursor::new(data);
        self.add_file_from_reader(path, data.len() as u64, &mut reader)
    }

    /// Adds exactly `size` bytes from `reader`. The source is read before each
    /// corresponding encrypted chunk is written. The catalog is saved only
    /// after all file data has been synchronized to storage.
    /// Bytes after the declared size are left unread. Missing parent directories
    /// are created and existing entries are never replaced. Each file requires
    /// one continuous run of free data chunks.
    ///
    /// Internal plaintext buffers are wiped on drop; callers are responsible
    /// for any plaintext retained by their source reader.
    ///
    /// # Errors
    ///
    /// Fails for an invalid or conflicting path, insufficient data or catalog
    /// capacity, a short or failing source reader, or storage and encryption
    /// failures. If reading the source fails, the file is not added to the
    /// catalog. Failure while saving the catalog may return
    /// [`VaultError::CommitUncertain`]; close and reopen the volume to check what
    /// was saved before retrying. See [`Volume`] for more on recovery.
    pub fn add_file_from_reader<R: Read>(
        &mut self,
        path: &str,
        size: u64,
        reader: &mut R,
    ) -> Result<(), VaultError> {
        self.ensure_writable()?;
        validate_path(path)?;
        if self.catalog.find(path).is_some() {
            return Err(VaultError::FileError(format!("'{path}' already exists")));
        }

        let mut candidate = self.catalog.clone();
        for ancestor in candidate.missing_ancestors(path)? {
            candidate.insert(FileEntry::new_directory(ancestor.to_string())?)?;
        }

        let num_chunks = if size == 0 {
            0
        } else {
            size.div_ceil(self.chunk_size as u64)
        };
        let start_chunk = if num_chunks == 0 {
            0
        } else {
            self.allocator.find_free_extent(num_chunks)?
        };
        let entry = FileEntry::new_file(path.to_string(), size, start_chunk, num_chunks)?;
        candidate.insert(entry.clone())?;
        // Free data chunks do not guarantee that another catalog entry will fit.
        // Prepare the new catalog before writing any file data, so a full catalog
        // fails here. Keep these exact bytes to save once the file data is ready.
        let prepared = self.prepare_catalog(candidate)?;

        let mut remaining = size;
        let mut plaintext = Zeroizing::new(vec![0u8; self.chunk_size as usize]);
        for logical in 0..num_chunks {
            plaintext.fill(0);
            let take = remaining.min(self.chunk_size as u64) as usize;
            reader.read_exact(&mut plaintext[..take]).map_err(|error| {
                VaultError::FileError(format!("failed to read source data: {error}"))
            })?;
            remaining -= take as u64;
            if let Err(error) = self.write_data_chunk(
                start_chunk + logical,
                &entry.file_id,
                logical,
                plaintext.as_slice(),
            ) {
                self.poison(format!("a file-data write failed: {error}"));
                return Err(error);
            }
        }
        drop(plaintext);
        if let Err(error) = self.file.sync_data() {
            self.poison(format!("file data could not be synchronized: {error}"));
            return Err(VaultError::from_io(
                "failed to synchronize new file data",
                error,
            ));
        }

        self.commit_catalog(prepared)
    }

    /// Creates a directory and any missing parents.
    ///
    /// Succeeds without changing the catalog if the directory already exists.
    /// Fails if the path is invalid, a parent or target is a file, the catalog
    /// is full, or the catalog cannot be saved.
    pub fn mkdir(&mut self, path: &str) -> Result<(), VaultError> {
        self.ensure_writable()?;
        validate_path(path)?;
        if let Some(existing) = self.catalog.find(path) {
            return if existing.kind == EntryKind::Directory {
                Ok(())
            } else {
                Err(VaultError::FileError(format!(
                    "'{path}' already exists as a file"
                )))
            };
        }

        let mut candidate = self.catalog.clone();
        for ancestor in candidate.missing_ancestors(path)? {
            candidate.insert(FileEntry::new_directory(ancestor.to_string())?)?;
        }
        candidate.insert(FileEntry::new_directory(path.to_string())?)?;
        let prepared = self.prepare_catalog(candidate)?;
        self.commit_catalog(prepared)
    }

    /// Streams authenticated plaintext to `writer`.
    ///
    /// Each chunk is authenticated before it is written. If a later chunk fails,
    /// earlier verified bytes may already be in the writer, and a general writer
    /// gives us no way to take them back. Use [`Self::extract_file_to_path`] when
    /// the requested output filename should appear only after the whole file
    /// passes authentication. That method also refuses to replace existing files.
    /// This method does not flush the writer.
    /// Internal plaintext buffers are wiped on drop; callers are responsible
    /// for erasing any plaintext retained by their writer.
    ///
    /// # Errors
    ///
    /// Fails if `path` is absent or names a directory, a record cannot be read
    /// or authenticated, or the writer fails.
    pub fn extract_file_to_writer<W: Write>(
        &self,
        path: &str,
        writer: &mut W,
    ) -> Result<(), VaultError> {
        self.ensure_readable()?;
        let entry = self
            .catalog
            .find(path)
            .ok_or_else(|| VaultError::FileError(format!("'{path}' not found")))?;
        if entry.kind != EntryKind::File {
            return Err(VaultError::FileError(format!("'{path}' is a directory")));
        }

        let content = self.content_reader()?;
        for logical in 0..entry.num_chunks {
            let plaintext = content.read_chunk(entry, logical)?;
            writer.write_all(&plaintext).map_err(|error| {
                VaultError::FileError(format!("failed to write extracted data: {error}"))
            })?;
        }
        Ok(())
    }

    /// Returns an owned plaintext buffer that is wiped on drop, including when
    /// extraction fails after reading part of the file. Copies made by the
    /// caller need their own cleanup. For large files, use [`Self::extract_file_to_writer`].
    ///
    /// # Errors
    ///
    /// Files larger than 256 MiB are rejected. Other errors follow
    /// [`Self::extract_file_to_writer`].
    pub fn extract_file(&self, path: &str) -> Result<Plaintext, VaultError> {
        self.ensure_readable()?;
        let size = self
            .catalog
            .find(path)
            .ok_or_else(|| VaultError::FileError(format!("'{path}' not found")))?
            .size;
        if size > MAX_IN_MEMORY_EXTRACTION {
            return Err(VaultError::FileError(format!(
                "file exceeds the {MAX_IN_MEMORY_EXTRACTION}-byte in-memory extraction limit; use a streaming or path extraction API"
            )));
        }
        let capacity: usize = size
            .try_into()
            .map_err(|_| VaultError::FileError("file is too large for memory".to_string()))?;
        // We know the full file size from the authenticated catalog, so allocate
        // enough memory before copying plaintext. If the Vec grew later, it could
        // free its old allocation without erasing the plaintext left there.
        let mut output = Zeroizing::new(Vec::with_capacity(capacity));
        self.extract_file_to_writer(path, &mut *output)?;
        Ok(output)
    }

    /// Lists all files and directories, sorted by their vault paths.
    ///
    /// Reads the authenticated in-memory catalog without reading file data.
    pub fn list_files(&self) -> Result<Vec<FileInfo>, VaultError> {
        self.ensure_readable()?;
        Ok(self
            .catalog
            .entries()
            .map(|entry| FileInfo {
                path: entry.path.clone(),
                size: entry.size,
                is_directory: entry.kind == EntryKind::Directory,
            })
            .collect())
    }

    /// Returns catalog information for the exact vault path supplied.
    ///
    /// Returns an error if the entry does not exist or the volume is poisoned.
    pub fn stat(&self, path: &str) -> Result<FileInfo, VaultError> {
        self.ensure_readable()?;
        let entry = self
            .catalog
            .find(path)
            .ok_or_else(|| VaultError::FileError(format!("'{path}' not found")))?;
        Ok(FileInfo {
            path: entry.path.clone(),
            size: entry.size,
            is_directory: entry.kind == EntryKind::Directory,
        })
    }

    /// Lists a directory, then everything inside it sorted by vault path.
    ///
    /// Returns an error if `path` is absent or names a file, or the volume is
    /// poisoned. The returned list includes the requested directory itself.
    pub fn list_subtree(&self, path: &str) -> Result<Vec<FileInfo>, VaultError> {
        self.ensure_readable()?;
        let root = self
            .catalog
            .find(path)
            .ok_or_else(|| VaultError::FileError(format!("'{path}' not found")))?;
        if root.kind != EntryKind::Directory {
            return Err(VaultError::FileError(format!(
                "'{path}' is not a directory"
            )));
        }
        let mut entries = Vec::new();
        entries.push(FileInfo {
            path: root.path.clone(),
            size: 0,
            is_directory: true,
        });
        entries.extend(self.catalog.descendants(path).map(|entry| FileInfo {
            path: entry.path.clone(),
            size: entry.size,
            is_directory: entry.kind == EntryKind::Directory,
        }));
        Ok(entries)
    }

    /// Removes a file or directory from the catalog and frees its data space.
    ///
    /// Nonempty directories require `recursive`; files and empty directories
    /// can be removed with either value. Removal does not overwrite old
    /// ciphertext or erase copies retained in backups.
    ///
    /// # Errors
    ///
    /// Fails if `path` does not exist, a nonempty directory is removed without
    /// `recursive`, or the catalog cannot be saved.
    pub fn remove(&mut self, path: &str, recursive: bool) -> Result<(), VaultError> {
        self.ensure_writable()?;
        let entry = self
            .catalog
            .find(path)
            .ok_or_else(|| VaultError::FileError(format!("'{path}' not found")))?;
        let mut candidate = self.catalog.clone();

        if entry.kind == EntryKind::Directory {
            let descendants: Vec<&str> = self
                .catalog
                .descendants(path)
                .map(|entry| entry.path.as_str())
                .collect();
            if !recursive && !descendants.is_empty() {
                return Err(VaultError::FileError(format!(
                    "'{path}' is not empty; recursive removal is required"
                )));
            }
            for descendant in descendants.into_iter().rev() {
                candidate.remove(descendant);
            }
        }
        candidate.remove(path);
        let prepared = self.prepare_catalog(candidate)?;
        // The other catalog copy may still point to this file's chunks. Wait
        // until both copies are saved before making those chunks free to reuse.
        self.commit_catalog(prepared)
    }

    /// Checks the authentication of every file chunk in the current catalog.
    ///
    /// Decrypted chunks are erased after checking. Unused chunks and old
    /// copies are not inspected. This works on read-only volumes and does not
    /// modify or repair the vault.
    ///
    /// # Errors
    ///
    /// Stops at the first chunk that cannot be read, fails authentication, or
    /// has invalid contents. No partial success report is returned.
    pub fn verify(&self) -> Result<VerificationReport, VaultError> {
        self.ensure_readable()?;
        let mut report = VerificationReport {
            files_verified: 0,
            bytes_verified: 0,
            chunks_verified: 0,
        };
        let content = self.content_reader()?;
        for entry in self
            .catalog
            .entries()
            .filter(|entry| entry.kind == EntryKind::File)
        {
            for logical in 0..entry.num_chunks {
                content.read_chunk(entry, logical)?;
                report.chunks_verified += 1;
            }
            report.files_verified += 1;
            report.bytes_verified = report
                .bytes_verified
                .checked_add(entry.size)
                .ok_or_else(|| VaultError::corrupt("verification byte count overflow"))?;
        }
        Ok(report)
    }
}
