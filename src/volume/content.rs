//! Reads and checks file contents for extraction, verification, and previews.

use std::fs::File;

use super::{
    Volume,
    chunk_io::{data_chunk_aad, read_record},
    file_table::{EntryKind, FileEntry},
    geometry::file_data_start_chunk,
};
use crate::{Plaintext, cipher::Cipher, errors::VaultError, header::CONTAINER_ID_LEN};

/// Reads the file-data area using borrowed keys and file handles.
/// Preview readers keep their session guard until the read finishes. Otherwise,
/// closing or changing the volume could release the key while it is in use.
pub(super) struct ContentReader<'a> {
    file: &'a File,
    cipher: &'a Cipher,
    container_id: &'a [u8; CONTAINER_ID_LEN],
    chunk_size: u32,
    region_start: u64,
    chunk_count: u64,
}

impl<'a> ContentReader<'a> {
    pub(super) fn new(
        file: &'a File,
        cipher: &'a Cipher,
        container_id: &'a [u8; CONTAINER_ID_LEN],
        chunk_size: u32,
        region_start: u64,
        chunk_count: u64,
    ) -> Self {
        Self {
            file,
            cipher,
            container_id,
            chunk_size,
            region_start,
            chunk_count,
        }
    }

    /// Checks that the chunk is inside the file and data area, then authenticates
    /// its file ID and position. Checks the final chunk's zero padding and
    /// returns only bytes belonging to the file.
    pub(super) fn read_chunk(
        &self,
        entry: &FileEntry,
        logical: u64,
    ) -> Result<Plaintext, VaultError> {
        if entry.kind != EntryKind::File || logical >= entry.num_chunks {
            return Err(VaultError::corrupt(format!(
                "file '{}' has an invalid chunk extent",
                entry.path
            )));
        }
        let relative = entry
            .start_chunk
            .checked_add(logical)
            .ok_or_else(|| VaultError::corrupt("file chunk index overflow"))?;
        if relative >= self.chunk_count {
            return Err(VaultError::corrupt(format!(
                "file '{}' points outside the data region",
                entry.path
            )));
        }
        let physical = self
            .region_start
            .checked_add(relative)
            .ok_or_else(|| VaultError::corrupt("physical data chunk overflow"))?;
        let aad = data_chunk_aad(
            self.container_id,
            &entry.file_id,
            logical,
            physical,
            self.chunk_size,
        );
        let mut plaintext = read_record(self.file, self.cipher, self.chunk_size, physical, &aad)
            .map_err(|error| match error {
                VaultError::Corrupt(message) => VaultError::corrupt(format!(
                    "file '{}', logical chunk {logical}: {message}",
                    entry.path
                )),
                other => other,
            })?;
        let used = validated_plaintext_len(
            &entry.path,
            entry.size,
            logical,
            entry.num_chunks,
            self.chunk_size,
            &plaintext,
        )?;
        plaintext.truncate(used);
        Ok(plaintext)
    }
}

impl Volume {
    pub(super) fn content_reader(&self) -> Result<ContentReader<'_>, VaultError> {
        Ok(ContentReader::new(
            &self.file,
            &self.data_cipher,
            &self.container_id,
            self.chunk_size,
            file_data_start_chunk(self.metadata_copy_chunks)?,
            self.data_chunk_count,
        ))
    }
}

/// Checks that a decrypted chunk matches the file size and chunk count in the
/// catalog. Returns how many bytes belong to the file, excluding zero padding.
fn validated_plaintext_len(
    path: &str,
    file_size: u64,
    logical_chunk: u64,
    num_chunks: u64,
    chunk_size: u32,
    plaintext: &[u8],
) -> Result<usize, VaultError> {
    if logical_chunk >= num_chunks || plaintext.len() != chunk_size as usize {
        return Err(VaultError::corrupt(format!(
            "file '{path}' has an invalid chunk extent"
        )));
    }

    let chunk_start = logical_chunk
        .checked_mul(u64::from(chunk_size))
        .ok_or_else(|| VaultError::corrupt("file chunk offset overflow"))?;
    let remaining = file_size.checked_sub(chunk_start).ok_or_else(|| {
        VaultError::corrupt(format!("file '{path}' has an extent longer than its size"))
    })?;
    let used = remaining.min(u64::from(chunk_size)) as usize;
    let is_final = logical_chunk + 1 == num_chunks;

    if (!is_final && used != chunk_size as usize) || (is_final && remaining > u64::from(chunk_size))
    {
        return Err(VaultError::corrupt(format!(
            "file '{path}' has an extent inconsistent with its size"
        )));
    }
    // Every stored chunk has the same size, but a file's final chunk can be
    // partly empty. The extra bytes are authenticated too, but the file format
    // also requires them to be zero. Check that before removing the padding.
    if is_final && plaintext[used..].iter().any(|byte| *byte != 0) {
        return Err(VaultError::corrupt(format!(
            "non-zero padding in the final chunk of '{path}'"
        )));
    }
    Ok(used)
}
