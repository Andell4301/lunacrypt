use std::fs::File;

use zeroize::Zeroizing;

use crate::{
    cipher::{Cipher, NONCE_STORAGE_SIZE, TAG_SIZE},
    errors::VaultError,
    header::{CONTAINER_ID_LEN, DATA_AREA_OFFSET},
    io::{read_exact_at, write_all_at},
};

pub(super) const RECORD_NONCE_LEN: usize = NONCE_STORAGE_SIZE;
pub(super) const RECORD_TAG_LEN: usize = TAG_SIZE;
const DATA_AAD_DOMAIN: &[u8] = b"lunacrypt-v1-file-data-record";
const METADATA_AAD_DOMAIN: &[u8] = b"lunacrypt-v1-metadata-record";

/// Size of one stored chunk, including its nonce and authentication tag.
/// This complete bundle is called a record.
pub(super) fn record_size(chunk_size: u32) -> Result<u64, VaultError> {
    u64::from(chunk_size)
        .checked_add((RECORD_NONCE_LEN + RECORD_TAG_LEN) as u64)
        .ok_or_else(|| VaultError::corrupt("record size overflow"))
}

/// Total vault-file size: both headers plus all stored chunks.
/// `total_physical_chunks` includes both catalog copies and the file-data area.
pub(super) fn expected_file_len(
    total_physical_chunks: u64,
    chunk_size: u32,
) -> Result<u64, VaultError> {
    DATA_AREA_OFFSET
        .checked_add(
            total_physical_chunks
                .checked_mul(record_size(chunk_size)?)
                .ok_or_else(|| VaultError::corrupt("vault length overflow"))?,
        )
        .ok_or_else(|| VaultError::corrupt("vault length overflow"))
}

/// Byte offset where a stored chunk begins in the vault file.
/// Chunk numbers start at zero after the two headers and include catalog chunks.
pub(super) fn record_offset(physical_chunk: u64, chunk_size: u32) -> Result<u64, VaultError> {
    DATA_AREA_OFFSET
        .checked_add(
            physical_chunk
                .checked_mul(record_size(chunk_size)?)
                .ok_or_else(|| VaultError::corrupt("chunk offset overflow"))?,
        )
        .ok_or_else(|| VaultError::corrupt("chunk offset overflow"))
}

/// Builds the associated data for a file chunk. These are the details we expect
/// the chunk to belong to: its vault, file, position within the file, position
/// in the vault, and chunk size.
///
/// We supply the same details when encrypting and decrypting. So, copying an
/// encrypted chunk to another position won't pass the check for that position.
/// The caller gets these details from the header and catalog, rather than
/// trusting the chunk to tell us where it belongs. They don't need to be secret.
pub(super) fn data_chunk_aad(
    container_id: &[u8; CONTAINER_ID_LEN],
    file_id: &[u8; 16],
    logical_chunk: u64,
    physical_chunk: u64,
    chunk_size: u32,
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(DATA_AAD_DOMAIN.len() + CONTAINER_ID_LEN + file_id.len() + 8 + 8 + 4);
    aad.extend_from_slice(DATA_AAD_DOMAIN);
    aad.extend_from_slice(container_id);
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&logical_chunk.to_be_bytes());
    aad.extend_from_slice(&physical_chunk.to_be_bytes());
    aad.extend_from_slice(&chunk_size.to_be_bytes());
    aad
}

/// Builds the associated data for a catalog chunk. This works like the file
/// chunk check, but identifies a catalog copy instead of a file.
/// The copy number matters: the two copies hold the same catalog, but each
/// must be encrypted for its own position. Copying encrypted bytes from one
/// to the other would fail authentication.
pub(super) fn metadata_chunk_aad(
    container_id: &[u8; CONTAINER_ID_LEN],
    copy_slot: usize,
    logical_chunk: u64,
    physical_chunk: u64,
    chunk_size: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(METADATA_AAD_DOMAIN.len() + CONTAINER_ID_LEN + 1 + 8 + 8 + 4);
    aad.extend_from_slice(METADATA_AAD_DOMAIN);
    aad.extend_from_slice(container_id);
    aad.push(copy_slot as u8); // Which of the two catalog copies.
    aad.extend_from_slice(&logical_chunk.to_be_bytes());
    aad.extend_from_slice(&physical_chunk.to_be_bytes());
    aad.extend_from_slice(&chunk_size.to_be_bytes());
    aad
}

fn record_aad(context: &[u8], nonce: &[u8]) -> Vec<u8> {
    // All 24 stored nonce bytes are random so their appearance doesn't tell
    // someone which cipher we used. AES only uses the first 12 as its nonce,
    // so include the whole field here to catch changes to the extra bytes too.
    let mut aad = Vec::with_capacity(context.len() + nonce.len());
    aad.extend_from_slice(context);
    aad.extend_from_slice(nonce);
    aad
}

/// Encrypts one full chunk and writes its nonce, encrypted bytes, and tag.
/// The caller must pad a partial chunk before passing it here.
pub(super) fn write_record(
    file: &File,
    cipher: &Cipher,
    chunk_size: u32,
    physical_chunk: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(), VaultError> {
    if plaintext.len() != chunk_size as usize {
        return Err(VaultError::CryptoError(
            "record plaintext has the wrong length".to_string(),
        ));
    }
    let nonce = cipher.generate_nonce()?;
    let aad = record_aad(aad, &nonce);
    let encrypted = cipher.encrypt(&nonce[..cipher.nonce_size()], &aad, plaintext)?;
    if encrypted.len() != chunk_size as usize + RECORD_TAG_LEN {
        return Err(VaultError::CryptoError(
            "record cipher returned an unexpected length".to_string(),
        ));
    }

    let mut record = vec![0u8; RECORD_NONCE_LEN + encrypted.len()];
    record[..nonce.len()].copy_from_slice(&nonce);
    record[RECORD_NONCE_LEN..].copy_from_slice(&encrypted);
    write_all_at(file, &record, record_offset(physical_chunk, chunk_size)?)
}

/// Reads a stored chunk and checks its expected context and authentication tag.
/// The returned plaintext is wiped when dropped.
pub(super) fn read_record(
    file: &File,
    cipher: &Cipher,
    chunk_size: u32,
    physical_chunk: u64,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let record_len = RECORD_NONCE_LEN
        .checked_add(chunk_size as usize)
        .and_then(|value| value.checked_add(RECORD_TAG_LEN))
        .ok_or_else(|| VaultError::corrupt("record length overflow"))?;
    let mut record = vec![0u8; record_len];
    read_exact_at(
        file,
        record.as_mut_slice(),
        record_offset(physical_chunk, chunk_size)?,
    )?;

    let nonce_len = cipher.nonce_size();
    let aad = record_aad(aad, &record[..RECORD_NONCE_LEN]);
    // The record above is still encrypted. Decrypt puts the plaintext in a
    // separate buffer that is wiped on failure or when the returned value is dropped.
    let plaintext = cipher
        .decrypt(&record[..nonce_len], &aad, &record[RECORD_NONCE_LEN..])
        .map_err(|_| VaultError::corrupt("record authentication failed"))?;
    if plaintext.len() != chunk_size as usize {
        return Err(VaultError::corrupt("decrypted record has the wrong length"));
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secret_key::SecretKey,
        test_support::{TEST_CIPHERS, TestPath},
    };

    #[test]
    fn written_chunks_can_be_read_back() {
        let path = TestPath::file("record-read-back");
        let file = path.create_file();
        file.set_len(expected_file_len(2, 4096).unwrap()).unwrap();
        for id in TEST_CIPHERS {
            let mut key = SecretKey::zeroed().unwrap();
            key.expose_secret_mut().fill(7);
            let cipher = Cipher::new(id, key);
            let aad = data_chunk_aad(&[1u8; 16], &[2u8; 16], 0, 0, 4096);
            let plaintext = [3u8; 4096];
            write_record(&file, &cipher, 4096, 0, &aad, &plaintext).unwrap();
            let mut stored_nonce = [0u8; RECORD_NONCE_LEN];
            read_exact_at(&file, &mut stored_nonce, record_offset(0, 4096).unwrap()).unwrap();
            assert_ne!(stored_nonce[12..], [0u8; 12]);
            assert_eq!(
                read_record(&file, &cipher, 4096, 0, &aad)
                    .unwrap()
                    .as_slice(),
                plaintext
            );
        }
        drop(file);
    }

    #[test]
    fn reading_rejects_a_wrong_expected_chunk_position() {
        let path = TestPath::file("record-position");
        let file = path.create_file();
        file.set_len(expected_file_len(2, 4096).unwrap()).unwrap();
        for id in TEST_CIPHERS {
            let mut key = SecretKey::zeroed().unwrap();
            key.expose_secret_mut().fill(7);
            let cipher = Cipher::new(id, key);
            let aad = data_chunk_aad(&[1u8; 16], &[2u8; 16], 0, 0, 4096);
            let plaintext = [3u8; 4096];
            write_record(&file, &cipher, 4096, 0, &aad, &plaintext).unwrap();

            let wrong_position_aad = data_chunk_aad(&[1u8; 16], &[2u8; 16], 0, 1, 4096);
            assert!(read_record(&file, &cipher, 4096, 0, &wrong_position_aad).is_err());
        }
        drop(file);
    }

    #[test]
    fn reading_rejects_changes_to_stored_nonce_bytes() {
        let path = TestPath::file("record-nonce");
        let file = path.create_file();
        file.set_len(expected_file_len(2, 4096).unwrap()).unwrap();
        for id in TEST_CIPHERS {
            let mut key = SecretKey::zeroed().unwrap();
            key.expose_secret_mut().fill(7);
            let cipher = Cipher::new(id, key);
            let aad = data_chunk_aad(&[1u8; 16], &[2u8; 16], 0, 0, 4096);
            let plaintext = [3u8; 4096];
            write_record(&file, &cipher, 4096, 0, &aad, &plaintext).unwrap();

            // Change one actual nonce byte for each cipher.
            let mut indices = vec![0];
            if cipher.nonce_size() < RECORD_NONCE_LEN {
                // Also change the first and last extra bytes stored for AES.
                indices.push(cipher.nonce_size());
                indices.push(RECORD_NONCE_LEN - 1);
            }
            for index in indices {
                let offset = record_offset(0, 4096).unwrap() + index as u64;
                let mut byte = [0u8];
                read_exact_at(&file, &mut byte, offset).unwrap();
                byte[0] ^= 1;
                write_all_at(&file, &byte, offset).unwrap();
                assert!(matches!(
                    read_record(&file, &cipher, 4096, 0, &aad),
                    Err(VaultError::Corrupt(message)) if message == "record authentication failed"
                ));
                byte[0] ^= 1;
                write_all_at(&file, &byte, offset).unwrap();
            }
        }
        drop(file);
    }
}
