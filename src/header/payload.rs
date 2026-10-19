use getrandom::fill;
use zeroize::Zeroizing;

use super::{CONTAINER_ID_LEN, DATA_AREA_OFFSET};
use crate::{cipher::CipherId, errors::VaultError, secret_key::SecretKey};

const PAYLOAD_MAGIC: [u8; 8] = *b"LUNAPAY1";
const PAYLOAD_VERSION: u16 = 1;
const PAYLOAD_MIN_VERSION: u16 = 1;
pub(super) const PAYLOAD_LEN: usize = 256;

/// The copyable fields of the header, separate from the protected master key.
/// Includes:
///
/// - Cipher ID: which algorithm encrypts headers, file contents, and the catalog.
/// - Chunk size: how many plaintext bytes fit in each chunk.
/// - Data chunk count: chunks reserved for file contents, including unused ones.
/// - Metadata copy chunks: chunks reserved for each catalog copy. The catalog
///   stores filenames, file locations, and other file information.
/// - Container ID: a random identifier included in associated data, so encrypted
///   file and catalog chunks must match the vault they're being read from.
///
/// There are two catalog copies as well as the two header copies. The catalog
/// copies are stored separately; see `volume/metadata.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeaderFields {
    pub cipher_id: CipherId,
    pub chunk_size: u32,
    pub data_chunk_count: u64,
    pub metadata_copy_chunks: u64,
    pub container_id: [u8; CONTAINER_ID_LEN],
}

// Keep the copyable header fields separate from the protected master key,
// so callers can pass around fields without retaining the key.
pub(crate) struct HeaderPayload {
    fields: HeaderFields,
    master_key: SecretKey,
}

impl HeaderPayload {
    pub(crate) fn create(
        cipher_id: CipherId,
        chunk_size: u32,
        data_chunk_count: u64,
        metadata_copy_chunks: u64,
    ) -> Result<Self, VaultError> {
        let mut container_id = [0u8; CONTAINER_ID_LEN];
        // The vault's random master key is stored in the header payload.
        // A key derived from the user's password encrypts that payload.
        // Changing the password encrypts the payload again but keeps the same
        // master key, so existing file data doesn't need to be re-encrypted.
        // If the master key is exposed, changing the password won't protect
        // the contents. They need to be moved into a vault with a new master key.
        let mut master_key = SecretKey::zeroed()?;
        fill(&mut container_id)
            .map_err(|_| VaultError::CryptoError("failed to generate container id".to_string()))?;
        fill(master_key.expose_secret_mut())
            .map_err(|_| VaultError::CryptoError("failed to generate master key".to_string()))?;
        Ok(Self {
            fields: HeaderFields {
                cipher_id,
                chunk_size,
                data_chunk_count,
                metadata_copy_chunks,
                container_id,
            },
            master_key,
        })
    }

    pub(crate) fn fields(&self) -> HeaderFields {
        self.fields
    }

    pub(crate) fn master_key(&self) -> &SecretKey {
        &self.master_key
    }

    pub(super) fn equivalent(&self, other: &Self) -> bool {
        self.fields == other.fields
            && self.master_key.expose_secret() == other.master_key.expose_secret()
    }

    pub(super) fn to_bytes(&self, generation: u64) -> Box<Zeroizing<[u8; PAYLOAD_LEN]>> {
        let mut bytes = Box::new(Zeroizing::new([0u8; PAYLOAD_LEN]));
        bytes[0..8].copy_from_slice(&PAYLOAD_MAGIC);
        bytes[8..10].copy_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&PAYLOAD_MIN_VERSION.to_be_bytes());
        bytes[12..20].copy_from_slice(&generation.to_be_bytes());
        bytes[20] = self.fields.cipher_id as u8;
        // bytes 21..24 are reserved.
        bytes[24..28].copy_from_slice(&self.fields.chunk_size.to_be_bytes());
        bytes[28..36].copy_from_slice(&self.fields.data_chunk_count.to_be_bytes());
        bytes[36..44].copy_from_slice(&self.fields.metadata_copy_chunks.to_be_bytes());
        bytes[44..52].copy_from_slice(&DATA_AREA_OFFSET.to_be_bytes());
        // bytes 52..60 are flags and are currently zero.
        bytes[60..76].copy_from_slice(&self.fields.container_id);
        bytes[76..108].copy_from_slice(self.master_key.expose_secret());
        bytes
    }

    pub(super) fn from_bytes(
        bytes: &[u8; PAYLOAD_LEN],
        expected_generation: u64,
    ) -> Result<Self, VaultError> {
        if bytes[0..8] != PAYLOAD_MAGIC {
            return Err(VaultError::corrupt("invalid encrypted header magic"));
        }
        let version = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed slice"));
        let min_version = u16::from_be_bytes(bytes[10..12].try_into().expect("fixed slice"));
        if version != PAYLOAD_VERSION || min_version != PAYLOAD_MIN_VERSION {
            return Err(VaultError::corrupt("unsupported encrypted header version"));
        }
        let generation = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed slice"));
        if generation != expected_generation || generation == 0 {
            return Err(VaultError::corrupt("header generation mismatch"));
        }
        if bytes[21..24].iter().any(|byte| *byte != 0) {
            return Err(VaultError::corrupt(
                "non-zero encrypted header reserved bytes",
            ));
        }
        if bytes[52..60].iter().any(|byte| *byte != 0) {
            return Err(VaultError::corrupt("unsupported encrypted header flags"));
        }
        // We write these unused bytes as zeros. Reject anything else rather
        // than silently accepting data this format doesn't define.
        if bytes[108..].iter().any(|byte| *byte != 0) {
            return Err(VaultError::corrupt("non-zero encrypted header padding"));
        }
        let data_area_offset = u64::from_be_bytes(bytes[44..52].try_into().expect("fixed slice"));
        if data_area_offset != DATA_AREA_OFFSET {
            return Err(VaultError::corrupt("invalid data-area offset"));
        }

        let cipher_id = CipherId::try_from(bytes[20])?;
        let chunk_size = u32::from_be_bytes(bytes[24..28].try_into().expect("fixed slice"));
        let data_chunk_count = u64::from_be_bytes(bytes[28..36].try_into().expect("fixed slice"));
        let metadata_copy_chunks =
            u64::from_be_bytes(bytes[36..44].try_into().expect("fixed slice"));
        let container_id: [u8; CONTAINER_ID_LEN] = bytes[60..76].try_into().expect("fixed slice");
        if container_id.iter().all(|byte| *byte == 0) {
            return Err(VaultError::corrupt("zero container identity"));
        }
        let mut master_key = SecretKey::zeroed()?;
        master_key
            .expose_secret_mut()
            .copy_from_slice(&bytes[76..108]);
        Ok(Self {
            fields: HeaderFields {
                cipher_id,
                chunk_size,
                data_chunk_count,
                metadata_copy_chunks,
                container_id,
            },
            master_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_bytes_match_the_expected_storage_format() {
        let mut master_key = SecretKey::zeroed().unwrap();
        master_key.expose_secret_mut().fill(0x22);
        let mut payload = HeaderPayload {
            fields: HeaderFields {
                cipher_id: CipherId::XChaCha20Poly1305,
                chunk_size: 4096,
                data_chunk_count: 3,
                metadata_copy_chunks: 257,
                container_id: [0x11; CONTAINER_ID_LEN],
            },
            master_key,
        };

        // The format fixes the payload at 256 bytes; unused bytes stay zero.
        let mut expected = [0u8; 256];
        expected[0..8].copy_from_slice(b"LUNAPAY1"); // Payload signature.
        expected[8..12].copy_from_slice(&[0, 1, 0, 1]); // Version 1, minimum version 1.
        expected[12..20].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 9]); // Update number (generation) 9.
        expected[24..28].copy_from_slice(&[0, 0, 16, 0]); // 4096 plaintext bytes per chunk.
        expected[28..36].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 3]); // 3 file-data chunks.
        expected[36..44].copy_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1]); // 257 chunks per catalog copy.
        expected[44..52].copy_from_slice(&[0, 0, 0, 0, 0, 0, 32, 0]); // Catalog/file storage starts at byte 8192.
        expected[60..76].fill(0x11); // 16-byte container ID.
        expected[76..108].fill(0x22); // 32-byte master key.

        for (cipher_id, encoded_cipher_id) in [
            (CipherId::XChaCha20Poly1305, 1),
            (CipherId::Aes256GcmSiv, 2),
        ] {
            payload.fields.cipher_id = cipher_id;
            expected[20] = encoded_cipher_id;
            assert_eq!(**payload.to_bytes(9), expected);
            let decoded = HeaderPayload::from_bytes(&expected, 9).unwrap();
            assert!(decoded.equivalent(&payload));
        }
    }

    #[test]
    fn payload_decoding_rejects_invalid_fields() {
        for cipher_id in crate::test_support::TEST_CIPHERS {
            let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
            let original = payload.to_bytes(1);
            for (offset, value) in [
                (20, 0),   // Missing algorithm marker.
                (20, 3),   // Unknown algorithm.
                (20, 4),   // Unknown algorithm.
                (20, 255), // Unknown algorithm.
                (11, 0),   // Invalid minimum payload version.
                (21, 1),   // Reserved bytes.
                (52, 1),   // Unsupported flags.
                (108, 1),  // Padding.
            ] {
                let mut bytes = original.clone();
                bytes[offset] = value;
                assert!(HeaderPayload::from_bytes(&bytes, 1).is_err());
            }
            assert!(HeaderPayload::from_bytes(&original, 2).is_err());
        }
    }
}
