//! Stores the password-derivation settings in the header and reads them back.
//! The header needs these settings before it can be decrypted, so their values
//! are checked before deriving a key. `argon2.rs` does the actual derivation.

use crate::errors::VaultError;

// Argon2id uses the first 16 bytes, including the format fields. Keep the rest
// reserved so a future KDF can store different settings in this fixed space.
pub const KDF_PARAMS_LEN: usize = 32;
const KDF_ID_ARGON2ID: u8 = 1;
const KDF_PARAMETER_FORMAT_VERSION: u8 = 1;
const ARGON2ID_PAYLOAD_LEN: u16 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParams {
    Argon2id {
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
    },
}

impl KdfParams {
    pub fn to_bytes(self) -> [u8; KDF_PARAMS_LEN] {
        let mut bytes = [0u8; KDF_PARAMS_LEN];
        let Self::Argon2id {
            memory_cost,
            time_cost,
            parallelism,
        } = self;
        bytes[0] = KDF_ID_ARGON2ID;
        bytes[1] = KDF_PARAMETER_FORMAT_VERSION;
        bytes[2..4].copy_from_slice(&ARGON2ID_PAYLOAD_LEN.to_be_bytes()); // 2-byte settings length.
        bytes[4..8].copy_from_slice(&memory_cost.to_be_bytes()); // 4-byte memory cost in KiB.
        bytes[8..12].copy_from_slice(&time_cost.to_be_bytes()); // 4-byte pass count.
        bytes[12..16].copy_from_slice(&parallelism.to_be_bytes()); // 4-byte lane count.
        bytes
    }

    pub fn from_bytes(bytes: [u8; KDF_PARAMS_LEN]) -> Result<Self, VaultError> {
        if bytes[0] != KDF_ID_ARGON2ID {
            return Err(VaultError::corrupt("unsupported password KDF"));
        }
        if bytes[1] != KDF_PARAMETER_FORMAT_VERSION {
            return Err(VaultError::corrupt("unsupported KDF parameter version"));
        }
        if u16::from_be_bytes(bytes[2..4].try_into().expect("fixed slice")) != ARGON2ID_PAYLOAD_LEN
        {
            return Err(VaultError::corrupt("invalid KDF parameter length"));
        }
        // This format leaves the remaining bytes unused. Require zeros so we
        // do not silently accept data we don't know how to interpret.
        if bytes[16..].iter().any(|byte| *byte != 0) {
            return Err(VaultError::corrupt("non-zero reserved KDF bytes"));
        }

        let params = Self::Argon2id {
            memory_cost: u32::from_be_bytes(bytes[4..8].try_into().expect("fixed slice")),
            time_cost: u32::from_be_bytes(bytes[8..12].try_into().expect("fixed slice")),
            parallelism: u32::from_be_bytes(bytes[12..16].try_into().expect("fixed slice")),
        };

        // These public header fields have not been authenticated yet. Check the
        // resource limits now, before they can request Argon2 work or memory.
        params.validate()?;
        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_settings_encode_and_decode_the_expected_header_bytes() {
        let params = KdfParams::for_tests();
        let mut expected = [0u8; KDF_PARAMS_LEN];
        expected[..16].copy_from_slice(&[
            1, 1, 0, 12, // Argon2id, format v1, 12-byte parameter payload.
            0, 0, 32, 0, // 8192 KiB of memory.
            0, 0, 0, 1, // One pass over the work memory.
            0, 0, 0, 1, // One lane of work.
        ]);
        assert_eq!(params.to_bytes(), expected);
        assert_eq!(KdfParams::from_bytes(expected).unwrap(), params);
    }

    #[test]
    fn decoding_rejects_nonzero_reserved_bytes_and_excessive_memory_costs() {
        // The final byte is reserved and must stay zero.
        let mut bytes = KdfParams::for_tests().to_bytes();
        bytes[31] = 1;
        assert!(KdfParams::from_bytes(bytes).is_err());

        // A supported format still needs to reject an excessive memory request.
        let mut bytes = KdfParams::for_tests().to_bytes();
        bytes[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(KdfParams::from_bytes(bytes).is_err());
    }
}
