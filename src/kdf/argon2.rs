//! Argon2id turns a password and salt into a key. Its memory and time costs make
//! each password guess expensive. Argon2id is the password KDF used by LunaCrypt.
//!
//! Argon2id combines Argon2i's approach to limiting information leaked through
//! memory accesses with Argon2d's resistance to attacks that trade memory for
//! extra computation. See <https://www.rfc-editor.org/rfc/rfc9106.html#section-1>.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::validate_password_length;
use crate::{
    errors::VaultError,
    secret_key::{KEY_LEN, SecretKey},
};

pub const MIN_MEMORY_COST_KIB: u32 = 8 * 1024;
pub const MAX_MEMORY_COST_KIB: u32 = 128 * 1024;
pub const DEFAULT_MEMORY_COST_KIB: u32 = 64 * 1024;

pub const MIN_TIME_COST: u32 = 1;
pub const MAX_TIME_COST: u32 = 6;
pub const DEFAULT_TIME_COST: u32 = 3;

pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 8;
pub const DEFAULT_PARALLELISM: u32 = 4;

/// Checks the memory, pass count, and lane count against the allowed ranges.
/// Argon2 also needs at least eight memory blocks per lane.
///
/// We read these settings before the header can be authenticated. Without
/// limits, a modified header could request enormous amounts of work or memory
/// before we even check the password. Validate before constructing Argon2.
pub(crate) fn validate_argon2_costs(
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<(), VaultError> {
    if !(MIN_MEMORY_COST_KIB..=MAX_MEMORY_COST_KIB).contains(&memory_cost) {
        return Err(VaultError::KdfError(
            "unsupported Argon2id memory cost".to_string(),
        ));
    }
    if !(MIN_TIME_COST..=MAX_TIME_COST).contains(&time_cost) {
        return Err(VaultError::KdfError(
            "unsupported Argon2id time cost".to_string(),
        ));
    }
    if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&parallelism) {
        return Err(VaultError::KdfError(
            "unsupported Argon2id parallelism".to_string(),
        ));
    }
    if memory_cost < parallelism.saturating_mul(8) {
        return Err(VaultError::KdfError(
            "Argon2id memory cost is too small for its parallelism".to_string(),
        ));
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct Argon2Kdf {
    params: Params,
}

impl Argon2Kdf {
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Result<Self, VaultError> {
        validate_argon2_costs(memory_cost, time_cost, parallelism)?;
        let params = Params::new(memory_cost, time_cost, parallelism, Some(KEY_LEN))
            .map_err(|_| VaultError::KdfError("invalid Argon2id parameters".to_string()))?;
        Ok(Self { params })
    }

    pub(crate) fn derive_key(
        &self,
        password: &SecretBox<Vec<u8>>,
        salt: &[u8],
    ) -> Result<SecretKey, VaultError> {
        validate_password_length(password)?;
        let mut output = SecretKey::zeroed()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());

        // Argon2's workspace contains password-derived data. Its allocating API
        // does not erase that workspace in version 0.5, so own it here inside
        // Zeroizing. It is then wiped on success and on early returns.
        // This workspace is still ordinary memory that the OS can swap out.
        // Reserving first lets us report allocation failure as an error;
        // resize_with then creates the blocks in that already reserved space.
        let mut memory = Zeroizing::new(Vec::<Block>::new());
        memory
            .try_reserve_exact(self.params.block_count())
            .map_err(|_| {
                VaultError::KdfError("failed to allocate Argon2id work memory".to_string())
            })?;
        memory.resize_with(self.params.block_count(), Block::default);

        argon2
            .hash_password_into_with_memory(
                password.expose_secret(),
                salt,
                output.expose_secret_mut(),
                memory.as_mut_slice(),
            )
            .map_err(|_| VaultError::KdfError("failed to derive the password key".to_string()))?;
        Ok(output)
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::new(MIN_MEMORY_COST_KIB, MIN_TIME_COST, MIN_PARALLELISM)
            .expect("minimum test KDF parameters are valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_salt_same_output_and_different_salt_different_output() {
        let kdf = Argon2Kdf::for_tests();
        let password = SecretBox::new(Box::new(b"password".to_vec()));

        let original = kdf.derive_key(&password, b"0123456789abcdef").unwrap();
        let same = kdf.derive_key(&password, b"0123456789abcdef").unwrap();
        let different = kdf.derive_key(&password, b"fedcba9876543210").unwrap();
        assert_eq!(original.expose_secret(), same.expose_secret());
        assert_ne!(original.expose_secret(), different.expose_secret());
    }

    #[test]
    fn rejects_argon2_costs_outside_the_allowed_ranges() {
        assert!(Argon2Kdf::new(MAX_MEMORY_COST_KIB + 1, 1, 1).is_err());
        assert!(Argon2Kdf::new(MIN_MEMORY_COST_KIB, MAX_TIME_COST + 1, 1).is_err());
        assert!(Argon2Kdf::new(MIN_MEMORY_COST_KIB, 1, MAX_PARALLELISM + 1).is_err());
        assert!(Argon2Kdf::new(0, 1, 1).is_err());
        assert!(Argon2Kdf::new(MIN_MEMORY_COST_KIB, 0, 1).is_err());
        assert!(Argon2Kdf::new(MIN_MEMORY_COST_KIB, 1, 0).is_err());
    }

    #[test]
    fn rejects_invalid_password_lengths() {
        let kdf = Argon2Kdf::for_tests();
        for bytes in [Vec::new(), vec![b'x'; crate::kdf::MAX_PASSWORD_LEN + 1]] {
            let password = SecretBox::new(Box::new(bytes));
            assert!(kdf.derive_key(&password, b"0123456789abcdef").is_err());
        }
    }
}
