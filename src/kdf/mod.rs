//! Derives keys from passwords and gives existing keys separate purposes.
//! Argon2id combines the password, salt, and stored settings to derive a key.
//! HKDF derives keys for specific jobs: header encryption starts from the
//! password-derived key, while file and catalog encryption start from the
//! vault's random master key.

use crate::{Password, errors::VaultError, secret_key::SecretKey};

mod argon2;
pub mod hkdf;
mod params;

use argon2::{Argon2Kdf, validate_argon2_costs};
pub(crate) use params::{KDF_PARAMS_LEN, KdfParams};

pub const MAX_PASSWORD_LEN: usize = 4096;

impl KdfParams {
    pub(crate) fn validate(self) -> Result<(), VaultError> {
        match self {
            Self::Argon2id {
                memory_cost,
                time_cost,
                parallelism,
            } => validate_argon2_costs(memory_cost, time_cost, parallelism),
        }
    }

    pub(crate) fn derive_key(
        self,
        password: &Password,
        salt: &[u8],
    ) -> Result<SecretKey, VaultError> {
        match self {
            Self::Argon2id {
                memory_cost,
                time_cost,
                parallelism,
            } => Argon2Kdf::new(memory_cost, time_cost, parallelism)?.derive_key(password, salt),
        }
    }

    // Tests use the lowest allowed costs so repeatedly opening disposable vaults
    // does not do as much password-derivation work as the normal defaults.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::Argon2id {
            memory_cost: argon2::MIN_MEMORY_COST_KIB,
            time_cost: argon2::MIN_TIME_COST,
            parallelism: argon2::MIN_PARALLELISM,
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::Argon2id {
            memory_cost: argon2::DEFAULT_MEMORY_COST_KIB,
            time_cost: argon2::DEFAULT_TIME_COST,
            parallelism: argon2::DEFAULT_PARALLELISM,
        }
    }
}

pub fn validate_password_length(password: &Password) -> Result<(), VaultError> {
    let len = secrecy::ExposeSecret::expose_secret(password).len();
    if len == 0 {
        return Err(VaultError::KdfError(
            "password must not be empty".to_string(),
        ));
    }
    if len > MAX_PASSWORD_LEN {
        return Err(VaultError::KdfError(format!(
            "password exceeds the {MAX_PASSWORD_LEN}-byte limit"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::password;

    /// Check our wrapper against known output from the Argon2 library's tests.
    /// Accidentally selecting Argon2i could still produce the same answer on
    /// repeated calls, but it would not produce these expected bytes.
    #[test]
    fn derived_key_matches_the_argon2_reference_output() {
        // https://github.com/RustCrypto/password-hashes/blob/5b6a74e0799955b21c9d3854de1674a78a472648/argon2/tests/kat.rs#L779-L790
        let params = KdfParams::Argon2id {
            memory_cost: 65536,
            time_cost: 1,
            parallelism: 1,
        };
        let password = password(b"password");
        let key = params.derive_key(&password, b"somesalt").unwrap();
        assert_eq!(
            key.expose_secret(),
            &[
                0xf6, 0xa5, 0xad, 0xc1, 0xba, 0x72, 0x3d, 0xdd, 0xef, 0x9b, 0x5a, 0xc1, 0xd4, 0x64,
                0xe1, 0x80, 0xfc, 0xd9, 0xdf, 0xfc, 0x9d, 0x1c, 0xbf, 0x76, 0xcc, 0xa2, 0xfe, 0xd7,
                0x95, 0xd9, 0xca, 0x98,
            ],
        );
    }
}
