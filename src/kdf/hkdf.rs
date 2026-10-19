use hkdf::Hkdf;
use sha2::Sha256;

use crate::{errors::VaultError, secret_key::SecretKey};

/// Names the job a derived key will do. Each name has a different fixed label,
/// so the same input key produces separate keys for encryption, authentication,
/// file data, and the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDomain {
    HeaderEncryption,
    HeaderAuthentication,
    FileData,
    Metadata,
}

impl KeyDomain {
    fn label(self) -> &'static [u8] {
        match self {
            Self::HeaderEncryption => b"lunacrypt-v1-header-encryption",
            Self::HeaderAuthentication => b"lunacrypt-v1-header-authentication",
            Self::FileData => b"lunacrypt-v1-file-data",
            Self::Metadata => b"lunacrypt-v1-metadata",
        }
    }
}

/// Derives a key for one purpose without changing the input key. The same input
/// and purpose always give the same result, so we do not have to store subkeys.
/// The result is locked in memory before any derived bytes are written into it.
pub fn expand_key(master_key: &SecretKey, domain: KeyDomain) -> Result<SecretKey, VaultError> {
    let mut key = SecretKey::zeroed()?;
    let hk = Hkdf::<Sha256>::from_prk(master_key.expose_secret())
        .map_err(|_| VaultError::KdfError("invalid master key length".to_string()))?;
    hk.expand(domain.label(), key.expose_secret_mut())
        .map_err(|_| VaultError::KdfError("failed to derive a vault subkey".to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_key_purpose_produces_a_distinct_repeatable_key() {
        let mut master = SecretKey::zeroed().unwrap();
        master.expose_secret_mut().fill(7);
        let domains = [
            KeyDomain::HeaderEncryption,
            KeyDomain::HeaderAuthentication,
            KeyDomain::FileData,
            KeyDomain::Metadata,
        ];
        let keys: Vec<_> = domains
            .iter()
            .map(|domain| expand_key(&master, *domain).unwrap())
            .collect();

        for (index, key) in keys.iter().enumerate() {
            assert_eq!(
                key.expose_secret(),
                expand_key(&master, domains[index]).unwrap().expose_secret()
            );
            for other in keys.iter().skip(index + 1) {
                assert_ne!(key.expose_secret(), other.expose_secret());
            }
        }
    }
}
