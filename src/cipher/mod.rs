use std::fmt;

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce as AesNonce,
    aead::{AeadInOut, KeyInit as _},
};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use zeroize::Zeroizing;

use crate::{Plaintext, errors::VaultError, secret_key::SecretKey};

pub(crate) const NONCE_STORAGE_SIZE: usize = 24;
// Both ciphers append a 16-byte authentication tag to the encrypted bytes.
// Decryption checks it to detect a wrong key or changes to the protected data.
pub(crate) const TAG_SIZE: usize = 16;

/// Supported cipher algorithms.
///
/// Both options encrypt the plaintext and authenticate it along with extra
/// context, called associated data. That context is checked without being
/// encrypted; the vault uses it to check where each chunk belongs.
///
/// XChaCha20-Poly1305 is the default. Its 192-bit nonces make accidental repeats
/// extremely unlikely when we generate a fresh random nonce for each operation.
///
/// <https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction>
///
/// AES-256-GCM-SIV is the AES option. It makes two passes during encryption, but
/// avoids AES-GCM's catastrophic failure if a nonce repeats. Repeats can still
/// reveal whether messages are equal, so we still generate fresh random nonces.
/// Its per-key usage limits and other requirements are described in SECURITY.md.
///
/// <https://www.rfc-editor.org/rfc/rfc8452.html#section-1>
///
/// <https://www.rfc-editor.org/rfc/rfc8452.html#section-9>
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum CipherId {
    /// XChaCha20-Poly1305 with 256-bit keys and 192-bit nonces; the default.
    #[default]
    XChaCha20Poly1305 = 1,
    /// AES-256-GCM-SIV with 256-bit keys and 96-bit nonces.
    Aes256GcmSiv = 2,
}

impl CipherId {
    pub(crate) const fn nonce_size(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            Self::Aes256GcmSiv => 12,
        }
    }
}

impl TryFrom<u8> for CipherId {
    type Error = VaultError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305),
            2 => Ok(Self::Aes256GcmSiv),
            _ => Err(VaultError::corrupt(format!(
                "unsupported cipher identifier: {value}"
            ))),
        }
    }
}

impl From<CipherId> for u8 {
    fn from(value: CipherId) -> Self {
        value as Self
    }
}

impl fmt::Display for CipherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Aes256GcmSiv => "AES-256-GCM-SIV",
        })
    }
}

pub(crate) struct Cipher {
    id: CipherId,
    key: SecretKey,
}

impl Cipher {
    pub(crate) fn new(id: CipherId, key: SecretKey) -> Self {
        Self { id, key }
    }

    pub(crate) fn nonce_size(&self) -> usize {
        self.id.nonce_size()
    }

    pub(crate) fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        if nonce.len() != self.nonce_size() {
            return Err(VaultError::CryptoError("invalid nonce length".to_string()));
        }
        let capacity = plaintext
            .len()
            .checked_add(TAG_SIZE)
            .ok_or_else(|| VaultError::CryptoError("plaintext is too large".to_string()))?;

        // Leave room for the tag before copying plaintext. If the Vec had to
        // grow later, it could free an old allocation without erasing the
        // plaintext there. Zeroizing can only wipe the allocation it still owns.
        let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
        buffer.extend_from_slice(plaintext);

        // The original key stays in its locked mapping. The library borrows it
        // to build temporary cipher state for this call, instead of us keeping
        // that state between calls. SecretKey's lock does not cover those
        // temporary values.
        match self.id {
            CipherId::XChaCha20Poly1305 => {
                XChaCha20Poly1305::new(Key::from_slice(self.key.expose_secret()))
                    .encrypt_in_place(XNonce::from_slice(nonce), aad, &mut *buffer)
                    .map_err(|_| ())
            }
            CipherId::Aes256GcmSiv => Aes256GcmSiv::new(self.key.expose_secret().into())
                .encrypt_in_place(
                    <&AesNonce>::try_from(nonce).expect("nonce length was checked"),
                    aad,
                    &mut *buffer,
                )
                .map_err(|_| ()),
        }
        .map_err(|_| VaultError::CryptoError("encryption failed".to_string()))?;

        // The buffer now holds only ciphertext and its tag. Take its Vec out
        // without copying; the empty Zeroizing wrapper can then be dropped.
        Ok(std::mem::take(&mut *buffer))
    }

    pub(crate) fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Plaintext, VaultError> {
        // Even an empty plaintext needs a tag, so shorter input cannot be valid.
        if nonce.len() != self.nonce_size() || ciphertext.len() < TAG_SIZE {
            return Err(VaultError::CryptoError("decryption failed".to_string()));
        }

        // AES-GCM-SIV has to decrypt before it can check the tag. Give the
        // buffer its cleanup wrapper now, so temporary plaintext is also
        // erased if the operation fails or unwinds.
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        match self.id {
            CipherId::XChaCha20Poly1305 => {
                XChaCha20Poly1305::new(Key::from_slice(self.key.expose_secret()))
                    .decrypt_in_place(XNonce::from_slice(nonce), aad, &mut *buffer)
                    .map_err(|_| ())
            }
            CipherId::Aes256GcmSiv => Aes256GcmSiv::new(self.key.expose_secret().into())
                .decrypt_in_place(
                    <&AesNonce>::try_from(nonce).expect("nonce length was checked"),
                    aad,
                    &mut *buffer,
                )
                .map_err(|_| ()),
        }
        .map_err(|_| VaultError::CryptoError("decryption failed".to_string()))?;

        // Keep the wrapper around the plaintext so it is erased when dropped.
        Ok(buffer)
    }

    /// Returns 24 bytes so both ciphers fit the same stored record layout.
    /// AES uses only the first 12 bytes as its nonce. The rest are random too,
    /// because a row of zeros in every record would give away which cipher we use.
    /// Callers must include all 24 stored bytes in the associated data so changes
    /// to the extra bytes are checked as well.
    pub(crate) fn generate_nonce(&self) -> Result<[u8; NONCE_STORAGE_SIZE], VaultError> {
        let mut nonce = [0u8; NONCE_STORAGE_SIZE];
        getrandom::fill(&mut nonce)
            .map_err(|_| VaultError::CryptoError("failed to generate a nonce".to_string()))?;
        Ok(nonce)
    }
}

#[cfg(test)]
mod tests;
