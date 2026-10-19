#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod cipher;
mod errors;
mod header;
mod io;
mod kdf;
mod secret_key;
pub mod volume;

#[cfg(test)]
mod test_support;

pub use cipher::CipherId;
pub use errors::VaultError;

/// Password bytes wrapped in a `secrecy::SecretBox<Vec<u8>>`.
/// You have to explicitly request access to the bytes, which helps avoid accidentally
/// exposing them. The wrapper wipes the bytes it owns when dropped.
///
/// Passwords must be between 1 and 4096 bytes, and they don't have to be UTF-8.
/// Password memory isn't locked against swapping. So, the OS may write it to disk
/// if it needs to free up RAM for other work.
///
/// Keys derived from the password are stored separately in locked memory, as is the
/// vault's randomly generated master key. Changing the password replaces the key
/// protecting the header. The master key stays the same, so the file contents don't
/// need to be encrypted again.
pub type Password = secrecy::SecretBox<Vec<u8>>;

/// Decrypted bytes wrapped in a `zeroize::Zeroizing<Vec<u8>>`.
/// This behaves like a normal byte buffer, but wipes the bytes it owns when dropped.
/// Its memory isn't locked against swapping. If you copy bytes into another buffer,
/// that buffer needs its own cleanup.
pub type Plaintext = zeroize::Zeroizing<Vec<u8>>;

pub use volume::{
    AccessMode, CreateOptions, DEFAULT_METADATA_CAPACITY_FLOOR, FileInfo, ImportReport,
    MAX_METADATA_CAPACITY, MAX_RANDOM_ACCESS_READ, MIN_METADATA_CAPACITY, VaultFileCursor,
    VaultFileReader, VaultInfo, VaultLocation, VerificationReport, Volume, normalize_vault_path,
    recommended_metadata_capacity, validate_vault_path,
};
