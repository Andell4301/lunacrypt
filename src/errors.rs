use thiserror::Error;

/// Errors returned by the vault library.
///
/// Match on the variant to decide how your application should respond.
/// The messages are for people to read, so don't rely on their wording in code.
#[derive(Error, Debug)]
pub enum VaultError {
    /// The OS couldn't allocate or protect memory for the secret key.
    #[error("cannot protect secret key memory: {0}")]
    SecretKeyProtection(String),

    /// Encryption, authentication, or random-number generation failed.
    /// A wrong password and a damaged encrypted header can both fail authentication;
    /// this error alone doesn't tell you which happened.
    #[error("cryptographic operation failed: {0}")]
    CryptoError(String),

    /// A file operation failed, for example because a path was invalid or a write failed.
    #[error("vault I/O failed: {0}")]
    FileError(String),

    /// The password or settings were invalid, or deriving a key failed.
    #[error("password derivation failed: {0}")]
    KdfError(String),

    /// Stored data has an invalid format, conflicting contents, or failed authentication.
    #[error("vault is corrupt: {0}")]
    Corrupt(String),

    /// An operation tried to change a vault that was opened read-only.
    #[error("vault was opened read-only")]
    ReadOnly,

    /// A preview reader was stopped because its volume changed, closed, or became
    /// unusable after a failure. Open a new reader on a usable volume to continue.
    #[error("vault file reader was revoked: {0}")]
    ReaderRevoked(String),

    /// A change may already have taken effect even though the operation returned an error.
    /// Before retrying, inspect the destination or close and reopen the vault to see
    /// which changes survived.
    #[error(
        "the operation may have committed, but durability could not be confirmed: {0}; inspect the destination or reopen and inspect the vault before retrying"
    )]
    CommitUncertain(String),

    /// A storage failure left this open volume in a state we can't safely keep using.
    /// Close and reopen the vault before doing more work.
    #[error("this vault handle is no longer usable: {0}; close it and reopen the vault")]
    Poisoned(String),
}

impl VaultError {
    pub(crate) fn from_io(context: &str, error: std::io::Error) -> Self {
        Self::FileError(format!("{context}: {error}"))
    }

    pub(crate) fn corrupt(message: impl Into<String>) -> Self {
        Self::Corrupt(message.into())
    }
}
