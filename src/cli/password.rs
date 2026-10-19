use std::path::Path;

use lunacrypt::{AccessMode, Password, VaultError, Volume};
use zeroize::Zeroizing;

fn prompt_password() -> Result<Password, VaultError> {
    let password = rpassword::prompt_password("Password: ")
        .map_err(|error| VaultError::FileError(format!("failed to read password: {error}")))?;
    Ok(Password::new(Box::new(password.into_bytes())))
}

/// Prompt for the password and open the vault in the requested mode.
/// The local password is dropped and its bytes are wiped when we return,
/// even if opening fails.
pub(super) fn prompt_and_open_volume(path: &Path, mode: AccessMode) -> Result<Volume, VaultError> {
    let password = prompt_password()?;
    match mode {
        AccessMode::ReadOnly => Volume::open_container_read_only(path, &password),
        AccessMode::ReadWrite => Volume::open_container(path, &password),
    }
}

pub(super) fn prompt_and_confirm_new_password() -> Result<Password, VaultError> {
    // Either prompt can fail, or the answers might disagree. Wrap each answer
    // so an early return wipes what we've read so far.
    let mut first = Zeroizing::new(
        rpassword::prompt_password("New password: ")
            .map_err(|error| VaultError::FileError(format!("failed to read password: {error}")))?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Confirm password: ")
            .map_err(|error| VaultError::FileError(format!("failed to read password: {error}")))?,
    );
    if *first != *second {
        return Err(VaultError::FileError("passwords do not match".to_string()));
    }
    if first.is_empty() {
        return Err(VaultError::FileError(
            "password must not be empty".to_string(),
        ));
    }
    // Move the String out of its wrapper so Password can own the same bytes.
    // The old wrapper is left empty, and Password now handles their cleanup.
    Ok(Password::new(Box::new(
        std::mem::take(&mut *first).into_bytes(),
    )))
}
