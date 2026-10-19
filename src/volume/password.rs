use super::Volume;
use crate::{
    Password,
    errors::VaultError,
    header::{HEADER_SLOT_COUNT, build_pair, write_slot},
    kdf::{KdfParams, validate_password_length},
};

impl Volume {
    /// Encrypts the existing master key in each header copy, using a key derived
    /// from `new_password` and that copy's fresh salt.
    ///
    /// File encryption keys come from the master key. So changing the password
    /// only needs to rewrite the headers; the master key and encrypted file
    /// data stay the same. Copies or backups made before this change can still
    /// be decrypted with their previous password.
    ///
    /// Both header copies are saved and synchronized to storage before success.
    /// Existing preview readers stop working when writing begins.
    ///
    /// # Errors
    ///
    /// Fails for an invalid password, unavailable protected key memory, or
    /// errors deriving a key or saving headers. [`VaultError::CommitUncertain`]
    /// means either password may be needed to reopen and inspect the vault; the
    /// current volume can no longer be used and must be closed.
    pub fn change_password(&mut self, new_password: &Password) -> Result<(), VaultError> {
        self.change_password_with_kdf(new_password, KdfParams::default())
    }

    pub(crate) fn change_password_with_kdf(
        &mut self,
        new_password: &Password,
        kdf_params: KdfParams,
    ) -> Result<(), VaultError> {
        self.ensure_writable()?;
        validate_password_length(new_password)?;
        kdf_params.validate()?;
        let generation = self
            .header_generation
            .checked_add(1)
            .ok_or_else(|| VaultError::FileError("header generation exhausted".to_string()))?;
        let pair = build_pair(generation, new_password, kdf_params, &self.header_payload)?;
        let first = (generation as usize) % HEADER_SLOT_COUNT;
        let second = 1 - first;

        // Building the new headers can fail without changing the vault. Keep
        // existing readers usable until we're actually about to write them.
        self.reader_session.invalidate();
        for slot in [first, second] {
            if let Err(error) = write_slot(&self.file, slot, &pair[slot]) {
                self.poison(format!(
                    "password update failed in header slot {slot}: {error}"
                ));
                return Err(VaultError::CommitUncertain(format!(
                    "password update could not confirm header slot {slot}: {error}"
                )));
            }
            if let Err(error) = self.file.sync_all() {
                self.poison(format!(
                    "password update synchronization failed after header slot {slot}: {error}"
                ));
                return Err(VaultError::CommitUncertain(format!(
                    "password update may have committed through header slot {slot}: {error}"
                )));
            }
        }

        self.header_generation = generation;
        self.redundancy_degraded = false;
        Ok(())
    }
}
