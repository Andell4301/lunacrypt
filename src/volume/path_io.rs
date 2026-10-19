use std::{
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs::File,
    path::Path,
};

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use getrandom::fill;

use crate::errors::VaultError;

/// Keeps a new file under a temporary name until the caller is ready to give it
/// its final name.
/// If an earlier step fails, dropping this value tries to remove that file.
/// We keep the parent directory open throughout creation, cleanup, and saving,
/// so renaming a parent cannot redirect a later step to another directory.
pub(super) struct PendingFile {
    parent: Dir,
    temporary_name: String,
    final_name: OsString,
    published: bool,
}

impl PendingFile {
    pub(super) fn create(final_path: &Path) -> Result<(Self, File), VaultError> {
        let name = final_path
            .file_name()
            .ok_or_else(|| VaultError::FileError("destination has no filename".to_string()))?;
        let parent = Dir::open_ambient_dir(parent_or_current_dir(final_path), ambient_authority())
            .map_err(|error| {
                VaultError::from_io("failed to open the destination directory", error)
            })?;
        Self::create_in(parent, name)
    }

    pub(super) fn create_in(parent: Dir, final_name: &OsStr) -> Result<(Self, File), VaultError> {
        // Require a filename without directory parts, so every operation below
        // stays inside the opened parent directory, including rustix calls.
        let mut components = Path::new(final_name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(VaultError::FileError(
                "invalid destination filename".to_string(),
            ));
        }
        match parent.symlink_metadata(final_name) {
            Ok(_) => return Err(already_exists(final_name)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(VaultError::from_io(
                    "failed to inspect the destination",
                    error,
                ));
            }
        }

        for _ in 0..128 {
            let temporary_name = format!(".lunacrypt-{}.tmp", random_hex_suffix()?);
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match parent.open_with(&temporary_name, &options) {
                Ok(file) => {
                    return Ok((
                        Self {
                            parent,
                            temporary_name,
                            final_name: final_name.to_os_string(),
                            published: false,
                        },
                        file.into_std(),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(VaultError::from_io(
                        "failed to create a temporary file",
                        error,
                    ));
                }
            }
        }
        Err(VaultError::FileError(
            "could not choose a unique temporary filename".to_string(),
        ))
    }

    /// The caller must synchronize file contents to storage before giving the
    /// file its final name. Saving the contents and saving the filename are
    /// separate steps; after the name is created, we synchronize its parent
    /// directory where the platform supports that.
    pub(super) fn publish(mut self) -> Result<(), VaultError> {
        // Another file could appear after our earlier existence check. The
        // final operation must also refuse replacement, so that race cannot
        // overwrite someone else's file.
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        ))]
        rustix::fs::renameat_with(
            &self.parent,
            &self.temporary_name,
            &self.parent,
            &self.final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| self.publication_error(error.into()))?;

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        )))]
        {
            // On Windows, std::fs::rename can replace an existing file. Instead,
            // give this same file a second name with a hard link, then remove
            // its temporary name. Creating the final name happens in one step
            // and refuses replacement. Without hard-link support, this fails
            // without creating the target.
            self.parent
                .hard_link(&self.temporary_name, &self.parent, &self.final_name)
                .map_err(|error| self.publication_error(error))?;
            if let Err(error) = self.parent.remove_file(&self.temporary_name) {
                return Err(VaultError::CommitUncertain(format!(
                    "'{}' was published, but its temporary link could not be removed: {error}",
                    Path::new(&self.final_name).display()
                )));
            }
        }
        self.published = true;
        sync_directory(&self.parent).map_err(|error| {
            VaultError::CommitUncertain(format!(
                "'{}' was published, but directory durability was not confirmed: {error}",
                Path::new(&self.final_name).display()
            ))
        })
    }

    fn publication_error(&self, error: std::io::Error) -> VaultError {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            already_exists(&self.final_name)
        } else {
            VaultError::from_io("failed to publish the new file", error)
        }
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.parent.remove_file(&self.temporary_name);
        }
    }
}

fn already_exists(name: &OsStr) -> VaultError {
    VaultError::FileError(format!(
        "refusing to overwrite existing destination '{}'",
        Path::new(name).display()
    ))
}

pub(super) fn random_hex_suffix() -> Result<String, VaultError> {
    let mut random = [0u8; 16];
    fill(&mut random)
        .map_err(|_| VaultError::CryptoError("failed to generate a random filename".to_string()))?;
    let mut suffix = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut suffix, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(suffix)
}

pub(super) fn parent_or_current_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
pub(super) fn sync_directory(directory: &Dir) -> Result<(), VaultError> {
    // An O_PATH handle identifies a directory but cannot synchronize it. Open
    // "." through that handle to get one that supports sync_all. If this fails,
    // the filename may already exist, but we cannot confirm it was saved.
    directory
        .open(".")
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            VaultError::from_io("failed to synchronize the destination directory", error)
        })
}

#[cfg(not(unix))]
pub(super) fn sync_directory(_directory: &Dir) -> Result<(), VaultError> {
    Ok(())
}
