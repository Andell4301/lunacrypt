use std::{
    io,
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::DirExt;
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder},
};

use super::{
    Volume,
    path_io::{PendingFile, parent_or_current_dir, sync_directory},
};
use crate::errors::VaultError;

fn portable_relative_path(path: &str) -> PathBuf {
    path.split('/').collect()
}

/// Opens one directory at a time without following symbolic links. Creates
/// missing directories with private permissions on Unix and saves each parent's
/// change where directory synchronization is supported.
fn create_directories(root: &Dir, path: &Path) -> Result<Dir, VaultError> {
    let mut parent = root
        .try_clone()
        .map_err(|error| VaultError::from_io("failed to retain an extraction directory", error))?;
    let mut builder = DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    for component in path.components() {
        let name = match component {
            Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => return Err(VaultError::FileError("invalid extraction path".to_string())),
        };
        match parent.create_dir_with(name, &builder) {
            Ok(()) => sync_directory(&parent)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(VaultError::from_io(
                    "failed to create an extraction directory",
                    error,
                ));
            }
        }
        parent = parent.open_dir_nofollow(name).map_err(|error| {
            VaultError::from_io("failed to open an extraction directory", error)
        })?;
    }
    Ok(parent)
}

fn open_destination(destination: &Path) -> Result<Dir, VaultError> {
    // The destination may not exist yet. Find a parent we can open, then create
    // the missing directories through that handle. This keeps us in the same
    // directory if a parent is renamed, and gives new directories private Unix
    // permissions from the moment they are created.
    let mut ancestor = destination;
    let mut missing = Vec::new();
    loop {
        match Dir::open_ambient_dir(ancestor, ambient_authority()) {
            Ok(root) => {
                let relative: PathBuf = missing.iter().rev().collect();
                return create_directories(&root, &relative);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    VaultError::FileError("invalid extraction destination".to_string())
                })?;
                missing.push(name);
                ancestor = parent_or_current_dir(ancestor);
            }
            Err(error) => {
                return Err(VaultError::from_io(
                    "failed to open the extraction destination",
                    error,
                ));
            }
        }
    }
}

impl Volume {
    fn extract_file_in_directory(
        &self,
        source: &str,
        root: &Dir,
        target: &Path,
    ) -> Result<(), VaultError> {
        let target_name = target
            .file_name()
            .ok_or_else(|| VaultError::FileError("invalid extraction filename".to_string()))?;
        let parent = create_directories(root, parent_or_current_dir(target))?;
        let (pending, mut file) = PendingFile::create_in(parent, target_name)?;
        // A later chunk can fail authentication after earlier chunks were
        // written. Keep them in the temporary file until the whole file passes,
        // so the requested filename never refers to an incomplete extraction.
        self.extract_file_to_writer(source, &mut file)?;
        file.sync_all().map_err(|error| {
            VaultError::from_io("failed to synchronize extracted plaintext", error)
        })?;
        drop(file);
        pending.publish()
    }

    /// Extracts one file under the requested name only after it is complete.
    /// Existing destination files are never overwritten.
    ///
    /// Plaintext is first written to a temporary file in the same directory,
    /// accessible only to its owner on Unix (mode 0600). It receives the requested
    /// name only after every chunk passes authentication.
    /// The destination's parent directory must already exist.
    ///
    /// # Errors
    ///
    /// Fails for a missing source or parent directory, a source that is a
    /// directory, an existing destination, failed authentication, or filesystem
    /// errors. [`VaultError::CommitUncertain`]
    /// can mean the complete plaintext file received its final name, but saving
    /// the directory change could not be confirmed. Temporary files are removed
    /// on failure when possible; removal does not securely erase bytes on disk.
    pub fn extract_file_to_path(&self, source: &str, destination: &Path) -> Result<(), VaultError> {
        self.ensure_readable()?;
        if self.stat(source)?.is_directory {
            return Err(VaultError::FileError(format!(
                "'{source}' is a directory; use extract_tree_to_directory"
            )));
        }
        let file_name = destination
            .file_name()
            .ok_or_else(|| VaultError::FileError("destination has no filename".to_string()))?;
        let root = Dir::open_ambient_dir(parent_or_current_dir(destination), ambient_authority())
            .map_err(|error| {
            VaultError::from_io("failed to open the extraction destination", error)
        })?;
        self.extract_file_in_directory(source, &root, Path::new(file_name))
    }

    /// Extracts a stored directory's contents beneath `destination`.
    ///
    /// Every file inside the source directory passes authentication before the
    /// destination is created or changed. Files then receive their final names
    /// one at a time, after completion, without overwriting existing files.
    /// A later filesystem or synchronization error can leave completed files
    /// and directories behind; those earlier changes are not undone.
    ///
    /// Files and directories inside the destination are accessed through open
    /// directory handles; symbolic links to directories are rejected. New
    /// directories are accessible only to their owner on Unix (mode 0700).
    /// The caller-selected destination itself may pass through symbolic links.
    ///
    /// # Errors
    ///
    /// Fails if the source is absent or is not a directory, any file fails
    /// authentication, a target file already exists, or filesystem operations
    /// fail. As with [`Self::extract_file_to_path`], errors while giving a file
    /// its final name can leave completed plaintext files; temporary files are
    /// removed when possible.
    pub fn extract_tree_to_directory(
        &self,
        source_directory: &str,
        destination: &Path,
    ) -> Result<(), VaultError> {
        self.ensure_readable()?;
        if !self.stat(source_directory)?.is_directory {
            return Err(VaultError::FileError(format!(
                "'{source_directory}' is not a directory"
            )));
        }
        let prefix = format!("{source_directory}/");
        let entries = self.list_subtree(source_directory)?;

        // Read every file once without saving the plaintext. If a later file
        // is corrupt, this catches it before we create any output. We then read
        // the files again to extract them one at a time. Filesystem errors can
        // still leave earlier files extracted; those changes are not undone.
        for entry in entries.iter().filter(|entry| !entry.is_directory) {
            self.extract_file_to_writer(&entry.path, &mut io::sink())?;
        }

        let root = open_destination(destination)?;
        for entry in entries.into_iter().skip(1) {
            let relative = entry
                .path
                .strip_prefix(&prefix)
                .ok_or_else(|| VaultError::corrupt("subtree path escaped its catalog prefix"))?;
            let target = portable_relative_path(relative);
            if entry.is_directory {
                let directory = create_directories(&root, &target)?;
                sync_directory(&directory)?;
            } else {
                self.extract_file_in_directory(&entry.path, &root, &target)?;
            }
        }
        sync_directory(&root)
    }
}
