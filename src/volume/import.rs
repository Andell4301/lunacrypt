use std::{collections::BTreeSet, ffi::OsStr, path::Path};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, DirEntry, OpenOptions},
};

use super::{
    ImportReport, Volume, file_table::validate_path, normalize_vault_path,
    path_io::parent_or_current_dir,
};
use crate::VaultError;

enum ImportSource {
    File { file: cap_std::fs::File, size: u64 },
    Directory(Dir),
}

impl Volume {
    /// Imports a local file or directory tree at the given vault path.
    ///
    /// The destination must be a valid vault path with Unicode text in NFC
    /// form; see [`normalize_vault_path`]. Names inside a source directory are
    /// converted to NFC automatically. Existing files are never replaced;
    /// existing directories can receive new entries. Symbolic links and special
    /// files, such as devices and named pipes, are rejected.
    ///
    /// Parent directories of the selected source may contain symbolic links.
    /// Inside the source, files and directories are opened through directory
    /// handles without following links, so renaming a parent does not redirect
    /// us to another directory. If a file is replaced with a named pipe while
    /// opening it, the import fails without waiting for pipe input.
    ///
    /// Directory entries are saved one at a time. On error, newly added entries
    /// are removed if the vault remains writable; failed cleanup reports
    /// [`VaultError::CommitUncertain`]. Stopping the process can leave a partial
    /// import. For document-provider streams, use [`Self::add_file_from_reader`]. Files are
    /// read as the import proceeds, so avoid changing the source during import
    /// if all files must reflect the same point in time.
    ///
    /// # Errors
    ///
    /// Fails for unsupported source types or names, conflicting destination
    /// entries, insufficient vault capacity, or source and vault I/O failures.
    /// Cleanup after a failed import preserves existing vault entries.
    pub fn import_path(
        &mut self,
        source: &Path,
        destination: &str,
    ) -> Result<ImportReport, VaultError> {
        self.ensure_writable()?;
        validate_path(destination)?;
        match open_import_source(source)? {
            ImportSource::Directory(directory) => {
                add_directory_recursive(self, &directory, source, destination)
            }
            ImportSource::File { mut file, size } => {
                self.add_file_from_reader(destination, size, &mut file)?;
                Ok(ImportReport {
                    files_imported: 1,
                    directories_imported: 0,
                    bytes_imported: size,
                })
            }
        }
    }
}

pub(super) fn open_directory_nofollow(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<Dir, VaultError> {
    parent.open_dir_nofollow(name).map_err(|error| {
        VaultError::FileError(format!(
            "failed to open directory '{}': {error}",
            display_path.display()
        ))
    })
}

pub(super) fn open_regular_file_nofollow(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(cap_std::fs::File, u64), VaultError> {
    let mut options = OpenOptions::new();
    // Listing the directory only tells us what this entry was at that moment.
    // It could be replaced with a named pipe before we open it. Open without
    // waiting for pipe input, then check the type of the handle we actually got.
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent.open_with(name, &options).map_err(|error| {
        VaultError::FileError(format!(
            "failed to open file '{}': {error}",
            display_path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        VaultError::FileError(format!(
            "failed to inspect '{}': {error}",
            display_path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(VaultError::FileError(format!(
            "source '{}' changed while it was being opened",
            display_path.display()
        )));
    }
    Ok((file, metadata.len()))
}

fn open_import_source(source: &Path) -> Result<ImportSource, VaultError> {
    let name = source.file_name().ok_or_else(|| {
        VaultError::FileError("source path must name a file or directory".to_string())
    })?;
    let parent = Dir::open_ambient_dir(parent_or_current_dir(source), ambient_authority())
        .map_err(|error| {
            VaultError::FileError(format!(
                "failed to open source directory '{}': {error}",
                parent_or_current_dir(source).display()
            ))
        })?;
    let file_type = parent
        .symlink_metadata(name)
        .map_err(|error| {
            VaultError::FileError(format!("failed to inspect '{}': {error}", source.display()))
        })?
        .file_type();
    if file_type.is_symlink() {
        return Err(VaultError::FileError(format!(
            "symbolic link '{}' was not imported",
            source.display()
        )));
    }
    if file_type.is_dir() {
        let directory = open_directory_nofollow(&parent, name, source)?;
        if !directory
            .dir_metadata()
            .map_err(|error| {
                VaultError::FileError(format!("failed to inspect '{}': {error}", source.display()))
            })?
            .is_dir()
        {
            return Err(VaultError::FileError(format!(
                "source '{}' changed while it was being opened",
                source.display()
            )));
        }
        Ok(ImportSource::Directory(directory))
    } else if file_type.is_file() {
        let (file, size) = open_regular_file_nofollow(&parent, name, source)?;
        Ok(ImportSource::File { file, size })
    } else {
        Err(VaultError::FileError(format!(
            "'{}' is not a regular file or directory",
            source.display()
        )))
    }
}

fn add_directory_recursive(
    volume: &mut Volume,
    local_directory: &Dir,
    local_display_path: &Path,
    vault_directory: &str,
) -> Result<ImportReport, VaultError> {
    let original = volume.list_files()?;
    let original_paths: BTreeSet<&str> = original.iter().map(|entry| entry.path.as_str()).collect();
    match add_directory_recursive_inner(
        volume,
        local_directory,
        local_display_path,
        vault_directory,
    ) {
        Ok(added) => Ok(added),
        Err(import_error) => match rollback_new_paths(volume, &original_paths) {
            Ok(()) => Err(import_error),
            Err(rollback_error) => Err(VaultError::CommitUncertain(format!(
                "directory import failed ({import_error}), and its partial changes could not be rolled back: {rollback_error}"
            ))),
        },
    }
}

fn rollback_new_paths(
    volume: &mut Volume,
    original_paths: &BTreeSet<&str>,
) -> Result<(), VaultError> {
    let mut added_paths = volume
        .list_files()?
        .into_iter()
        .filter(|entry| !original_paths.contains(entry.path.as_str()))
        .collect::<Vec<_>>();
    // Remove children before their parents, so each directory is empty by the
    // time we remove it. Only paths added by this import are included here.
    added_paths.sort_by(|left, right| {
        right
            .path
            .matches('/')
            .count()
            .cmp(&left.path.matches('/').count())
            .then_with(|| right.path.cmp(&left.path))
    });
    for entry in added_paths {
        volume.remove(&entry.path, false)?;
    }
    Ok(())
}

fn add_directory_recursive_inner(
    volume: &mut Volume,
    local_directory: &Dir,
    local_display_path: &Path,
    vault_directory: &str,
) -> Result<ImportReport, VaultError> {
    volume.mkdir(vault_directory)?;
    let mut report = ImportReport {
        directories_imported: 1,
        ..ImportReport::default()
    };
    let mut entries = local_directory
        .entries()
        .map_err(|error| {
            VaultError::FileError(format!(
                "failed to read '{}': {error}",
                local_display_path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            VaultError::FileError(format!(
                "failed to read '{}': {error}",
                local_display_path.display()
            ))
        })?;
    entries.sort_by_key(DirEntry::file_name);

    for entry in entries {
        let local_child = local_display_path.join(entry.file_name());
        let file_type = entry.file_type().map_err(|error| {
            VaultError::FileError(format!(
                "failed to inspect '{}': {error}",
                local_child.display()
            ))
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return Err(VaultError::FileError(format!(
                "'{}' has a non-UTF-8 filename",
                local_child.display()
            )));
        };
        let name = normalize_vault_path(&name);
        let vault_child = format!("{vault_directory}/{name}");
        if file_type.is_symlink() {
            return Err(VaultError::FileError(format!(
                "symbolic link '{}' was not imported",
                local_child.display()
            )));
        }
        if file_type.is_dir() {
            let directory =
                open_directory_nofollow(local_directory, &entry.file_name(), &local_child)?;
            let nested =
                add_directory_recursive_inner(volume, &directory, &local_child, &vault_child)?;
            report.files_imported += nested.files_imported;
            report.directories_imported += nested.directories_imported;
            report.bytes_imported += nested.bytes_imported;
        } else if file_type.is_file() {
            let (mut file, size) =
                open_regular_file_nofollow(local_directory, &entry.file_name(), &local_child)?;
            volume.add_file_from_reader(&vault_child, size, &mut file)?;
            report.files_imported += 1;
            report.bytes_imported += size;
        } else {
            return Err(VaultError::FileError(format!(
                "'{}' is not a regular file or directory",
                local_child.display()
            )));
        }
    }
    Ok(report)
}
