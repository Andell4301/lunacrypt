use std::{
    fmt,
    path::{Path, PathBuf},
};

use zeroize::Zeroize;

use crate::CipherId;

/// Whether the open vault allows only reading or also changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Reading only. Other readers can open the vault at the same time.
    /// Opening does not repair header or catalog copies.
    ReadOnly,
    /// Reading and writing. Locks the vault for its own use and can repair
    /// header or catalog copies when opening.
    ReadWrite,
}

/// Options chosen when a vault is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CreateOptions {
    /// Encryption algorithm for headers, file contents, and the catalog.
    /// Defaults to XChaCha20-Poly1305. Opening detects the choice automatically.
    pub cipher: CipherId,
    /// Requested usable bytes for each catalog copy, rounded up to whole chunks.
    /// `None` lets the library choose the capacity.
    pub metadata_capacity: Option<u64>,
    /// Whether to fill the space after the headers with random bytes at creation.
    pub fill_data_area: bool,
}

/// Information about one file or directory in the vault.
/// Its fields are wiped when this value is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    /// Path relative to the vault root, using `/`, such as `docs/notes.txt`.
    /// Must follow the rules in [`super::validate_vault_path`].
    pub path: String,
    /// File size in bytes before encryption; zero for directories.
    pub size: u64,
    /// Whether this entry is a directory.
    pub is_directory: bool,
}

impl Drop for FileInfo {
    fn drop(&mut self) {
        self.path.zeroize();
        self.size.zeroize();
        self.is_directory.zeroize();
    }
}

/// Where the vault was opened from.
/// This can be a filesystem path or a document selected through a system picker,
/// such as Android's document picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultLocation {
    /// The vault's path on the filesystem.
    Path(PathBuf),
    /// A document opened by the application, for example through a system picker.
    ExternalDocument {
        /// Name supplied by the application for display only.
        display_name: String,
    },
}

impl VaultLocation {
    /// Returns the filesystem path, or `None` for an external document.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Path(path) => Some(path),
            Self::ExternalDocument { .. } => None,
        }
    }

    /// Whether the vault was opened as an external document rather than by path.
    pub fn is_external_document(&self) -> bool {
        matches!(self, Self::ExternalDocument { .. })
    }
}

impl fmt::Display for VaultLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => write!(formatter, "{}", path.display()),
            Self::ExternalDocument { display_name } => formatter.write_str(display_name),
        }
    }
}

/// Information about an open vault, including space usage, access mode,
/// and whether stored copies need repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInfo {
    /// The vault's filesystem path or the application's display label.
    pub location: VaultLocation,
    /// Whether the open vault allows only reading or also changes.
    pub access_mode: AccessMode,
    /// Encryption algorithm used for headers, file contents, and the catalog.
    pub cipher: CipherId,
    /// Total space reserved for file contents, in bytes before encryption.
    /// Excludes headers, catalogs, and encryption overhead.
    pub data_capacity: u64,
    /// Space used by file contents, in bytes, including padding in each file's
    /// final chunk.
    pub data_used: u64,
    /// Unused space for file contents, in bytes.
    /// A file may still not fit if the free chunks are split into separate
    /// ranges: each file needs enough free chunks next to each other.
    pub free_space: u64,
    /// Maximum catalog size in bytes for each stored copy, before encryption.
    pub metadata_capacity: u64,
    /// Bytes needed to store the catalog before encryption, for each copy.
    pub metadata_used: u64,
    /// Number of bytes each chunk can hold before encryption.
    pub chunk_size: u32,
    /// Number of files and directories in the catalog.
    pub file_count: usize,
    /// Header update number. Increases when the password changes.
    pub header_generation: u64,
    /// Catalog update number. Increases when the catalog changes.
    pub metadata_generation: u64,
    /// Whether opening left header or catalog copies missing, damaged, or out
    /// of date. Read-only opening reports this without repairing those copies.
    pub redundancy_degraded: bool,
}

/// Counts after checking all current file contents for damage or tampering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Files checked, including empty files but not directories.
    pub files_verified: usize,
    /// File-content bytes checked, without padding or encryption overhead.
    pub bytes_verified: u64,
    /// File-data chunks checked. Unused chunks are skipped.
    pub chunks_verified: u64,
}

/// Counts from a successful import of a local file or directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportReport {
    /// Files added to the vault, including empty files.
    pub files_imported: usize,
    /// Source directories visited, including the selected directory itself.
    /// A directory counts even if its destination already existed in the vault.
    /// Parent directories created only to reach the destination do not count.
    pub directories_imported: usize,
    /// Total bytes read from those files, before padding or encryption.
    pub bytes_imported: u64,
}
