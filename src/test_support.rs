//! Helpers shared by library tests. These aren't included in normal builds.

use std::{
    fs::{DirBuilder, File, OpenOptions},
    path::PathBuf,
};

use crate::{CipherId, Password};

pub(crate) const TEST_CIPHERS: [CipherId; 2] =
    [CipherId::XChaCha20Poly1305, CipherId::Aes256GcmSiv];

pub(crate) fn password(bytes: &[u8]) -> Password {
    Password::new(Box::new(bytes.to_vec()))
}

/// Owns a unique temporary directory and everything a test creates inside it.
/// Declare it before the files you open. Rust drops local values in reverse order,
/// so the files will close before cleanup tries to remove them. Windows needs this.
pub(crate) struct TestPath {
    pub(crate) path: PathBuf,
    root: PathBuf,
}

impl TestPath {
    /// Creates a private directory and returns a path for a file inside it.
    /// The file itself doesn't exist yet.
    pub(crate) fn file(label: &str) -> Self {
        let mut owned = Self::directory(label);
        owned.path = owned.root.join("file");
        owned
    }

    pub(crate) fn directory(label: &str) -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).expect("test directory randomness");
        let root = std::env::temp_dir().join(format!(
            "lunacrypt-{label}-{:032x}",
            u128::from_le_bytes(random)
        ));
        let mut builder = DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).expect("create unique test directory");
        Self {
            path: root.clone(),
            root,
        }
    }

    /// Creates a file for reading and writing. Fails if the path already exists.
    pub(crate) fn create_file(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&self.path)
            .expect("create new test file")
    }
}

impl Drop for TestPath {
    fn drop(&mut self) {
        // Cleanup also runs when a test panics. A second panic here could abort
        // the process, so only report cleanup failures if the test wasn't already failing.
        if let Err(error) = std::fs::remove_dir_all(&self.root) {
            if !std::thread::panicking() {
                panic!(
                    "failed to remove test directory '{}': {error}",
                    self.root.display()
                );
            }
        }
    }
}
