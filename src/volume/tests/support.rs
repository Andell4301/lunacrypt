use std::{
    fs::{File, OpenOptions},
    path::Path,
};

use crate::{
    CipherId,
    kdf::KdfParams,
    test_support::password,
    volume::{CreateOptions, Volume},
};

pub(super) fn create_test_vault(path: &Path) -> Volume {
    create_test_vault_with_cipher(path, CipherId::default())
}

pub(super) fn create_test_vault_with_cipher(path: &Path, cipher: CipherId) -> Volume {
    let volume = Volume::create_container_with_kdf_and_options(
        path,
        &password(b"test password"),
        128 * 1024,
        4096,
        CreateOptions {
            cipher,
            ..CreateOptions::default()
        },
        KdfParams::for_tests(),
    )
    .unwrap();
    assert_eq!(volume.info().unwrap().cipher, cipher);
    volume
}

pub(super) fn flip_byte(path: &Path, offset: u64) {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    flip_byte_in_file(&file, offset);
}

// On Windows, opening another handle won't let us change bytes protected by
// the vault's write lock, even in the same process. So tests that damage an
// open vault use the file handle that already holds its lock.
pub(super) fn flip_byte_in_file(file: &File, offset: u64) {
    let mut byte = [0u8; 1];
    crate::io::read_exact_at(file, &mut byte, offset).unwrap();
    byte[0] ^= 0x80;
    crate::io::write_all_at(file, &byte, offset).unwrap();
    file.sync_all().unwrap();
}

pub(super) fn read_file_bytes(file: &File) -> Vec<u8> {
    let mut bytes = vec![0; usize::try_from(file.metadata().unwrap().len()).unwrap()];
    crate::io::read_exact_at(file, &mut bytes, 0).unwrap();
    bytes
}

#[cfg(unix)]
pub(super) fn create_fifo(path: &Path) {
    // Opening a named pipe can wait for another process. We use these to check
    // that the library rejects pipes without getting stuck. The system command
    // also works on Apple platforms, where Rustix doesn't provide this operation.
    assert!(
        std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}
