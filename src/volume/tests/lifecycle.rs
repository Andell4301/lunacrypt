use std::{fs::OpenOptions, io::Write};

use super::{TEST_CIPHERS, TestPath, create_test_vault, create_test_vault_with_cipher, password};
use crate::{AccessMode, CreateOptions, MIN_METADATA_CAPACITY, VaultError, VaultLocation, Volume};

fn expect_volume_error(result: Result<Volume, VaultError>) -> VaultError {
    match result {
        Ok(_) => panic!("vault operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn caller_supplied_file_handles_support_creating_and_reading_vaults() {
    let backing = TestPath::file("external-handle");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&backing.path)
        .unwrap();
    let mut volume = Volume::create_container_on_file_with_options(
        file,
        "provider-vault.luna",
        &password(b"test password"),
        8192,
        4096,
        CreateOptions {
            metadata_capacity: Some(MIN_METADATA_CAPACITY),
            fill_data_area: false,
            ..CreateOptions::default()
        },
    )
    .unwrap();
    assert_eq!(volume.info().unwrap().access_mode, AccessMode::ReadWrite);
    assert_eq!(
        volume.location(),
        &VaultLocation::ExternalDocument {
            display_name: "provider-vault.luna".to_string(),
        }
    );
    volume.add_file("message.txt", b"external handle").unwrap();
    drop(volume);

    let file = OpenOptions::new().read(true).open(&backing.path).unwrap();
    let mut read_only = Volume::open_container_file_read_only(
        file,
        "provider-vault.luna",
        &password(b"test password"),
    )
    .unwrap();
    assert_eq!(read_only.info().unwrap().access_mode, AccessMode::ReadOnly);
    assert_eq!(
        read_only.extract_file("message.txt").unwrap().as_slice(),
        b"external handle"
    );
    assert!(matches!(
        read_only.mkdir("blocked"),
        Err(VaultError::ReadOnly)
    ));

    let nonempty = TestPath::file("external-handle-nonempty");
    std::fs::write(&nonempty.path, b"sentinel").unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&nonempty.path)
        .unwrap();
    assert!(matches!(
        expect_volume_error(Volume::create_container_on_file(
            file,
            "nonempty.luna",
            &password(b"test password"),
            4096,
            4096,
        )),
        VaultError::FileError(_)
    ));
    assert_eq!(std::fs::read(&nonempty.path).unwrap(), b"sentinel");

    let invalid_name = TestPath::file("external-handle-invalid-name");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&invalid_name.path)
        .unwrap();
    assert!(matches!(
        expect_volume_error(Volume::create_container_on_file(
            file,
            "provider\nname",
            &password(b"test password"),
            4096,
            4096,
        )),
        VaultError::FileError(_)
    ));
    assert_eq!(std::fs::metadata(&invalid_name.path).unwrap().len(), 0);
}

#[test]
fn added_and_removed_files_keep_their_state_after_reopening() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("lifecycle");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("docs/readme.txt", b"hello vault").unwrap();
        volume.add_file("empty.bin", b"").unwrap();
        let large: Vec<u8> = (0..10_000).map(|index| (index % 251) as u8).collect();
        volume.add_file("data/large.bin", &large).unwrap();
        let report = volume.verify().unwrap();
        assert_eq!(report.files_verified, 3);
        assert_eq!(
            volume.extract_file("docs/readme.txt").unwrap().as_slice(),
            b"hello vault"
        );
        drop(volume);

        let mut reopened =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert_eq!(reopened.info().unwrap().cipher, cipher);
        assert_eq!(
            reopened.extract_file("data/large.bin").unwrap().as_slice(),
            large
        );
        assert!(matches!(reopened.mkdir("nope"), Err(VaultError::ReadOnly)));
        assert!(!reopened.info().unwrap().redundancy_degraded);
        drop(reopened);

        let mut writer =
            Volume::open_container(&vault_path.path, &password(b"test password")).unwrap();
        assert_eq!(writer.info().unwrap().cipher, cipher);
        writer.remove("docs", true).unwrap();
        drop(writer);
        let reopened =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(reopened.stat("docs/readme.txt").is_err());
        assert!(reopened.stat("data/large.bin").is_ok());
    }
}

#[test]
fn opening_rejects_wrong_or_empty_passwords_and_extra_bytes() {
    let vault_path = TestPath::file("bad-open");
    drop(create_test_vault(&vault_path.path));
    assert!(Volume::open_container_read_only(&vault_path.path, &password(b"wrong")).is_err());
    assert!(Volume::open_container_read_only(&vault_path.path, &password(b"")).is_err());

    let mut file = OpenOptions::new()
        .append(true)
        .open(&vault_path.path)
        .unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        Volume::open_container_read_only(&vault_path.path, &password(b"test password")).is_err()
    );
}

#[test]
fn readers_can_share_a_vault_but_cannot_overlap_a_writer() {
    let vault_path = TestPath::file("locks");
    let writer = create_test_vault(&vault_path.path);
    assert!(
        Volume::open_container_read_only(&vault_path.path, &password(b"test password")).is_err()
    );
    drop(writer);

    let reader_one =
        Volume::open_container_read_only(&vault_path.path, &password(b"test password")).unwrap();
    let reader_two =
        Volume::open_container_read_only(&vault_path.path, &password(b"test password")).unwrap();
    assert!(Volume::open_container(&vault_path.path, &password(b"test password")).is_err());
    drop(reader_one);
    drop(reader_two);
    assert!(Volume::open_container(&vault_path.path, &password(b"test password")).is_ok());
}

#[cfg(unix)]
#[test]
fn closing_the_volume_releases_its_lock_even_if_a_file_handle_copy_remains() {
    let vault_path = TestPath::file("lock-duplicate");
    let volume = create_test_vault(&vault_path.path);
    // On Unix, these handles share the same operating-system file state.
    // If we relied on closing the volume's handle to release the lock, this
    // clone could keep it locked. Closing the volume must unlock it even
    // while the clone stays alive.
    let duplicate = volume.file.try_clone().unwrap();
    assert!(Volume::open_container(&vault_path.path, &password(b"test password")).is_err());
    drop(volume);
    let reopened = Volume::open_container(&vault_path.path, &password(b"test password")).unwrap();
    drop(duplicate);
    drop(reopened);
}

#[cfg(unix)]
#[test]
fn failed_open_or_creation_releases_locks_even_if_file_handle_copies_remain() {
    let vault_path = TestPath::file("failed-construction-lock-duplicate");
    drop(create_test_vault(&vault_path.path));

    let file = std::fs::File::open(&vault_path.path).unwrap();
    let duplicate = file.try_clone().unwrap();
    let error = expect_volume_error(Volume::open_container_file_read_only(
        file,
        "vault.luna",
        &password(b"wrong password"),
    ));
    assert!(matches!(error, VaultError::CryptoError(_)));
    let reopened = Volume::open_container(&vault_path.path, &password(b"test password")).unwrap();
    drop(duplicate);
    drop(reopened);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&vault_path.path)
        .unwrap();
    let duplicate = file.try_clone().unwrap();
    let error = expect_volume_error(Volume::create_container_on_file(
        file,
        "vault.luna",
        &password(b"test password"),
        4096,
        4096,
    ));
    assert!(matches!(error, VaultError::FileError(message) if message.contains("empty file")));
    let reopened = Volume::open_container(&vault_path.path, &password(b"test password")).unwrap();
    drop(duplicate);
    drop(reopened);
}

#[cfg(any(unix, windows))]
#[test]
fn append_mode_is_rejected_before_creation_or_repair_changes_a_vault() {
    let empty = TestPath::file("external-append-create");
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .open(&empty.path)
        .unwrap();
    let error = expect_volume_error(Volume::create_container_on_file(
        file,
        "append.luna",
        &password(b"test password"),
        4096,
        4096,
    ));
    assert!(matches!(error, VaultError::FileError(message) if message.contains("append")));
    assert_eq!(std::fs::metadata(&empty.path).unwrap().len(), 0);

    let existing = TestPath::file("external-append-open");
    drop(create_test_vault(&existing.path));
    super::flip_byte(&existing.path, 200);
    let before = std::fs::read(&existing.path).unwrap();
    let append_handle = || {
        OpenOptions::new()
            .read(true)
            .append(true)
            .open(&existing.path)
            .unwrap()
    };
    let error = expect_volume_error(Volume::open_container_file(
        append_handle(),
        "append.luna",
        &password(b"test password"),
    ));
    assert!(matches!(error, VaultError::FileError(message) if message.contains("append")));
    assert_eq!(std::fs::read(&existing.path).unwrap(), before);

    // Opening read-only leaves the damaged header untouched. Append mode is
    // harmless here because the volume only reads from the file.
    let volume = Volume::open_container_file_read_only(
        append_handle(),
        "append.luna",
        &password(b"test password"),
    )
    .unwrap();
    assert!(volume.info().unwrap().redundancy_degraded);
    assert_eq!(std::fs::read(&existing.path).unwrap(), before);
}

#[test]
fn creating_or_opening_a_vault_for_changes_requires_read_and_write_access() {
    let empty = TestPath::file("external-write-only-create");
    let write_only = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&empty.path)
        .unwrap();
    let error = expect_volume_error(Volume::create_container_on_file(
        write_only,
        "unreadable.luna",
        &password(b"test password"),
        4096,
        4096,
    ));
    assert!(matches!(error, VaultError::FileError(message) if message.contains("access")));
    assert_eq!(std::fs::metadata(&empty.path).unwrap().len(), 0);

    let existing = TestPath::file("external-read-only-open");
    drop(create_test_vault(&existing.path));
    let read_only = std::fs::File::open(&existing.path).unwrap();
    let error = expect_volume_error(Volume::open_container_file(
        read_only,
        "read-only.luna",
        &password(b"test password"),
    ));
    assert!(matches!(error, VaultError::FileError(message) if message.contains("access")));
}

#[cfg(unix)]
#[test]
fn opening_a_named_pipe_fails_without_waiting_for_a_writer() {
    use std::{os::unix::fs::OpenOptionsExt, sync::mpsc, time::Duration};

    let fifo = TestPath::file("vault-fifo");
    super::create_fifo(&fifo.path);
    let path = fifo.path.clone();
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let failed = Volume::open_container_read_only(&path, &password(b"test password")).is_err();
        sender.send(failed).unwrap();
    });
    let result = receiver.recv_timeout(Duration::from_secs(2));
    if result.is_err() {
        // A timeout means open() may be stuck waiting for a writer. Supply one
        // before joining, or the test itself would hang instead of failing.
        let _rescue = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&fifo.path)
            .unwrap();
        worker.join().unwrap();
        panic!("opening a FIFO waited for a writer");
    }
    assert!(result.unwrap());
    worker.join().unwrap();
}
