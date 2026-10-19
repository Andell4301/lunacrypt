#[cfg(unix)]
use std::{ffi::OsStr, os::unix::fs::symlink};

#[cfg(unix)]
use cap_std::{ambient_authority, fs::Dir};

#[cfg(unix)]
use super::create_test_vault;
use super::{TEST_CIPHERS, TestPath, create_test_vault_with_cipher, password};
#[cfg(unix)]
use crate::volume::import::{open_directory_nofollow, open_regular_file_nofollow};
use crate::{VaultError, Volume};

#[test]
fn import_supports_files_and_folders_and_normalizes_names_for_both_ciphers() {
    for cipher in TEST_CIPHERS {
        let root = TestPath::directory("public-local-import");
        let source = root.path.join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::create_dir(source.join("empty")).unwrap();
        std::fs::write(source.join("cafe\u{301}.txt"), b"root data").unwrap();
        std::fs::write(source.join("nested/child.txt"), b"child data").unwrap();
        let vault_path = root.path.join("vault.luna");
        let mut volume = create_test_vault_with_cipher(&vault_path, cipher);

        let report = volume.import_path(&source, "chosen/tree").unwrap();
        assert_eq!(report.files_imported, 2);
        assert_eq!(report.directories_imported, 3);
        assert_eq!(report.bytes_imported, 19);
        assert!(volume.stat("chosen/tree/empty").unwrap().is_directory);
        assert_eq!(
            volume
                .extract_file("chosen/tree/café.txt")
                .unwrap()
                .as_slice(),
            b"root data"
        );
        assert_eq!(
            volume
                .extract_file("chosen/tree/nested/child.txt")
                .unwrap()
                .as_slice(),
            b"child data"
        );

        let single = source.join("nested/child.txt");
        let report = volume.import_path(&single, "single/file.txt").unwrap();
        assert_eq!(report.files_imported, 1);
        assert_eq!(report.directories_imported, 0);
        assert_eq!(report.bytes_imported, 10);
        std::fs::write(&single, b"replacement").unwrap();
        assert!(volume.import_path(&single, "single/file.txt").is_err());
        assert_eq!(
            volume.extract_file("single/file.txt").unwrap().as_slice(),
            b"child data"
        );

        // We're still visiting a source folder even though its destination
        // already exists, so it counts. Parents such as `chosen` that were
        // created just to reach the destination don't count as imported folders.
        let report = volume
            .import_path(&source.join("empty"), "chosen/tree/empty")
            .unwrap();
        assert_eq!(report.files_imported, 0);
        assert_eq!(report.directories_imported, 1);
        assert_eq!(report.bytes_imported, 0);
        let before = volume.list_files().unwrap();
        assert!(volume.import_path(&source, "invalid//destination").is_err());
        assert_eq!(volume.list_files().unwrap(), before);
        volume.verify().unwrap();
        drop(volume);
        let mut read_only =
            Volume::open_container_read_only(&vault_path, &password(b"test password")).unwrap();
        assert!(matches!(
            read_only.import_path(&single, "another.txt"),
            Err(VaultError::ReadOnly)
        ));
        assert_eq!(read_only.list_files().unwrap(), before);
    }
}

#[cfg(unix)]
#[test]
fn import_rejects_source_files_and_folders_replaced_with_symbolic_links() {
    let test_directory = TestPath::directory("local-import");
    let source = test_directory.path.join("source");
    let outside_file = test_directory.path.join("outside.txt");
    let outside_directory = test_directory.path.join("outside-directory");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(&outside_file, b"outside secret").unwrap();
    std::fs::create_dir(&outside_directory).unwrap();
    let source_dir = Dir::open_ambient_dir(&source, ambient_authority()).unwrap();

    let selected_file = source.join("selected-file");
    std::fs::write(&selected_file, b"original").unwrap();
    assert!(
        source_dir
            .symlink_metadata("selected-file")
            .unwrap()
            .is_file()
    );
    std::fs::remove_file(&selected_file).unwrap();
    symlink(&outside_file, &selected_file).unwrap();
    assert!(
        open_regular_file_nofollow(&source_dir, OsStr::new("selected-file"), &selected_file)
            .is_err()
    );

    let selected_directory = source.join("selected-directory");
    std::fs::create_dir(&selected_directory).unwrap();
    assert!(
        source_dir
            .symlink_metadata("selected-directory")
            .unwrap()
            .is_dir()
    );
    std::fs::remove_dir(&selected_directory).unwrap();
    symlink(&outside_directory, &selected_directory).unwrap();
    assert!(
        open_directory_nofollow(
            &source_dir,
            OsStr::new("selected-directory"),
            &selected_directory,
        )
        .is_err()
    );
    let mut volume = create_test_vault(&test_directory.path.join("vault.luna"));
    assert!(volume.import_path(&selected_file, "selected-file").is_err());
    assert!(
        volume
            .import_path(&selected_directory, "selected-directory")
            .is_err()
    );
    assert!(volume.list_files().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn finding_a_symbolic_link_undoes_all_files_and_folders_added_by_the_import() {
    let test_directory = TestPath::directory("local-import");
    let source = test_directory.path.join("source");
    let earlier_directory = source.join("a-directory");
    let earlier_file = source.join("b-file.txt");
    let later_symlink = source.join("z-symlink.txt");
    let outside_file = test_directory.path.join("outside.txt");
    let vault_path = test_directory.path.join("rollback-test.luna");

    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&earlier_directory).unwrap();
    std::fs::write(earlier_directory.join("nested.txt"), b"nested plaintext").unwrap();
    std::fs::write(&earlier_file, b"earlier plaintext").unwrap();
    std::fs::write(&outside_file, b"outside plaintext").unwrap();
    symlink(&outside_file, &later_symlink).unwrap();

    let mut volume = create_test_vault(&vault_path);
    volume.mkdir("existing").unwrap();
    volume
        .add_file("existing/keep.txt", b"preexisting plaintext")
        .unwrap();
    let original_files = volume.list_files().unwrap();

    let error = volume.import_path(&source, "incoming").unwrap_err();

    assert!(
        matches!(&error, VaultError::FileError(message) if
            message.contains("symbolic link") && message.contains("z-symlink.txt")),
        "unexpected import error: {error}"
    );
    assert_eq!(volume.list_files().unwrap(), original_files);
    assert_eq!(
        volume.extract_file("existing/keep.txt").unwrap().as_slice(),
        b"preexisting plaintext"
    );
    assert!(volume.stat("incoming").is_err());
}

#[cfg(unix)]
#[test]
fn import_rejects_a_file_replaced_with_a_named_pipe_without_waiting() {
    let test_directory = TestPath::directory("local-import");
    let source = test_directory.path.join("selected");
    std::fs::write(&source, b"original").unwrap();
    let parent = Dir::open_ambient_dir(&test_directory.path, ambient_authority()).unwrap();
    assert!(parent.symlink_metadata("selected").unwrap().is_file());
    std::fs::remove_file(&source).unwrap();
    super::create_fifo(&source);

    let display_path = source.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        sender
            .send(
                open_regular_file_nofollow(&parent, OsStr::new("selected"), &display_path).is_err(),
            )
            .unwrap();
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(2));
    // If the replaced file makes open() wait, give the pipe another end so we
    // can join the worker and report the failed timeout.
    let _unblock = if result.is_err() {
        Some(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&source)
                .unwrap(),
        )
    } else {
        None
    };
    worker.join().unwrap();
    assert!(result.unwrap());
}
