use super::{TestPath, create_test_vault, flip_byte_in_file};
use crate::volume::chunk_io::{RECORD_NONCE_LEN, record_offset};

#[test]
fn failed_file_authentication_leaves_no_output_or_temporary_files() {
    let vault_path = TestPath::file("extract-auth-failure");
    let destination = TestPath::directory("extract-auth-destination");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("two-chunks.bin", &[0x5a; 8192]).unwrap();
    let entry = volume.catalog.find("two-chunks.bin").unwrap();
    let second_physical = volume
        .physical_chunk_for_data_chunk(entry.start_chunk + 1)
        .unwrap();
    let corrupt_offset =
        record_offset(second_physical, volume.chunk_size).unwrap() + RECORD_NONCE_LEN as u64 + 17;
    flip_byte_in_file(&volume.file, corrupt_offset);

    let target = destination.path.join("plaintext.bin");
    assert!(
        volume
            .extract_file_to_path("two-chunks.bin", &target)
            .is_err()
    );
    assert!(!target.exists());
    let residue = std::fs::read_dir(&destination.path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        residue.is_empty(),
        "plaintext residue remained: {residue:?}"
    );
}

#[test]
fn folder_extraction_checks_all_files_before_changing_the_destination() {
    let vault_path = TestPath::file("extract-tree-auth-failure");
    let destination_parent = TestPath::directory("extract-tree-auth-destination");
    let mut volume = create_test_vault(&vault_path.path);
    volume
        .add_file("tree/a-first.txt", b"verified first")
        .unwrap();
    volume.add_file("tree/z-later.bin", &[0x7b; 8192]).unwrap();
    let entry = volume.catalog.find("tree/z-later.bin").unwrap();
    let second_physical = volume
        .physical_chunk_for_data_chunk(entry.start_chunk + 1)
        .unwrap();
    let corrupt_offset =
        record_offset(second_physical, volume.chunk_size).unwrap() + RECORD_NONCE_LEN as u64 + 19;
    flip_byte_in_file(&volume.file, corrupt_offset);

    let destination = destination_parent.path.join("tree-output");
    assert!(
        volume
            .extract_tree_to_directory("tree", &destination)
            .is_err()
    );
    assert!(!destination.exists());
    assert!(
        std::fs::read_dir(&destination_parent.path)
            .unwrap()
            .next()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn extracted_files_are_accessible_only_to_the_current_user() {
    use std::os::unix::fs::PermissionsExt;

    let vault_path = TestPath::file("extract-private-mode");
    let destination = TestPath::directory("extract-private-destination");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("private.txt", b"private bytes").unwrap();

    let target = destination.path.join("private.txt");
    volume.extract_file_to_path("private.txt", &target).unwrap();
    let mode = std::fs::metadata(target).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0);
}

#[test]
fn extraction_creates_new_files_without_replacing_existing_ones() {
    let vault_path = TestPath::file("extract");
    let destination = TestPath::directory("extract-destination");
    let mut volume = create_test_vault(&vault_path.path);
    volume
        .add_file("tree/sub/file.txt", b"complete plaintext")
        .unwrap();
    let existing_target = destination.path.join("existing.txt");
    std::fs::write(&existing_target, b"keep me").unwrap();
    assert!(
        volume
            .extract_file_to_path("tree/sub/file.txt", &existing_target)
            .is_err()
    );
    assert_eq!(std::fs::read(&existing_target).unwrap(), b"keep me");

    let new_target = destination.path.join("new.txt");
    volume
        .extract_file_to_path("tree/sub/file.txt", &new_target)
        .unwrap();
    assert_eq!(std::fs::read(&new_target).unwrap(), b"complete plaintext");

    let tree_target = destination.path.join("tree-output");
    volume
        .extract_tree_to_directory("tree", &tree_target)
        .unwrap();
    assert_eq!(
        std::fs::read(tree_target.join("sub/file.txt")).unwrap(),
        b"complete plaintext"
    );
}

#[cfg(unix)]
#[test]
fn folder_extraction_cannot_follow_symbolic_links_outside_the_destination() {
    use std::os::unix::fs::symlink;

    let vault_path = TestPath::file("extract-symlink");
    let destination = TestPath::directory("extract-root");
    let outside = TestPath::directory("extract-outside");
    symlink(&outside.path, destination.path.join("link")).unwrap();

    let mut volume = create_test_vault(&vault_path.path);
    volume
        .add_file("tree/link/escaped.txt", b"must stay inside")
        .unwrap();
    assert!(
        volume
            .extract_tree_to_directory("tree", &destination.path)
            .is_err()
    );
    assert!(!outside.path.join("escaped.txt").exists());
}

#[cfg(unix)]
#[test]
fn extraction_respects_the_filesystems_rules_for_non_utf8_names() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    let vault_path = TestPath::file("extract-local-bytes");
    let destination = TestPath::directory("extract-local-bytes-destination");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("portable.txt", b"verified bytes").unwrap();
    let target = destination.path.join(OsStr::from_bytes(b"local-\xff.txt"));

    // Unix paths can hold these bytes, but the filesystem may reject them.
    // Try a regular rename first, since extraction also gives a temporary
    // file its final name. APFS, for example, requires valid UTF-8 filenames.
    let probe = destination.path.join("filename-probe");
    std::fs::write(&probe, b"").unwrap();
    let accepts_name = match std::fs::rename(&probe, &target) {
        Ok(()) => {
            std::fs::remove_file(&target).unwrap();
            true
        }
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error()) => {
            std::fs::remove_file(&probe).unwrap();
            false
        }
        Err(error) => panic!("failed to check which filenames the filesystem accepts: {error}"),
    };

    let result = volume.extract_file_to_path("portable.txt", &target);
    if accepts_name {
        result.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"verified bytes");
    } else {
        assert!(matches!(result, Err(crate::VaultError::FileError(_))));
        assert!(
            std::fs::read_dir(&destination.path)
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[cfg(unix)]
#[test]
fn extracted_folders_are_private_and_existing_symbolic_links_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let vault_path = TestPath::file("extract-private-tree");
    let destination = TestPath::directory("extract-private-tree-destination");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("tree/child/file.txt", b"private").unwrap();
    let root = destination.path.join("new/output");
    volume.extract_tree_to_directory("tree", &root).unwrap();
    for directory in [
        destination.path.join("new"),
        root.clone(),
        root.join("child"),
    ] {
        assert_eq!(
            std::fs::metadata(directory).unwrap().permissions().mode() & 0o077,
            0
        );
    }

    let hostile_root = destination.path.join("hostile");
    std::fs::create_dir_all(hostile_root.join("real")).unwrap();
    symlink("real", hostile_root.join("child")).unwrap();
    assert!(
        volume
            .extract_tree_to_directory("tree", &hostile_root)
            .is_err()
    );
    assert!(!hostile_root.join("real/file.txt").exists());
}

#[cfg(unix)]
#[test]
fn extraction_does_not_replace_a_symbolic_link_to_a_missing_file() {
    use std::os::unix::fs::symlink;

    let vault_path = TestPath::file("extract-dangling-symlink");
    let destination = TestPath::directory("extract-dangling-symlink-destination");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("file", b"plaintext").unwrap();
    let target = destination.path.join("file");
    symlink("does-not-exist", &target).unwrap();
    assert!(volume.extract_file_to_path("file", &target).is_err());
    assert_eq!(
        std::fs::read_link(&target).unwrap(),
        std::path::Path::new("does-not-exist")
    );
    assert_eq!(std::fs::read_dir(&destination.path).unwrap().count(), 1);
}
