use std::{
    fs::OpenOptions,
    io::{Cursor, Write},
    sync::{Arc, Barrier},
};

use super::{TestPath, password, read_file_bytes};
use crate::{
    CreateOptions, MIN_METADATA_CAPACITY, VaultError, VaultLocation, Volume,
    header::{DATA_AREA_OFFSET, HeaderPayload, build_pair},
    kdf::KdfParams,
    volume::chunk_io::{RECORD_NONCE_LEN, record_offset},
};

#[test]
fn vault_export_and_import_preserve_file_contents_and_the_chosen_cipher() {
    for cipher in super::TEST_CIPHERS {
        let vault_path = TestPath::file("transport-cipher-source");
        let destination = TestPath::file("transport-cipher-import");
        let mut volume = super::create_test_vault_with_cipher(&vault_path.path, cipher);
        let data: Vec<u8> = (0..9000).map(|index| (index % 251) as u8).collect();
        volume.add_file("media.bin", &data).unwrap();
        let mut exported = Vec::new();
        volume.export_container_to_writer(&mut exported).unwrap();
        drop(volume);

        let imported = Volume::import_container_from_reader(
            &mut Cursor::new(exported),
            &destination.path,
            &password(b"test password"),
        )
        .unwrap();
        assert_eq!(imported.info().unwrap().cipher, cipher);
        assert_eq!(imported.extract_file("media.bin").unwrap().as_slice(), data);
        imported.verify().unwrap();
    }
}

struct FirstWriteBarrier {
    bytes: Vec<u8>,
    barrier: Arc<Barrier>,
    first_write: bool,
}

impl FirstWriteBarrier {
    fn new(barrier: Arc<Barrier>) -> Self {
        Self {
            bytes: Vec::new(),
            barrier,
            first_write: true,
        }
    }
}

impl Write for FirstWriteBarrier {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(buffer);
        if self.first_write {
            self.first_write = false;
            // Let every export finish its first read before any starts the next
            // one. If they rely on the shared file position, one export moves
            // it for the others and they skip data. Waiting here makes that
            // mistake show up reliably in the output checks.
            self.barrier.wait();
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn create_transport_vault(path: &std::path::Path) -> Volume {
    create_transport_vault_with_capacity(path, 32 * 1024)
}

fn create_transport_vault_with_capacity(path: &std::path::Path, capacity: u64) -> Volume {
    Volume::create_container_with_kdf_and_options(
        path,
        &password(b"test password"),
        capacity,
        4096,
        CreateOptions {
            metadata_capacity: Some(MIN_METADATA_CAPACITY),
            fill_data_area: false,
            ..CreateOptions::default()
        },
        KdfParams::for_tests(),
    )
    .unwrap()
}

fn assert_directory_empty(path: &std::path::Path) {
    let entries = std::fs::read_dir(path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(entries.is_empty(), "unexpected residue: {entries:?}");
}

fn expect_import_error(result: Result<Volume, VaultError>) -> VaultError {
    match result {
        Ok(_) => panic!("import unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn simultaneous_vault_exports_match_the_original_and_can_be_imported() {
    let vault_path = TestPath::file("transport-source");
    let destination = TestPath::file("transport-import");
    let mut volume = create_transport_vault_with_capacity(&vault_path.path, 8 * 1024 * 1024);
    let large: Vec<u8> = (0..9000).map(|index| (index % 251) as u8).collect();
    volume
        .add_file("docs/message.txt", b"portable secret")
        .unwrap();
    volume.add_file("data/large.bin", &large).unwrap();

    let expected_container = Arc::new(read_file_bytes(&volume.file));
    assert!(expected_container.len() > 4 * 1024 * 1024);
    let volume = Arc::new(volume);
    let start_barrier = Arc::new(Barrier::new(5));
    let first_write_barrier = Arc::new(Barrier::new(4));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let start_barrier = Arc::clone(&start_barrier);
        let first_write_barrier = Arc::clone(&first_write_barrier);
        let volume = Arc::clone(&volume);
        threads.push(std::thread::spawn(move || {
            start_barrier.wait();
            let mut exported = FirstWriteBarrier::new(first_write_barrier);
            let copied = volume.export_container_to_writer(&mut exported).unwrap();
            (copied, exported.bytes)
        }));
    }
    start_barrier.wait();

    let mut exported_for_import = None;
    for thread in threads {
        let (copied, exported) = thread.join().unwrap();
        assert_eq!(copied as usize, expected_container.len());
        assert_eq!(exported, *expected_container);
        exported_for_import.get_or_insert(exported);
    }

    let mut source = Cursor::new(exported_for_import.unwrap());
    let imported = Volume::import_container_from_reader(
        &mut source,
        &destination.path,
        &password(b"test password"),
    )
    .unwrap();
    assert_eq!(
        imported.location(),
        &VaultLocation::Path(destination.path.clone())
    );
    assert_eq!(
        imported
            .extract_file("docs/message.txt")
            .unwrap()
            .as_slice(),
        b"portable secret"
    );
    assert_eq!(
        imported.extract_file("data/large.bin").unwrap().as_slice(),
        large
    );
    drop(imported);

    let reopened =
        Volume::open_container_read_only(&destination.path, &password(b"test password")).unwrap();
    assert_eq!(
        reopened
            .extract_file("docs/message.txt")
            .unwrap()
            .as_slice(),
        b"portable secret"
    );
}

#[test]
fn failed_vault_imports_leave_no_destination_or_temporary_files() {
    let vault_path = TestPath::file("transport-rejected-source");
    let destination_directory = TestPath::directory("transport-rejected-destination");
    let mut volume = create_transport_vault(&vault_path.path);
    volume.add_file("two-chunks.bin", &[7u8; 8192]).unwrap();
    let container = read_file_bytes(&volume.file);

    let wrong_destination = destination_directory.path.join("wrong-password.luna");
    let mut wrong_source = Cursor::new(container.clone());
    let error = expect_import_error(Volume::import_container_from_reader(
        &mut wrong_source,
        &wrong_destination,
        &password(b"wrong password"),
    ));
    assert!(matches!(error, VaultError::CryptoError(_)));
    assert_eq!(wrong_source.position(), DATA_AREA_OFFSET);
    assert!(!wrong_destination.exists());
    assert_directory_empty(&destination_directory.path);

    let entry = volume.catalog.find("two-chunks.bin").unwrap();
    let second_physical = volume
        .physical_chunk_for_data_chunk(entry.start_chunk + 1)
        .unwrap();
    let corrupt_offset =
        record_offset(second_physical, volume.chunk_size).unwrap() as usize + RECORD_NONCE_LEN + 7;
    let mut tampered = container;
    tampered[corrupt_offset] ^= 0x80;

    let tampered_destination = destination_directory.path.join("tampered.luna");
    let mut tampered_source = Cursor::new(tampered);
    let error = expect_import_error(Volume::import_container_from_reader(
        &mut tampered_source,
        &tampered_destination,
        &password(b"test password"),
    ));
    assert!(matches!(error, VaultError::Corrupt(_)));
    assert!(!tampered_destination.exists());
    assert_directory_empty(&destination_directory.path);
}

#[test]
fn vault_import_and_export_do_not_replace_existing_destinations() {
    let vault_path = TestPath::file("transport-no-clobber-source");
    let existing = TestPath::file("transport-no-clobber-existing");
    let mut volume = create_transport_vault(&vault_path.path);
    volume.add_file("secret.txt", b"secret").unwrap();
    let container = read_file_bytes(&volume.file);
    std::fs::write(&existing.path, b"sentinel").unwrap();

    let error = volume.export_container_to_path(&existing.path).unwrap_err();
    assert!(matches!(error, VaultError::FileError(_)));
    assert_eq!(std::fs::read(&existing.path).unwrap(), b"sentinel");

    let mut existing_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&existing.path)
        .unwrap();
    let error = volume
        .export_container_to_file(&mut existing_file)
        .unwrap_err();
    assert!(matches!(error, VaultError::FileError(_)));
    assert_eq!(std::fs::read(&existing.path).unwrap(), b"sentinel");

    let mut source = Cursor::new(container);
    let error = expect_import_error(Volume::import_container_from_reader(
        &mut source,
        &existing.path,
        &password(b"test password"),
    ));
    assert!(matches!(error, VaultError::FileError(_)));
    assert_eq!(std::fs::read(&existing.path).unwrap(), b"sentinel");
}

#[test]
fn failed_vault_import_leaves_the_supplied_source_file_unchanged() {
    let vault_path = TestPath::file("transport-staged-rejected-source");
    let staging_directory = TestPath::directory("transport-staged-rejected-directory");
    let mut volume = create_transport_vault(&vault_path.path);
    volume.add_file("secret.txt", b"secret").unwrap();
    let container = read_file_bytes(&volume.file);

    let staged = staging_directory.path.join("provider-copy.luna");
    let destination = staging_directory.path.join("adopted.luna");
    std::fs::write(&staged, &container).unwrap();

    let error = expect_import_error(Volume::import_container_from_staged_path(
        &staged,
        &destination,
        &password(b"wrong password"),
    ));
    assert!(matches!(error, VaultError::CryptoError(_)));
    assert_eq!(std::fs::read(&staged).unwrap(), container);
    assert!(!destination.exists());

    let mut entries = std::fs::read_dir(&staging_directory.path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries, [staged.file_name().unwrap()]);
}

#[cfg(unix)]
#[test]
fn importing_a_symbolic_link_creates_a_regular_file_and_keeps_the_source() {
    use std::os::unix::fs::symlink;

    let vault_path = TestPath::file("transport-staged-source");
    let staging_directory = TestPath::directory("transport-staged-directory");
    let mut volume = create_transport_vault(&vault_path.path);
    volume.add_file("secret.txt", b"staged secret").unwrap();
    let container = read_file_bytes(&volume.file);

    let real_stage = staging_directory.path.join("provider-copy.luna");
    let staged_link = staging_directory.path.join("selected-stage.luna");
    let destination = staging_directory.path.join("adopted.luna");
    std::fs::write(&real_stage, &container).unwrap();
    symlink(&real_stage, &staged_link).unwrap();

    let imported = Volume::import_container_from_staged_path(
        &staged_link,
        &destination,
        &password(b"test password"),
    )
    .unwrap();
    assert_eq!(
        imported.extract_file("secret.txt").unwrap().as_slice(),
        b"staged secret"
    );
    assert!(
        std::fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_file()
    );
    assert!(
        std::fs::symlink_metadata(&staged_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(read_file_bytes(&imported.file), container);
    assert_eq!(std::fs::read(&real_stage).unwrap(), container);
}

#[test]
fn vault_import_rejects_invalid_passwords_and_headers_before_reading_contents() {
    let directory = TestPath::directory("transport-invalid-header");
    let destination = directory.path.join("import.luna");

    let mut source = Cursor::new(vec![0u8; 1024 * 1024]);
    assert!(matches!(
        expect_import_error(Volume::import_container_from_reader(
            &mut source,
            &destination,
            &password(b""),
        )),
        VaultError::KdfError(_)
    ));
    assert_eq!(source.position(), 0);
    assert_directory_empty(&directory.path);

    assert!(matches!(
        expect_import_error(Volume::import_container_from_reader(
            &mut source,
            &destination,
            &password(b"test password"),
        )),
        VaultError::CryptoError(_)
    ));
    assert_eq!(source.position(), DATA_AREA_OFFSET);
    assert_directory_empty(&directory.path);

    // This header has a valid tag, but claims a vault size we don't support.
    // We still need to reject that size before trying to copy its contents.
    let payload = HeaderPayload::create(crate::CipherId::default(), 4096, u64::MAX, 257).unwrap();
    let pair = build_pair(
        1,
        &password(b"test password"),
        KdfParams::for_tests(),
        &payload,
    )
    .unwrap();
    let mut bytes = pair.into_iter().flatten().collect::<Vec<_>>();
    bytes.resize(bytes.len() + 1024 * 1024, 0);
    let mut source = Cursor::new(bytes);
    assert!(matches!(
        expect_import_error(Volume::import_container_from_reader(
            &mut source,
            &destination,
            &password(b"test password"),
        )),
        VaultError::Corrupt(_)
    ));
    assert_eq!(source.position(), DATA_AREA_OFFSET);
    assert_directory_empty(&directory.path);
}

#[test]
fn vault_import_rejects_missing_bytes_and_stops_at_the_first_extra_byte() {
    let vault_path = TestPath::file("transport-exact-length-source");
    let directory = TestPath::directory("transport-exact-length-destination");
    let destination = directory.path.join("import.luna");
    let volume = create_transport_vault(&vault_path.path);
    let container = read_file_bytes(&volume.file);
    drop(volume);
    let expected = container.len();

    let mut truncated = Cursor::new(&container[..expected - 1]);
    assert!(
        Volume::import_container_from_reader(
            &mut truncated,
            &destination,
            &password(b"test password"),
        )
        .is_err()
    );
    assert_directory_empty(&directory.path);

    let mut oversized = container;
    oversized.resize(expected + 1024 * 1024, 0);
    let mut source = Cursor::new(oversized);
    assert!(matches!(
        expect_import_error(Volume::import_container_from_reader(
            &mut source,
            &destination,
            &password(b"test password"),
        )),
        VaultError::Corrupt(message) if message.contains("trailing bytes")
    ));
    assert_eq!(source.position(), expected as u64 + 1);
    assert_directory_empty(&directory.path);
}

#[test]
fn vault_export_writes_nothing_if_the_source_file_length_has_changed() {
    let vault_path = TestPath::file("transport-export-length-changed");
    let volume = create_transport_vault(&vault_path.path);
    let expected = volume.file.metadata().unwrap().len();
    for changed in [expected + 1, expected - 1] {
        volume.file.set_len(changed).unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            volume.export_container_to_writer(&mut output),
            Err(VaultError::Corrupt(_))
        ));
        assert!(output.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn vault_import_rejects_a_named_pipe_without_waiting_for_a_writer() {
    let directory = TestPath::directory("transport-staged-fifo");
    let staged = directory.path.join("fifo");
    let destination = directory.path.join("import.luna");
    super::create_fifo(&staged);

    let source = staged.clone();
    let output = destination.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = Volume::import_container_from_staged_path(
            &source,
            &output,
            &password(b"test password"),
        );
        sender.send(result.is_err()).unwrap();
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(2));
    // Let a stuck pipe open finish so we can join the worker and clean up.
    // The timeout above still makes the test fail.
    let _unblock = if result.is_err() {
        Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&staged)
                .unwrap(),
        )
    } else {
        None
    };
    worker.join().unwrap();
    assert!(result.unwrap());
    assert!(!destination.exists());
    assert_eq!(std::fs::read_dir(&directory.path).unwrap().count(), 1);
}
