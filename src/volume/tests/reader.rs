use std::{
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Barrier},
};

use super::{
    TEST_CIPHERS, TestPath, create_test_vault, create_test_vault_with_cipher, flip_byte_in_file,
    password,
};
use crate::{
    MAX_RANDOM_ACCESS_READ, VaultError, Volume,
    volume::chunk_io::{RECORD_NONCE_LEN, record_offset},
};

fn patterned_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| ((index * 17 + index / 251) % 256) as u8)
        .collect()
}

#[test]
fn reads_can_cross_chunk_boundaries_and_stop_at_the_end_of_the_file() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("reader-boundaries");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        let data = patterned_bytes(3 * 4096 + 37);
        volume.add_file("media/sample.bin", &data).unwrap();

        let reader = volume.open_file_reader("media/sample.bin").unwrap();
        assert_eq!(reader.path(), "media/sample.bin");
        assert!(!format!("{reader:?}").contains("media/sample.bin"));
        assert_eq!(reader.len(), data.len() as u64);
        assert!(!reader.is_empty());
        assert_eq!(
            reader.catalog_generation(),
            volume.info().unwrap().metadata_generation
        );

        let offset = 4096 - 7;
        let mut across_boundary = [0u8; 29];
        assert_eq!(
            reader.read_at(offset as u64, &mut across_boundary).unwrap(),
            across_boundary.len()
        );
        assert_eq!(
            across_boundary.as_slice(),
            &data[offset..offset + across_boundary.len()]
        );

        let mut across_eof = [0xa5; 16];
        assert_eq!(
            reader
                .read_at((data.len() - 5) as u64, &mut across_eof)
                .unwrap(),
            5
        );
        assert_eq!(&across_eof[..5], &data[data.len() - 5..]);
        assert_eq!(&across_eof[5..], &[0xa5; 11]);

        let mut beyond_eof = [0x6d; 8];
        assert_eq!(
            reader
                .read_at(data.len() as u64 + 100, &mut beyond_eof)
                .unwrap(),
            0
        );
        assert_eq!(beyond_eof, [0x6d; 8]);

        assert_eq!(
            volume
                .read_range("media/sample.bin", 4093, 19)
                .unwrap()
                .as_slice(),
            &data[4093..4112]
        );

        let mut cursor = reader.clone().cursor();
        assert_eq!(cursor.seek(SeekFrom::Start(4090)).unwrap(), 4090);
        let mut cursor_bytes = [0u8; 23];
        cursor.read_exact(&mut cursor_bytes).unwrap();
        assert_eq!(cursor_bytes.as_slice(), &data[4090..4113]);
        assert_eq!(
            cursor.seek(SeekFrom::End(-9)).unwrap(),
            data.len() as u64 - 9
        );
        let mut final_bytes = Vec::new();
        cursor.read_to_end(&mut final_bytes).unwrap();
        assert_eq!(final_bytes, data[data.len() - 9..]);

        let mut cursor = reader.cursor();
        assert!(cursor.seek(SeekFrom::Current(-1)).is_err());
    }
}

#[test]
fn cloned_readers_can_read_different_positions_at_the_same_time() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("reader-concurrent");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        let data = Arc::new(patterned_bytes(8 * 4096 + 211));
        volume.add_file("parallel.bin", data.as_slice()).unwrap();
        let reader = volume.open_file_reader("parallel.bin").unwrap();

        let barrier = Arc::new(Barrier::new(5));
        let mut threads = Vec::new();
        for worker in 0..4usize {
            let barrier = Arc::clone(&barrier);
            let data = Arc::clone(&data);
            let reader = reader.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for round in 0..24usize {
                    let offset = (worker * 977 + round * 1531) % (data.len() - 513);
                    let mut output = [0u8; 513];
                    assert_eq!(
                        reader.read_at(offset as u64, &mut output).unwrap(),
                        output.len()
                    );
                    assert_eq!(output.as_slice(), &data[offset..offset + output.len()]);
                }
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }
}

#[test]
fn failed_authentication_clears_all_requested_output_even_after_a_partial_read() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("reader-tamper");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        let data = patterned_bytes(2 * 4096);
        volume.add_file("two-chunks.bin", &data).unwrap();
        let entry = volume.catalog.find("two-chunks.bin").unwrap().clone();
        let reader = volume.open_file_reader("two-chunks.bin").unwrap();

        let second_physical = volume
            .physical_chunk_for_data_chunk(entry.start_chunk + 1)
            .unwrap();
        let corrupt_offset = record_offset(second_physical, volume.chunk_size).unwrap()
            + RECORD_NONCE_LEN as u64
            + 13;
        flip_byte_in_file(&volume.file, corrupt_offset);

        // Start eight bytes before the damaged chunk, so reading copies some
        // valid bytes before it fails. Returning an error must clear the whole
        // requested output, including the bytes that were already copied.
        let mut destination = [0xa5; 32];
        let error = reader.read_at(4096 - 8, &mut destination).unwrap_err();
        assert!(matches!(error, VaultError::Corrupt(_)));
        assert_eq!(destination, [0u8; 32]);
    }
}

#[test]
fn catalog_changes_disable_old_readers_and_closing_the_volume_releases_its_lock() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("reader-revocation");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("kept.bin", b"persistent bytes").unwrap();

        let stale = volume.open_file_reader("kept.bin").unwrap();
        volume.mkdir("new-directory").unwrap();
        let mut output = [0x5a; 4];
        let error = stale.read_at(0, &mut output).unwrap_err();
        assert!(matches!(error, VaultError::ReaderRevoked(_)));
        assert_eq!(output, [0u8; 4]);

        let current = volume.open_file_reader("kept.bin").unwrap();
        assert_eq!(current.read_at(0, &mut output).unwrap(), output.len());
        assert_eq!(&output, b"pers");
        drop(volume);

        output.fill(0x5a);
        let error = current.read_at(0, &mut output).unwrap_err();
        assert!(matches!(error, VaultError::ReaderRevoked(_)));
        assert_eq!(output, [0u8; 4]);

        // These readers are still alive, but their volume has closed. A new
        // writable volume needs the lock, so this open would fail if an old
        // reader were keeping the vault locked.
        let reopened =
            Volume::open_container(&vault_path.path, &password(b"test password")).unwrap();
        assert_eq!(
            reopened.extract_file("kept.bin").unwrap().as_slice(),
            b"persistent bytes"
        );
    }
}

#[test]
fn read_range_rejects_requests_above_the_size_limit() {
    let vault_path = TestPath::file("reader-limit");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("small.bin", b"small").unwrap();

    let error = volume
        .read_range("small.bin", 0, MAX_RANDOM_ACCESS_READ + 1)
        .unwrap_err();
    assert!(matches!(error, VaultError::FileError(_)));
}

#[test]
fn returned_plaintext_outlives_the_volume_and_is_wiped_when_dropped() {
    fn assert_wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("owned-plaintext");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        let data = patterned_bytes(4096 + 13);
        volume.add_file("data.bin", &data).unwrap();
        volume.add_file("empty.bin", b"").unwrap();

        let complete: crate::Plaintext = volume.extract_file("data.bin").unwrap();
        let tail: crate::Plaintext = volume.read_range("data.bin", 4090, 100).unwrap();
        let empty_file: crate::Plaintext = volume.extract_file("empty.bin").unwrap();
        let beyond_eof: crate::Plaintext = volume
            .read_range("data.bin", data.len() as u64 + 1, 100)
            .unwrap();
        let empty_range: crate::Plaintext = volume.read_range("data.bin", 0, 0).unwrap();
        assert_wiped_on_drop(&complete);
        assert_wiped_on_drop(&tail);
        assert_wiped_on_drop(&empty_file);
        assert_wiped_on_drop(&beyond_eof);
        assert_wiped_on_drop(&empty_range);
        drop(volume);

        assert_eq!(complete.as_slice(), data);
        assert_eq!(tail.as_slice(), &data[4090..]);
        assert!(empty_file.is_empty());
        assert!(beyond_eof.is_empty());
        assert!(empty_range.is_empty());
    }
}

#[test]
fn preview_reads_stay_correct_or_are_disabled_when_a_file_is_added() {
    let vault_path = TestPath::file("reader-during-write");
    let mut volume = create_test_vault(&vault_path.path);
    let original = patterned_bytes(3 * 4096);
    volume.add_file("original.bin", &original).unwrap();
    let reader = volume.open_file_reader("original.bin").unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let start = Arc::clone(&barrier);
    let thread = std::thread::spawn(move || {
        start.wait();
        for _ in 0..1000 {
            let mut output = vec![0; original.len()];
            match reader.read_at(0, &mut output) {
                Ok(length) => {
                    assert_eq!(length, original.len());
                    assert_eq!(output, original);
                }
                Err(VaultError::ReaderRevoked(_)) => {
                    assert!(output.iter().all(|byte| *byte == 0));
                    return;
                }
                Err(error) => panic!("concurrent preview failed: {error}"),
            }
        }
    });
    barrier.wait();
    let added = patterned_bytes(24 * 4096);
    volume.add_file("added.bin", &added).unwrap();
    thread.join().unwrap();
    assert_eq!(volume.extract_file("added.bin").unwrap().as_slice(), added);
    volume.verify().unwrap();
    drop(volume);
    Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
        .unwrap()
        .verify()
        .unwrap();
}
