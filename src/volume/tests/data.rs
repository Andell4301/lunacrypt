use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
};

use super::{TEST_CIPHERS, TestPath, create_test_vault_with_cipher, password};
use crate::{
    VaultError, Volume,
    header::DATA_AREA_OFFSET,
    volume::chunk_io::{data_chunk_aad, record_size, write_record},
};

#[test]
fn deleted_file_space_can_be_reused_without_bringing_the_file_back() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("delete-reuse");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("a.bin", b"a").unwrap();
        volume.add_file("b.bin", b"b").unwrap();
        let retired = volume.catalog.find("a.bin").unwrap().start_chunk;
        volume.remove("a.bin", false).unwrap();
        volume.add_file("c.bin", b"c").unwrap();
        assert_eq!(volume.catalog.find("c.bin").unwrap().start_chunk, retired);
        drop(volume);

        let reopened =
            Volume::open_container(&vault_path.path, &password(b"test password")).unwrap();
        assert!(reopened.stat("a.bin").is_err());
        assert_eq!(reopened.extract_file("b.bin").unwrap().as_slice(), b"b");
        assert_eq!(reopened.extract_file("c.bin").unwrap().as_slice(), b"c");
    }
}

#[test]
fn verification_rejects_a_file_chunk_copied_to_a_different_position() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("data-tamper");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("two.bin", &vec![9u8; 8192]).unwrap();
        let entry = volume.catalog.find("two.bin").unwrap().clone();
        let data_start = volume.metadata_copy_chunks * 2;
        let record_len = record_size(volume.chunk_size).unwrap();
        let first_offset = DATA_AREA_OFFSET + (data_start + entry.start_chunk) * record_len;
        let second_offset = first_offset + record_len;
        drop(volume);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&vault_path.path)
            .unwrap();
        let mut first = vec![0u8; record_len as usize];
        file.seek(SeekFrom::Start(first_offset)).unwrap();
        file.read_exact(&mut first).unwrap();
        file.seek(SeekFrom::Start(second_offset)).unwrap();
        file.write_all(&first).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let reader =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(reader.verify().is_err());
    }
}

#[test]
fn all_read_methods_reject_nonzero_file_padding_even_with_a_valid_tag() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("extract-padding");
        let destination = TestPath::directory("extract-padding-destination");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("padded.bin", &vec![0x5a; 4097]).unwrap();
        let entry = volume.catalog.find("padded.bin").unwrap().clone();

        // The last chunk has one real file byte followed by zero padding.
        // Give it a nonzero padding byte, then encrypt it normally so its tag
        // is valid. Otherwise we'd only test whether changing encrypted bytes
        // breaks the tag, without reaching the padding check.
        let logical = entry.num_chunks - 1;
        let physical = volume
            .physical_chunk_for_data_chunk(entry.start_chunk + logical)
            .unwrap();
        let aad = data_chunk_aad(
            &volume.container_id,
            &entry.file_id,
            logical,
            physical,
            volume.chunk_size,
        );
        let mut plaintext = vec![0u8; volume.chunk_size as usize];
        plaintext[0] = 0x5a;
        plaintext[1] = 0x01;
        write_record(
            &volume.file,
            &volume.data_cipher,
            volume.chunk_size,
            physical,
            &aad,
            &plaintext,
        )
        .unwrap();
        volume.file.sync_data().unwrap();

        assert!(matches!(volume.verify(), Err(VaultError::Corrupt(_))));
        assert!(matches!(
            volume.extract_file("padded.bin"),
            Err(VaultError::Corrupt(_))
        ));

        let reader = volume.open_file_reader("padded.bin").unwrap();
        let mut byte = [0xa5];
        assert!(matches!(
            reader.read_at(4096, &mut byte),
            Err(VaultError::Corrupt(_))
        ));
        assert_eq!(byte, [0]);

        let target = destination.path.join("padded.bin");
        assert!(matches!(
            volume.extract_file_to_path("padded.bin", &target),
            Err(VaultError::Corrupt(_))
        ));
        assert!(!target.exists());
        assert!(
            std::fs::read_dir(&destination.path)
                .unwrap()
                .next()
                .is_none()
        );
    }
}
