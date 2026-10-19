use sha2::{Digest, Sha256};

use super::{
    TEST_CIPHERS, TestPath, create_test_vault, create_test_vault_with_cipher, flip_byte, password,
};
use crate::{
    VaultError, Volume,
    header::DATA_AREA_OFFSET,
    volume::{
        chunk_io::{RECORD_NONCE_LEN, metadata_chunk_aad, read_record, record_size, write_record},
        file_table::FileEntry,
        metadata::{
            METADATA_COPY_COUNT, catalog_decode_count, prepare_catalog_snapshot,
            reset_catalog_decode_count, write_snapshot,
        },
    },
};

fn metadata_record_offset(volume: &Volume, slot: usize) -> u64 {
    let physical = slot as u64 * volume.metadata_copy_chunks;
    DATA_AREA_OFFSET + physical * record_size(volume.chunk_size).unwrap()
}

#[test]
fn opening_a_healthy_vault_builds_only_one_catalog_in_memory() {
    let vault_path = TestPath::file("persistence-single-catalog-decode");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("kept.txt", b"kept").unwrap();
    drop(volume);

    // Opening needs to check both copies, but it only needs to rebuild one
    // catalog in memory. Rebuilding both would briefly double the memory used
    // by a large catalog.
    reset_catalog_decode_count();
    let reopened =
        Volume::open_container_read_only(&vault_path.path, &password(b"test password")).unwrap();
    assert_eq!(catalog_decode_count(), 1);
    assert_eq!(
        reopened.extract_file("kept.txt").unwrap().as_slice(),
        b"kept"
    );
}

#[test]
fn a_damaged_catalog_copy_is_reported_and_repaired() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("metadata-repair");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("saved.txt", b"durable").unwrap();
        let corrupt_offset = metadata_record_offset(&volume, 1) + RECORD_NONCE_LEN as u64 + 7;
        drop(volume);
        flip_byte(&vault_path.path, corrupt_offset);

        let reader =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(reader.info().unwrap().redundancy_degraded);
        assert_eq!(
            reader.extract_file("saved.txt").unwrap().as_slice(),
            b"durable"
        );
        drop(reader);

        drop(Volume::open_container(&vault_path.path, &password(b"test password")).unwrap());
        let reader =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(!reader.info().unwrap().redundancy_degraded);
    }
}

#[test]
fn opening_rejects_damage_to_both_catalog_copy_headers() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("metadata-both-bad");
        let volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        let offsets: Vec<u64> = (0..METADATA_COPY_COUNT)
            .map(|slot| metadata_record_offset(&volume, slot) + RECORD_NONCE_LEN as u64 + 3)
            .collect();
        drop(volume);
        for offset in offsets {
            flip_byte(&vault_path.path, offset);
        }
        assert!(
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .is_err()
        );
    }
}

#[test]
fn a_newer_catalog_with_damaged_contents_cannot_be_replaced_by_an_older_copy() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("metadata-newer-body-corrupt");
        let volume = create_test_vault_with_cipher(&vault_path.path, cipher);

        let mut candidate = volume.catalog.clone();
        for index in 0..128 {
            candidate
                .insert(
                    FileEntry::new_directory(format!("new-generation-entry-{index:03}")).unwrap(),
                )
                .unwrap();
        }
        let generation = volume.metadata_generation + 1;
        let slot = generation as usize % METADATA_COPY_COUNT;
        let prepared =
            prepare_catalog_snapshot(&candidate, volume.metadata_copy_chunks, volume.chunk_size)
                .unwrap();
        write_snapshot(
            &volume.file,
            &volume.metadata_cipher,
            &volume.container_id,
            volume.chunk_size,
            volume.metadata_copy_chunks,
            slot,
            generation,
            &prepared,
        )
        .unwrap();
        // The valid newer header tells us an update was saved. Damage its
        // contents while leaving that header intact. Falling back to the old
        // copy could lose saved changes, so opening must fail here.
        let body_offset = metadata_record_offset(&volume, slot)
            + record_size(volume.chunk_size).unwrap()
            + RECORD_NONCE_LEN as u64
            + 9;
        drop(volume);
        flip_byte(&vault_path.path, body_offset);

        let error =
            match Volume::open_container_read_only(&vault_path.path, &password(b"test password")) {
                Ok(_) => panic!("vault unexpectedly rolled back to older metadata"),
                Err(error) => error,
            };
        assert!(
            matches!(error, VaultError::Corrupt(message) if message.contains("refusing to roll back"))
        );
    }
}

#[test]
fn catalog_copies_with_the_same_update_number_must_agree() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("metadata-split-brain");
        let volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        let generation = volume.metadata_generation + 1;

        for (slot, name) in ["copy-zero", "copy-one"].into_iter().enumerate() {
            let mut candidate = volume.catalog.clone();
            candidate
                .insert(FileEntry::new_directory(name.to_string()).unwrap())
                .unwrap();
            let prepared = prepare_catalog_snapshot(
                &candidate,
                volume.metadata_copy_chunks,
                volume.chunk_size,
            )
            .unwrap();
            write_snapshot(
                &volume.file,
                &volume.metadata_cipher,
                &volume.container_id,
                volume.chunk_size,
                volume.metadata_copy_chunks,
                slot,
                generation,
                &prepared,
            )
            .unwrap();
        }
        drop(volume);

        let error =
            match Volume::open_container_read_only(&vault_path.path, &password(b"test password")) {
                Ok(_) => panic!("split-brain metadata unexpectedly opened"),
                Err(error) => error,
            };
        assert!(
            matches!(error, VaultError::Corrupt(message) if message.contains("disagree at the same generation"))
        );
    }
}

#[test]
fn damaged_contents_cannot_hide_conflicting_catalog_copies_at_the_same_update_number() {
    let vault_path = TestPath::file("metadata-split-brain-corrupt-body");
    let volume = create_test_vault(&vault_path.path);
    let generation = volume.metadata_generation + 1;

    for (slot, prefix) in ["copy-zero", "copy-one"].into_iter().enumerate() {
        let mut candidate = volume.catalog.clone();
        for index in 0..128 {
            candidate
                .insert(FileEntry::new_directory(format!("{prefix}-entry-{index:03}")).unwrap())
                .unwrap();
        }
        let prepared =
            prepare_catalog_snapshot(&candidate, volume.metadata_copy_chunks, volume.chunk_size)
                .unwrap();
        write_snapshot(
            &volume.file,
            &volume.metadata_cipher,
            &volume.container_id,
            volume.chunk_size,
            volume.metadata_copy_chunks,
            slot,
            generation,
            &prepared,
        )
        .unwrap();
    }

    let corrupt_slot = 1;
    let body_offset = metadata_record_offset(&volume, corrupt_slot)
        + record_size(volume.chunk_size).unwrap()
        + RECORD_NONCE_LEN as u64
        + 11;
    drop(volume);
    flip_byte(&vault_path.path, body_offset);

    let read_only =
        match Volume::open_container_read_only(&vault_path.path, &password(b"test password")) {
            Ok(_) => panic!("read-only open accepted conflicting metadata heads"),
            Err(error) => error,
        };
    assert!(
        matches!(read_only, VaultError::Corrupt(message) if message.contains("disagree at the same generation"))
    );

    let writable = match Volume::open_container(&vault_path.path, &password(b"test password")) {
        Ok(_) => panic!("writable open repaired over a conflicting metadata head"),
        Err(error) => error,
    };
    assert!(
        matches!(writable, VaultError::Corrupt(message) if message.contains("disagree at the same generation"))
    );
}

#[test]
fn an_invalid_newer_catalog_cannot_be_replaced_by_an_older_copy() {
    let vault_path = TestPath::file("persistence-invalid-newer-catalog");
    let volume = create_test_vault(&vault_path.path);
    let slot = 0;
    let physical = slot as u64 * volume.metadata_copy_chunks;
    let aad = metadata_chunk_aad(&volume.container_id, slot, 0, physical, volume.chunk_size);
    let mut head = read_record(
        &volume.file,
        &volume.metadata_cipher,
        volume.chunk_size,
        physical,
        &aad,
    )
    .unwrap();

    let generation = u64::from_be_bytes(head[12..20].try_into().unwrap()) + 1;
    head[12..20].copy_from_slice(&generation.to_be_bytes());
    let head_len = u16::from_be_bytes(head[10..12].try_into().unwrap()) as usize;
    let catalog_len = u64::from_be_bytes(head[20..28].try_into().unwrap()) as usize;
    assert!(head_len + catalog_len <= head.len());
    // We want the catalog to pass the hash and tag checks but still be invalid.
    // Change its signature, then update the hash and re-encrypt below. This
    // makes loading reach the catalog format check we're trying to test.
    head[head_len] ^= 0x80;
    let digest: [u8; 32] = Sha256::digest(&head[head_len..head_len + catalog_len]).into();
    head[36..68].copy_from_slice(&digest);
    write_record(
        &volume.file,
        &volume.metadata_cipher,
        volume.chunk_size,
        physical,
        &aad,
        head.as_slice(),
    )
    .unwrap();
    volume.file.sync_all().unwrap();
    drop(volume);

    for writable in [false, true] {
        let result = if writable {
            Volume::open_container(&vault_path.path, &password(b"test password"))
        } else {
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
        };
        let error = match result {
            Ok(_) => panic!("vault unexpectedly rolled back from an invalid newer catalog"),
            Err(error) => error,
        };
        assert!(
            matches!(error, VaultError::Corrupt(message) if message.contains("refusing to roll back"))
        );
    }
}

#[test]
fn a_catalog_header_with_a_valid_tag_but_invalid_fields_is_rejected_without_repair() {
    let vault_path = TestPath::file("persistence-malformed-authenticated-head");
    let volume = create_test_vault(&vault_path.path);
    let slot = 1;
    let physical = slot as u64 * volume.metadata_copy_chunks;
    let aad = metadata_chunk_aad(&volume.container_id, slot, 0, physical, volume.chunk_size);
    let mut head = read_record(
        &volume.file,
        &volume.metadata_cipher,
        volume.chunk_size,
        physical,
        &aad,
    )
    .unwrap();

    // This copy still claims the same update number and catalog hash as the
    // healthy copy. Set a reserved byte that must be zero, then re-encrypt so
    // its tag is valid. Matching those fields mustn't hide an invalid header.
    head[68] = 1;
    write_record(
        &volume.file,
        &volume.metadata_cipher,
        volume.chunk_size,
        physical,
        &aad,
        head.as_slice(),
    )
    .unwrap();
    volume.file.sync_all().unwrap();
    drop(volume);

    for writable in [false, true] {
        let result = if writable {
            Volume::open_container(&vault_path.path, &password(b"test password"))
        } else {
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
        };
        let error = match result {
            Ok(_) => panic!("malformed authenticated head was accepted or repaired"),
            Err(error) => error,
        };
        assert!(
            matches!(error, VaultError::Corrupt(message) if message.contains("authenticated metadata head is malformed"))
        );
    }
}
