use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
};

use super::{TEST_CIPHERS, TestPath, password};
use crate::{
    CreateOptions, MIN_METADATA_CAPACITY, VaultError, Volume,
    header::DATA_AREA_OFFSET,
    kdf::KdfParams,
    volume::{chunk_io::record_size, metadata::METADATA_COPY_COUNT},
};

fn first_file_data_record_offset(volume: &Volume) -> u64 {
    let physical = volume.metadata_copy_chunks * METADATA_COPY_COUNT as u64;
    DATA_AREA_OFFSET + physical * record_size(volume.chunk_size).unwrap()
}

#[test]
fn creating_a_vault_does_not_replace_an_existing_file() {
    let existing = TestPath::file("existing");
    std::fs::write(&existing.path, b"sentinel").unwrap();
    assert!(
        Volume::create_container_with_kdf(
            &existing.path,
            &password(b"pw"),
            4096,
            4096,
            KdfParams::for_tests(),
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&existing.path).unwrap(), b"sentinel");
}

#[test]
fn invalid_password_derivation_settings_create_no_files() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("invalid-kdf-create");
        let result = Volume::create_container_with_kdf_and_options(
            &vault_path.path,
            &password(b"test password"),
            4096,
            4096,
            CreateOptions {
                cipher,
                metadata_capacity: Some(MIN_METADATA_CAPACITY),
                fill_data_area: true,
            },
            KdfParams::Argon2id {
                memory_cost: 0,
                time_cost: 1,
                parallelism: 1,
            },
        );

        assert!(matches!(result, Err(VaultError::KdfError(_))));
        assert!(
            std::fs::read_dir(vault_path.path.parent().unwrap())
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[test]
fn creation_can_fill_unused_storage_with_random_bytes() {
    fn create_and_read_record(fill_data_area: bool) -> Vec<u8> {
        let vault_path = TestPath::file(if fill_data_area {
            "filled-create"
        } else {
            "sparse-create"
        });
        let volume = Volume::create_container_with_kdf_and_options(
            &vault_path.path,
            &password(b"test password"),
            4096,
            4096,
            CreateOptions {
                metadata_capacity: Some(MIN_METADATA_CAPACITY),
                fill_data_area,
                ..CreateOptions::default()
            },
            KdfParams::for_tests(),
        )
        .unwrap();
        let offset = first_file_data_record_offset(&volume);
        let length = record_size(volume.chunk_size).unwrap() as usize;
        drop(volume);

        let mut file = OpenOptions::new()
            .read(true)
            .open(&vault_path.path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut record = vec![0u8; length];
        file.read_exact(&mut record).unwrap();
        let reopened =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(reopened.list_files().unwrap().is_empty());
        record
    }

    assert!(create_and_read_record(false).iter().all(|byte| *byte == 0));
    assert!(create_and_read_record(true).iter().any(|byte| *byte != 0));
}

#[test]
fn requested_catalog_capacity_is_met_with_less_than_one_extra_chunk() {
    let vault_path = TestPath::file("metadata-capacity");
    let requested = 8 * 1024 * 1024 + 1;
    let volume = Volume::create_container_with_kdf_and_options(
        &vault_path.path,
        &password(b"test password"),
        4096,
        4096,
        CreateOptions {
            metadata_capacity: Some(requested),
            fill_data_area: false,
            ..CreateOptions::default()
        },
        KdfParams::for_tests(),
    )
    .unwrap();
    let actual = volume.info().unwrap().metadata_capacity;
    assert!(actual >= requested);
    assert!(actual < requested + volume.chunk_size as u64);
}
