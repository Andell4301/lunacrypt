use super::{TEST_CIPHERS, TestPath, create_test_vault_with_cipher, password};
use crate::{
    VaultError, Volume,
    volume::{
        file_table::FileEntry,
        metadata::{
            METADATA_COPY_COUNT, SnapshotWritePhase, inject_snapshot_failure,
            prepare_catalog_snapshot, write_snapshot,
        },
    },
};

#[test]
fn outdated_catalog_changes_cannot_overwrite_a_newer_saved_update() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("persistence-prepared");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("kept.txt", b"kept").unwrap();
        volume.add_file("removed.txt", b"removed").unwrap();
        let reader = volume.open_file_reader("kept.txt").unwrap();
        let before = volume.info().unwrap();

        let mut stale_catalog = volume.catalog.clone();
        stale_catalog
            .insert(FileEntry::new_directory("stale-directory".to_string()).unwrap())
            .unwrap();
        let stale = volume.prepare_catalog(stale_catalog).unwrap();

        let mut next = volume.catalog.clone();
        next.remove("removed.txt").unwrap();
        next.insert(FileEntry::new_directory("committed-directory".to_string()).unwrap())
            .unwrap();
        let prepared = volume.prepare_catalog(next).unwrap();
        volume.commit_catalog(prepared).unwrap();

        let committed = volume.info().unwrap();
        assert_eq!(
            committed.metadata_generation,
            before.metadata_generation + 1
        );
        assert_eq!(
            committed.free_space,
            before.free_space + u64::from(before.chunk_size)
        );
        assert!(!committed.redundancy_degraded);
        assert!(volume.stat("removed.txt").is_err());
        assert!(volume.stat("committed-directory").unwrap().is_directory);
        let mut destination = [0xa5; 4];
        assert!(matches!(
            reader.read_at(0, &mut destination),
            Err(VaultError::ReaderRevoked(_))
        ));
        assert_eq!(destination, [0; 4]);

        let current_reader = volume.open_file_reader("kept.txt").unwrap();
        assert!(matches!(
            volume.commit_catalog(stale),
            Err(VaultError::FileError(_))
        ));
        assert_eq!(volume.info().unwrap(), committed);
        assert_eq!(current_reader.read_at(0, &mut destination).unwrap(), 4);
        assert_eq!(&destination, b"kept");
        drop(volume);

        let reopened =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert_eq!(
            reopened.info().unwrap().metadata_generation,
            committed.metadata_generation
        );
        assert!(reopened.stat("committed-directory").is_ok());
        assert!(reopened.stat("stale-directory").is_err());
        assert!(reopened.stat("removed.txt").is_err());
    }
}

#[test]
fn prepared_catalog_changes_cannot_be_saved_through_another_open_volume() {
    for cipher in TEST_CIPHERS {
        let source_path = TestPath::file("persistence-source");
        let copy_path = TestPath::file("persistence-copy");
        let mut source = create_test_vault_with_cipher(&source_path.path, cipher);
        source.add_file("kept.txt", b"kept").unwrap();
        source.export_container_to_path(&copy_path.path).unwrap();
        let mut copy =
            Volume::open_container(&copy_path.path, &password(b"test password")).unwrap();
        assert_eq!(source.container_id, copy.container_id);
        assert_eq!(source.metadata_generation, copy.metadata_generation);

        let mut candidate = source.catalog.clone();
        candidate
            .insert(FileEntry::new_directory("foreign-directory".to_string()).unwrap())
            .unwrap();
        let prepared = source.prepare_catalog(candidate).unwrap();
        let reader = copy.open_file_reader("kept.txt").unwrap();
        let before = copy.info().unwrap();
        assert!(matches!(
            copy.commit_catalog(prepared),
            Err(VaultError::FileError(_))
        ));
        assert_eq!(copy.info().unwrap(), before);
        assert!(copy.stat("foreign-directory").is_err());
        let mut destination = [0; 4];
        assert_eq!(reader.read_at(0, &mut destination).unwrap(), 4);
        assert_eq!(&destination, b"kept");
        drop(copy);

        let reopened =
            Volume::open_container_read_only(&copy_path.path, &password(b"test password")).unwrap();
        assert!(reopened.stat("foreign-directory").is_err());
        assert_eq!(
            reopened.info().unwrap().metadata_generation,
            before.metadata_generation
        );
    }
}

#[test]
fn opening_recovers_a_catalog_update_saved_to_only_one_copy() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("metadata-interrupted");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("old.txt", b"old").unwrap();

        let mut candidate = volume.catalog.clone();
        candidate
            .insert(FileEntry::new_directory("new-directory".to_string()).unwrap())
            .unwrap();
        let generation = volume.metadata_generation + 1;
        let prepared =
            prepare_catalog_snapshot(&candidate, volume.metadata_copy_chunks, volume.chunk_size)
                .unwrap();
        let slot = generation as usize % METADATA_COPY_COUNT;
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
        drop(volume); // Simulate stopping before the second catalog copy was updated.

        let reader =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(reader.stat("new-directory").unwrap().is_directory);
        assert!(reader.info().unwrap().redundancy_degraded);
        drop(reader);

        drop(Volume::open_container(&vault_path.path, &password(b"test password")).unwrap());
        let reader =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(!reader.info().unwrap().redundancy_degraded);
        assert!(reader.stat("new-directory").is_ok());
    }
}

#[test]
fn failure_before_saving_the_catalog_disables_the_volume_and_existing_readers() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("persistence-precommit-failure");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("kept.txt", b"kept").unwrap();
        let reader = volume.open_file_reader("kept.txt").unwrap();

        let next_generation = volume.metadata_generation + 1;
        let first_slot = next_generation as usize % 2;
        let _failure = inject_snapshot_failure(first_slot, SnapshotWritePhase::BeforeHead);
        let error = volume.mkdir("not-committed").unwrap_err();
        assert!(matches!(error, VaultError::FileError(_)));
        assert!(matches!(volume.info(), Err(VaultError::Poisoned(_))));

        let mut destination = [0xa5; 4];
        assert!(matches!(
            reader.read_at(0, &mut destination),
            Err(VaultError::ReaderRevoked(_))
        ));
        assert_eq!(destination, [0; 4]);
        drop(volume);

        let reopened =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(reopened.stat("not-committed").is_err());
        assert_eq!(
            reopened.extract_file("kept.txt").unwrap().as_slice(),
            b"kept"
        );
    }
}

#[test]
fn failure_saving_the_second_catalog_copy_reports_uncertainty_and_recovers_the_update() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("persistence-mirror-failure");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("kept.txt", b"kept").unwrap();

        let next_generation = volume.metadata_generation + 1;
        let first_slot = next_generation as usize % 2;
        let second_slot = 1 - first_slot;
        let _failure = inject_snapshot_failure(second_slot, SnapshotWritePhase::BeforeHead);
        let error = volume.mkdir("committed").unwrap_err();
        assert!(matches!(error, VaultError::CommitUncertain(_)));
        assert!(matches!(volume.info(), Err(VaultError::Poisoned(_))));
        drop(volume);

        let read_only =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(read_only.stat("committed").unwrap().is_directory);
        assert!(read_only.info().unwrap().redundancy_degraded);
        drop(read_only);

        drop(Volume::open_container(&vault_path.path, &password(b"test password")).unwrap());
        let repaired =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert!(repaired.stat("committed").is_ok());
        assert!(!repaired.info().unwrap().redundancy_degraded);
    }
}

#[test]
fn interrupted_catalog_writes_keep_the_last_fully_saved_copy() {
    for cipher in TEST_CIPHERS {
        for fail_mirror in [false, true] {
            let vault_path = TestPath::file("persistence-body-replaced");
            let volume = create_test_vault_with_cipher(&vault_path.path, cipher);
            let mut baseline = volume.catalog.clone();
            for index in 0..128 {
                baseline
                    .insert(
                        FileEntry::new_directory(format!("existing-directory-{index:03}")).unwrap(),
                    )
                    .unwrap();
            }
            let generation = volume.metadata_generation + 1;
            let prepared =
                prepare_catalog_snapshot(&baseline, volume.metadata_copy_chunks, volume.chunk_size)
                    .unwrap();
            assert!(baseline.encoded_len().unwrap() > volume.chunk_size as usize);
            for slot in 0..METADATA_COPY_COUNT {
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

            let mut volume =
                Volume::open_container(&vault_path.path, &password(b"test password")).unwrap();
            let first_slot = (volume.metadata_generation + 1) as usize % METADATA_COPY_COUNT;
            let failing_slot = if fail_mirror {
                1 - first_slot
            } else {
                first_slot
            };
            // By this point we've replaced the later catalog chunks on disk,
            // but the header still has the old hash. This copy can no longer
            // be read. Stopping here checks that opening keeps the last complete
            // copy, whether we were updating the first copy or the second.
            let _failure =
                inject_snapshot_failure(failing_slot, SnapshotWritePhase::PublishingHead);
            assert!(matches!(
                volume.mkdir("added-directory"),
                Err(VaultError::CommitUncertain(_))
            ));
            drop(volume);

            let reopened =
                Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                    .unwrap();
            assert_eq!(reopened.stat("added-directory").is_ok(), fail_mirror);
            assert!(reopened.stat("existing-directory-127").is_ok());
            assert!(reopened.info().unwrap().redundancy_degraded);
            drop(reopened);

            drop(Volume::open_container(&vault_path.path, &password(b"test password")).unwrap());
            let repaired =
                Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                    .unwrap();
            assert_eq!(repaired.stat("added-directory").is_ok(), fail_mirror);
            assert!(!repaired.info().unwrap().redundancy_degraded);
        }
    }
}
