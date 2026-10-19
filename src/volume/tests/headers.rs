use super::{
    TEST_CIPHERS, TestPath, create_test_vault, create_test_vault_with_cipher, flip_byte, password,
    read_file_bytes,
};
use crate::{
    VaultError, Volume,
    header::{HEADER_SLOT_SIZE, build_slot, write_slot},
    kdf::KdfParams,
};

#[test]
fn password_changes_keep_file_contents_even_if_only_one_header_copy_is_updated() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("password-change");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("secret.txt", b"secret").unwrap();
        let new_password = password(b"new test password");
        volume
            .change_password_with_kdf(&new_password, KdfParams::for_tests())
            .unwrap();
        drop(volume);
        assert!(
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .is_err()
        );
        let reopened = Volume::open_container(&vault_path.path, &new_password).unwrap();
        assert_eq!(reopened.info().unwrap().cipher, cipher);
        assert_eq!(
            reopened.extract_file("secret.txt").unwrap().as_slice(),
            b"secret"
        );

        let third_password = password(b"third password");
        let next_generation = reopened.header_generation + 1;
        let slot = next_generation as usize % 2;
        let raw = build_slot(
            slot,
            next_generation,
            &third_password,
            KdfParams::for_tests(),
            &reopened.header_payload,
        )
        .unwrap();
        write_slot(&reopened.file, slot, &raw).unwrap();
        reopened.file.sync_all().unwrap();
        drop(reopened); // Simulate stopping after only one header copy was updated.

        assert!(Volume::open_container_read_only(&vault_path.path, &new_password).is_err());
        let recovered = Volume::open_container(&vault_path.path, &third_password).unwrap();
        assert_eq!(recovered.info().unwrap().cipher, cipher);
        assert_eq!(
            recovered.extract_file("secret.txt").unwrap().as_slice(),
            b"secret"
        );
        drop(recovered);
        assert!(Volume::open_container_read_only(&vault_path.path, &new_password).is_err());
    }
}

#[test]
fn opening_for_writing_repairs_one_damaged_header_copy() {
    let vault_path = TestPath::file("header-volume-repair");
    drop(create_test_vault(&vault_path.path));
    flip_byte(&vault_path.path, HEADER_SLOT_SIZE as u64 + 200);
    let reader =
        Volume::open_container_read_only(&vault_path.path, &password(b"test password")).unwrap();
    assert!(reader.info().unwrap().redundancy_degraded);
    drop(reader);
    drop(Volume::open_container(&vault_path.path, &password(b"test password")).unwrap());
    assert!(
        !Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
            .unwrap()
            .info()
            .unwrap()
            .redundancy_degraded
    );
}

#[test]
fn password_changes_that_fail_before_writing_keep_existing_readers_working() {
    let vault_path = TestPath::file("password-prepare-failure");
    let mut volume = create_test_vault(&vault_path.path);
    volume.add_file("secret.txt", b"secret").unwrap();
    let reader = volume.open_file_reader("secret.txt").unwrap();
    volume.header_generation = u64::MAX;

    assert!(
        volume
            .change_password_with_kdf(&password(b"new password"), KdfParams::for_tests())
            .is_err()
    );
    let mut bytes = [0; 6];
    assert_eq!(reader.read_at(0, &mut bytes).unwrap(), bytes.len());
    assert_eq!(&bytes, b"secret");
    assert!(volume.info().is_ok());
    drop(volume);

    let reopened =
        Volume::open_container_read_only(&vault_path.path, &password(b"test password")).unwrap();
    assert_eq!(
        reopened.extract_file("secret.txt").unwrap().as_slice(),
        b"secret"
    );
}

#[test]
fn invalid_password_derivation_settings_leave_the_password_and_readers_unchanged() {
    for cipher in TEST_CIPHERS {
        let vault_path = TestPath::file("invalid-kdf-password-change");
        let mut volume = create_test_vault_with_cipher(&vault_path.path, cipher);
        volume.add_file("secret.txt", b"secret").unwrap();
        let reader = volume.open_file_reader("secret.txt").unwrap();
        let original = read_file_bytes(&volume.file);

        let result = volume.change_password_with_kdf(
            &password(b"new password"),
            KdfParams::Argon2id {
                memory_cost: 0,
                time_cost: 1,
                parallelism: 1,
            },
        );

        assert!(matches!(result, Err(VaultError::KdfError(_))));
        assert_eq!(read_file_bytes(&volume.file), original);
        let mut bytes = [0; 6];
        assert_eq!(reader.read_at(0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes, b"secret");
        assert!(volume.info().is_ok());
        drop(reader);
        drop(volume);

        let reopened =
            Volume::open_container_read_only(&vault_path.path, &password(b"test password"))
                .unwrap();
        assert_eq!(
            reopened.extract_file("secret.txt").unwrap().as_slice(),
            b"secret"
        );
    }
}
