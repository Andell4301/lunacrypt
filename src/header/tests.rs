use std::io::{Read, Seek, SeekFrom, Write};

use super::{
    slot::{
        CIPHERTEXT_OFFSET, KDF_OFFSET, NONCE_OFFSET, OUTER_MAC_OFFSET, RESERVED_OFFSET,
        SALT_OFFSET, outer_mac_bytes,
    },
    *,
};
use crate::{
    CipherId,
    kdf::KdfParams,
    test_support::{TEST_CIPHERS, TestPath, password},
};

fn temp_file() -> (TestPath, File) {
    let path = TestPath::file("header");
    let file = path.create_file();
    file.set_len(DATA_AREA_OFFSET).unwrap();
    (path, file)
}

#[test]
fn changing_the_encrypted_cipher_choice_fails_authentication() {
    let pw = password(b"example password");
    for cipher_id in TEST_CIPHERS {
        let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
        let mut raw = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
        let parsed = parse_slot(raw, 0).unwrap().unwrap();
        let decoded = decrypt_slot(&parsed, &pw).unwrap().unwrap();
        assert_eq!(decoded.payload.fields().cipher_id, cipher_id);

        // Flip the encrypted byte where the payload stores its cipher choice.
        // Recalculate the outer MAC so that check passes. The cipher's own
        // authentication tag must still reject the changed ciphertext.
        raw[CIPHERTEXT_OFFSET + 20] ^=
            u8::from(CipherId::XChaCha20Poly1305) ^ u8::from(CipherId::Aes256GcmSiv);
        let mac = outer_mac_bytes(&raw, 0, payload.master_key()).unwrap();
        raw[OUTER_MAC_OFFSET..RESERVED_OFFSET].copy_from_slice(&mac);
        let tampered = parse_slot(raw, 0).unwrap().unwrap();
        assert!(outer_mac_valid(&tampered, payload.master_key()).unwrap());
        assert!(decrypt_slot(&tampered, &pw).unwrap().is_none());
    }
}

#[test]
fn wrong_password_fails_authentication_but_empty_password_fails_validation() {
    let pw = password(b"example password");
    for cipher_id in TEST_CIPHERS {
        let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
        let raw = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
        let parsed = parse_slot(raw, 0).unwrap().unwrap();
        assert!(
            decrypt_slot(&parsed, &password(b"wrong password"))
                .unwrap()
                .is_none()
        );
        let failure = decrypt_slot(&parsed, &password(b""));
        assert!(matches!(failure, Err(VaultError::KdfError(_))));
    }
}

#[test]
fn header_copies_with_the_same_update_number_must_choose_the_same_cipher() {
    let (_path, file) = temp_file();
    let pw = password(b"example password");
    let kdf = KdfParams::for_tests();
    let payload = HeaderPayload::create(CipherId::XChaCha20Poly1305, 4096, 100, 256).unwrap();
    let first = build_slot(0, 1, &pw, kdf, &payload).unwrap();
    let mut bytes = payload.to_bytes(1);
    bytes[20] = CipherId::Aes256GcmSiv.into();
    let other_payload = HeaderPayload::from_bytes(&bytes, 1).unwrap();
    let second = build_slot(1, 1, &pw, kdf, &other_payload).unwrap();
    write_slot(&file, 0, &first).unwrap();
    write_slot(&file, 1, &second).unwrap();
    assert!(open_pair(&file, &pw).is_err());
    drop(file);
}

#[test]
fn header_copies_use_different_salts_and_nonces() {
    let pw = password(b"example password");
    let payload = HeaderPayload::create(CipherId::XChaCha20Poly1305, 4096, 100, 256).unwrap();
    let pair = build_pair(1, &pw, KdfParams::for_tests(), &payload).unwrap();
    assert_ne!(
        pair[0][SALT_OFFSET..KDF_OFFSET],
        pair[1][SALT_OFFSET..KDF_OFFSET]
    );
    assert_ne!(
        pair[0][NONCE_OFFSET..CIPHERTEXT_OFFSET],
        pair[1][NONCE_OFFSET..CIPHERTEXT_OFFSET],
    );
}

#[test]
fn header_copies_cannot_be_moved_between_slots() {
    let pw = password(b"example password");
    for cipher_id in TEST_CIPHERS {
        let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
        let raw = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
        let moved = parse_slot(raw, 1).unwrap().unwrap();
        assert!(decrypt_slot(&moved, &pw).unwrap().is_none());
        assert!(!outer_mac_valid(&moved, payload.master_key()).unwrap());
    }
}

#[test]
fn header_parsing_rejects_invalid_password_derivation_settings() {
    let pw = password(b"example password");
    let payload = HeaderPayload::create(CipherId::XChaCha20Poly1305, 4096, 100, 256).unwrap();
    let original = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
    for parameter_offset in [4, 8, 12] {
        for cost in [0u32, u32::MAX] {
            let mut raw = original;
            let start = KDF_OFFSET + parameter_offset;
            raw[start..start + 4].copy_from_slice(&cost.to_be_bytes());
            assert!(parse_slot(raw, 0).unwrap().is_none());
        }
    }
}

#[test]
fn one_damaged_header_copy_can_be_repaired() {
    for cipher_id in TEST_CIPHERS {
        let (_path, mut file) = temp_file();
        let kdf = KdfParams::for_tests();
        let pw = password(b"example password");
        let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
        let pair = build_pair(1, &pw, kdf, &payload).unwrap();
        write_slot(&file, 0, &pair[0]).unwrap();
        write_slot(&file, 1, &pair[1]).unwrap();
        file.sync_all().unwrap();

        let opened = open_pair(&file, &pw).unwrap();
        assert_eq!(opened.generation, 1);
        assert_eq!(opened.payload.fields(), payload.fields());

        let corrupt_offset = HEADER_SLOT_SIZE as u64 + 100;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        let opened = open_pair(&file, &pw).unwrap();
        assert!(opened.degraded);
        repair_pair(
            &file,
            &pw,
            opened.generation,
            &opened.payload,
            opened.kdf_params,
            opened.healthy_slots,
        )
        .unwrap();
        assert!(!open_pair(&file, &pw).unwrap().degraded);

        drop(file);
    }
}

#[test]
fn a_header_copy_with_a_valid_mac_but_invalid_fields_is_rejected() {
    let (_path, file) = temp_file();
    let kdf = KdfParams::for_tests();
    let pw = password(b"example password");
    let payload = HeaderPayload::create(CipherId::XChaCha20Poly1305, 4096, 100, 256).unwrap();
    let mut pair = build_pair(1, &pw, kdf, &payload).unwrap();

    pair[1][RESERVED_OFFSET] = 1;
    let mac = outer_mac_bytes(&pair[1], 1, payload.master_key()).unwrap();
    pair[1][OUTER_MAC_OFFSET..RESERVED_OFFSET].copy_from_slice(&mac);
    write_slot(&file, 0, &pair[0]).unwrap();
    write_slot(&file, 1, &pair[1]).unwrap();
    file.sync_all().unwrap();

    let error = match open_pair(&file, &pw) {
        Ok(_) => panic!("authenticated malformed header slot was accepted"),
        Err(error) => error,
    };
    assert!(
        matches!(error, VaultError::Corrupt(message) if message.contains("authenticated header slot"))
    );

    drop(file);
}

#[test]
fn updating_one_header_copy_to_a_new_password_blocks_the_old_password() {
    for cipher_id in TEST_CIPHERS {
        let (_path, file) = temp_file();
        let kdf = KdfParams::for_tests();
        let old = password(b"old password");
        let new = password(b"new password");
        let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
        let old_pair = build_pair(1, &old, kdf, &payload).unwrap();
        write_slot(&file, 0, &old_pair[0]).unwrap();
        write_slot(&file, 1, &old_pair[1]).unwrap();
        let new_slot = build_slot(0, 2, &new, kdf, &payload).unwrap();
        write_slot(&file, 0, &new_slot).unwrap();
        file.sync_all().unwrap();

        assert!(open_pair(&file, &old).is_err());
        let opened = open_pair(&file, &new).unwrap();
        assert_eq!(opened.generation, 2);
        repair_pair(
            &file,
            &new,
            opened.generation,
            &opened.payload,
            opened.kdf_params,
            opened.healthy_slots,
        )
        .unwrap();
        assert!(open_pair(&file, &old).is_err());

        drop(file);
    }
}
