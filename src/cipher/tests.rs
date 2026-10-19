use super::*;
use crate::test_support::TEST_CIPHERS;

fn cipher(id: CipherId, key_byte: u8) -> Cipher {
    let mut key = SecretKey::zeroed().unwrap();
    key.expose_secret_mut().fill(key_byte);
    Cipher::new(id, key)
}

#[test]
fn cipher_ids_use_the_expected_numbers_and_reject_unknown_values() {
    assert_eq!(CipherId::default(), CipherId::XChaCha20Poly1305);
    assert_eq!(u8::from(CipherId::XChaCha20Poly1305), 1);
    assert_eq!(u8::from(CipherId::Aes256GcmSiv), 2);
    for value in u8::MIN..=u8::MAX {
        match value {
            1 | 2 => assert_eq!(u8::from(CipherId::try_from(value).unwrap()), value),
            _ => assert!(CipherId::try_from(value).is_err()),
        }
    }
}

#[test]
fn generated_nonces_fill_both_halves_with_random_bytes() {
    for id in TEST_CIPHERS {
        let cipher = cipher(id, 7);
        let first = cipher.generate_nonce().unwrap();
        let second = cipher.generate_nonce().unwrap();
        // AES only needs the first half, but leaving the other half empty
        // would reveal the cipher to someone looking at the stored bytes.
        assert_ne!(first[..12], second[..12]);
        assert_ne!(first[12..], second[12..]);
    }
}

#[test]
fn ciphers_can_encrypt_and_decrypt_with_random_nonces() {
    for id in TEST_CIPHERS {
        let cipher = cipher(id, 7);
        let first = cipher.generate_nonce().unwrap();
        let second = cipher.generate_nonce().unwrap();
        for (nonce, plaintext) in [
            (first, b"secret bytes".as_slice()),
            (second, b"".as_slice()),
        ] {
            let nonce = &nonce[..cipher.nonce_size()];
            let ciphertext = cipher.encrypt(nonce, b"context", plaintext).unwrap();
            assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
            assert_eq!(
                cipher
                    .decrypt(nonce, b"context", &ciphertext)
                    .unwrap()
                    .as_slice(),
                plaintext,
            );
        }
    }
}

#[test]
fn decryption_fails_with_the_wrong_key_nonce_or_context() {
    for id in TEST_CIPHERS {
        let sender = cipher(id, 7);
        let nonce_storage = sender.generate_nonce().unwrap();
        let nonce = &nonce_storage[..sender.nonce_size()];
        let ciphertext = sender.encrypt(nonce, b"context-a", b"secret").unwrap();
        // Keep the encrypted bytes unchanged, but claim they belong to different context.
        assert!(sender.decrypt(nonce, b"context-b", &ciphertext).is_err());
        // The same nonce and context cannot make the wrong key work.
        assert!(
            cipher(id, 8)
                .decrypt(nonce, b"context-a", &ciphertext)
                .is_err()
        );
        // Changing one nonce byte must also fail authentication.
        let mut other_nonce = nonce.to_vec();
        other_nonce[0] ^= 1;
        assert!(
            sender
                .decrypt(&other_nonce, b"context-a", &ciphertext)
                .is_err()
        );
    }
}

#[test]
fn rejects_tampered_ciphertext_and_tag() {
    for id in TEST_CIPHERS {
        let cipher = cipher(id, 7);
        let nonce_storage = cipher.generate_nonce().unwrap();
        let nonce = &nonce_storage[..cipher.nonce_size()];
        let ciphertext = cipher.encrypt(nonce, b"context", b"secret").unwrap();

        let mut tampered_content = ciphertext.clone();
        tampered_content[0] ^= 1;
        assert!(
            cipher
                .decrypt(nonce, b"context", &tampered_content)
                .is_err()
        );

        let tag_start = ciphertext.len() - TAG_SIZE;
        let mut tampered_tag = ciphertext;
        tampered_tag[tag_start] ^= 1;
        assert!(cipher.decrypt(nonce, b"context", &tampered_tag).is_err());
    }
}

#[test]
fn rejects_truncated_ciphertext() {
    for id in TEST_CIPHERS {
        let cipher = cipher(id, 7);
        let nonce_storage = cipher.generate_nonce().unwrap();
        let nonce = &nonce_storage[..cipher.nonce_size()];
        let ciphertext = cipher.encrypt(nonce, b"context", b"secret").unwrap();

        for truncated_length in [
            0,                    // Empty.
            TAG_SIZE - 1,         // Too short for tag.
            TAG_SIZE,             // As many bytes as a tag, but still truncated.
            ciphertext.len() - 1, // Final byte missing.
        ] {
            assert!(
                cipher
                    .decrypt(nonce, b"context", &ciphertext[..truncated_length])
                    .is_err(),
                "{id:?} accepted ciphertext truncated to {truncated_length} bytes"
            );
        }
    }
}

#[test]
fn rejects_invalid_nonce_lengths() {
    for id in TEST_CIPHERS {
        let cipher = cipher(id, 7);
        let nonce_storage = cipher.generate_nonce().unwrap();
        let nonce = &nonce_storage[..cipher.nonce_size()];
        let ciphertext = cipher.encrypt(nonce, b"context", b"secret").unwrap();

        let nonce_size = cipher.nonce_size();
        for bad_len in [0, nonce_size - 1, nonce_size + 1] {
            let bad_nonce = vec![0u8; bad_len];
            assert!(cipher.encrypt(&bad_nonce, b"context", b"secret").is_err());
            assert!(cipher.decrypt(&bad_nonce, b"context", &ciphertext).is_err());
        }
    }
}

// Encrypting and decrypting with the same mistake could still recover the input.
// These published examples also check that our wrapper produces the exact bytes
// expected for a given key, nonce, plaintext, and associated data.

#[test]
fn aes256_gcm_siv_matches_published_output_for_empty_plaintext() {
    // RFC 8452, Appendix C.2: empty plaintext and no AAD.
    // https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C.2
    let mut key: SecretKey = SecretKey::zeroed().unwrap();
    key.expose_secret_mut()[0] = 1;
    let cipher = Cipher::new(CipherId::Aes256GcmSiv, key);
    let nonce = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [];
    let aad = [];

    // Empty plaintext still produces a 16-byte authentication tag.
    let expected_ciphertext = [
        0x07, 0xf5, 0xf4, 0x16, 0x9b, 0xbf, 0x55, 0xa8, 0x40, 0x0c, 0xd4, 0x7e, 0xa6, 0xfd, 0x40,
        0x0f,
    ];

    let encrypted = cipher.encrypt(&nonce, &aad, &plaintext).unwrap();
    assert_eq!(encrypted, expected_ciphertext);

    let decrypted = cipher.decrypt(&nonce, &aad, &expected_ciphertext).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

#[test]
fn aes256_gcm_siv_matches_published_output_with_associated_data() {
    // RFC 8452, Appendix C.2: 8-byte plaintext and 1-byte AAD.
    // https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C.2
    let mut key: SecretKey = SecretKey::zeroed().unwrap();
    key.expose_secret_mut()[0] = 1;
    let cipher = Cipher::new(CipherId::Aes256GcmSiv, key);
    let nonce = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [2, 0, 0, 0, 0, 0, 0, 0];
    let aad = [1];
    let expected_ciphertext = [
        0x1d, 0xe2, 0x29, 0x67, 0x23, 0x7a, 0x81, 0x32, 0x91, 0x21, 0x3f, 0x26, 0x7e, 0x3b, 0x45,
        0x2f, 0x02, 0xd0, 0x1a, 0xe3, 0x3e, 0x4e, 0xc8, 0x54,
    ];

    let encrypted = cipher.encrypt(&nonce, &aad, &plaintext).unwrap();
    assert_eq!(encrypted, expected_ciphertext);

    let decrypted = cipher.decrypt(&nonce, &aad, &expected_ciphertext).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

#[test]
fn xchacha20_poly1305_matches_published_output_with_associated_data() {
    // XChaCha draft, Appendix A.3.1: 114-byte plaintext and 12-byte AAD.
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1
    let mut key = SecretKey::zeroed().unwrap();
    key.expose_secret_mut().copy_from_slice(&[
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ]);
    let cipher = Cipher::new(CipherId::XChaCha20Poly1305, key);
    let nonce = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];

    // The expected output is the published ciphertext followed by its tag.
    let expected_ciphertext = [
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
        0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
        0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
        0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
        0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
        0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
        0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e, 0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7,
        0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
    ];

    let encrypted = cipher.encrypt(&nonce, &aad, plaintext).unwrap();
    assert_eq!(encrypted, expected_ciphertext);

    let decrypted = cipher.decrypt(&nonce, &aad, &expected_ciphertext).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}
