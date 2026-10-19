use std::fs::File;

use getrandom::fill;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{
    HEADER_SLOT_COUNT, HEADER_SLOT_SIZE,
    payload::{HeaderPayload, PAYLOAD_LEN},
};
use crate::{
    Password,
    cipher::{Cipher, CipherId, NONCE_STORAGE_SIZE, TAG_SIZE},
    errors::VaultError,
    io::{read_exact_at, write_all_at},
    kdf::{
        KDF_PARAMS_LEN, KdfParams,
        hkdf::{KeyDomain, expand_key},
        validate_password_length,
    },
    secret_key::SecretKey,
};

const CLEAR_MAGIC: [u8; 8] = *b"LUNAHDR1";
const FORMAT_VERSION: u16 = 1;
const SLOT_VERSION: u16 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = NONCE_STORAGE_SIZE;
const TAG_LEN: usize = TAG_SIZE;
const OUTER_MAC_LEN: usize = 32;

const MAGIC_OFFSET: usize = 0;
const FORMAT_OFFSET: usize = 8;
const SLOT_VERSION_OFFSET: usize = 10;
const GENERATION_OFFSET: usize = 12;
pub(super) const SALT_OFFSET: usize = 20;
pub(super) const KDF_OFFSET: usize = SALT_OFFSET + SALT_LEN;
pub(super) const NONCE_OFFSET: usize = KDF_OFFSET + KDF_PARAMS_LEN;
pub(super) const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;
const TAG_OFFSET: usize = CIPHERTEXT_OFFSET + PAYLOAD_LEN;
pub(super) const OUTER_MAC_OFFSET: usize = TAG_OFFSET + TAG_LEN;
pub(super) const RESERVED_OFFSET: usize = OUTER_MAC_OFFSET + OUTER_MAC_LEN;

// One 4096-byte header slot. Only the payload is encrypted; the other fields
// stay readable, but their authentication checks still detect changes.
//
// FORMAT:
// [0..8]      - CLEAR_MAGIC
// [8..10]     - FORMAT_VERSION
// [10..12]    - SLOT_VERSION
// [12..20]    - GENERATION
// [20..52]    - SALT
// [52..84]    - KDF_PARAMS
// [84..108]   - NONCE
// [108..364]  - CIPHERTEXT (encrypted HeaderPayload)
// [364..380]  - TAG (checks the encrypted payload and its associated data)
// [380..412]  - OUTER_MAC (checks the whole slot, treating this MAC field as zero)
// [412..4096] - RESERVED

const HEADER_AAD_DOMAIN: &[u8] = b"lunacrypt-v1-header-slot";
const HEADER_MAC_DOMAIN: &[u8] = b"lunacrypt-v1-header-outer-mac";

pub(super) struct ParsedSlot {
    raw: [u8; HEADER_SLOT_SIZE],
    pub(super) slot: usize,
    pub(super) generation: u64,
    salt: [u8; SALT_LEN],
    pub(super) kdf_params: KdfParams,
    nonce: [u8; NONCE_LEN],
}

/// A header copy that decrypted and passed authentication, but may still be
/// older than the other copy. So `open_pair` compares both before choosing one,
/// and rejects copies that disagree at the same update number (generation).
pub(super) struct Candidate {
    pub(super) slot: usize,
    pub(super) generation: u64,
    pub(super) kdf_params: KdfParams,
    pub(super) payload: HeaderPayload,
}

fn slot_offset(slot: usize) -> Result<u64, VaultError> {
    if slot >= HEADER_SLOT_COUNT {
        return Err(VaultError::corrupt("invalid header slot index"));
    }
    Ok((slot * HEADER_SLOT_SIZE) as u64)
}

// These public fields describe how to open the payload. Include them in the
// associated data so changing the update number, salt, or password derivation
// settings makes authentication fail. Including the slot number also prevents
// moving a valid copy to the other slot. Include all 24 stored nonce bytes:
// AES uses only the first 12 as its nonce, but changes to the rest must fail too.
fn header_aad(raw: &[u8; HEADER_SLOT_SIZE], slot: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_AAD_DOMAIN.len() + 1 + CIPHERTEXT_OFFSET);
    aad.extend_from_slice(HEADER_AAD_DOMAIN);
    aad.push(slot as u8);
    aad.extend_from_slice(&raw[..CIPHERTEXT_OFFSET]);
    aad
}

pub(super) fn read_slot(file: &File, slot: usize) -> Result<[u8; HEADER_SLOT_SIZE], VaultError> {
    let mut raw = [0u8; HEADER_SLOT_SIZE];
    read_exact_at(file, &mut raw, slot_offset(slot)?)?;
    Ok(raw)
}

pub(crate) fn write_slot(
    file: &File,
    slot: usize,
    raw: &[u8; HEADER_SLOT_SIZE],
) -> Result<(), VaultError> {
    write_all_at(file, raw, slot_offset(slot)?)
}

/// Feeds the header slot into the outer MAC calculation.
/// Returns the calculator so callers can either produce the MAC bytes or
/// verify a stored MAC.
fn prepare_outer_mac(
    raw: &[u8; HEADER_SLOT_SIZE],
    slot: usize,
    master_key: &SecretKey,
) -> Result<Hmac<Sha256>, VaultError> {
    let key = expand_key(master_key, KeyDomain::HeaderAuthentication)?;
    let mut mac =
        <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.expose_secret()).map_err(|_| {
            VaultError::CryptoError("failed to initialize header authentication".to_string())
        })?;
    drop(key);
    mac.update(HEADER_MAC_DOMAIN);
    mac.update(&[slot as u8]);
    mac.update(&raw[..OUTER_MAC_OFFSET]);
    // The MAC can't include its own final value. Use zeros for that field
    // during both creation and verification, and include all other slot bytes.
    mac.update(&[0u8; OUTER_MAC_LEN]);
    mac.update(&raw[RESERVED_OFFSET..]);
    Ok(mac)
}

/// Calculates and returns the outer MAC bytes to store in a header slot.
pub(super) fn outer_mac_bytes(
    raw: &[u8; HEADER_SLOT_SIZE],
    slot: usize,
    master_key: &SecretKey,
) -> Result<[u8; OUTER_MAC_LEN], VaultError> {
    let mac = prepare_outer_mac(raw, slot, master_key)?;
    let output = mac.finalize().into_bytes();
    Ok(output
        .as_slice()
        .try_into()
        .expect("SHA-256 output is 32 bytes"))
}

/// Checks whether a parsed header slot's outer MAC is valid.
pub(super) fn outer_mac_valid(
    parsed: &ParsedSlot,
    master_key: &SecretKey,
) -> Result<bool, VaultError> {
    outer_mac_valid_raw(&parsed.raw, parsed.slot, master_key)
}

/// Checks a header slot's outer MAC without requiring successful parsing.
/// A slot can fail our format checks and still have a valid MAC. Recovery
/// needs to detect that case, so it can reject the vault rather than overwrite
/// authenticated bytes it doesn't understand.
pub(super) fn outer_mac_valid_raw(
    raw: &[u8; HEADER_SLOT_SIZE],
    slot: usize,
    master_key: &SecretKey,
) -> Result<bool, VaultError> {
    let stored = &raw[OUTER_MAC_OFFSET..RESERVED_OFFSET];
    let mac = prepare_outer_mac(raw, slot, master_key)?;
    Ok(mac.verify_slice(stored).is_ok())
}

/// Reads and checks the public fields without deriving a password key.
/// `Ok(Some(...))` means those fields follow the format and their password
/// derivation costs are within our limits. It doesn't prove authentication.
/// `Ok(None)` means the public fields are invalid. Other errors must stop
/// opening the vault, rather than treating this copy as safe to repair over.
pub(super) fn parse_slot(
    raw: [u8; HEADER_SLOT_SIZE],
    slot: usize,
) -> Result<Option<ParsedSlot>, VaultError> {
    if raw[MAGIC_OFFSET..FORMAT_OFFSET] != CLEAR_MAGIC {
        return Ok(None);
    }
    if u16::from_be_bytes(
        raw[FORMAT_OFFSET..SLOT_VERSION_OFFSET]
            .try_into()
            .expect("fixed slice"),
    ) != FORMAT_VERSION
    {
        return Ok(None);
    }
    if u16::from_be_bytes(
        raw[SLOT_VERSION_OFFSET..GENERATION_OFFSET]
            .try_into()
            .expect("fixed slice"),
    ) != SLOT_VERSION
    {
        return Ok(None);
    }
    let generation = u64::from_be_bytes(
        raw[GENERATION_OFFSET..SALT_OFFSET]
            .try_into()
            .expect("fixed slice"),
    );
    if generation == 0 {
        return Ok(None);
    }
    if raw[RESERVED_OFFSET..].iter().any(|byte| *byte != 0) {
        return Ok(None);
    }

    let salt = raw[SALT_OFFSET..KDF_OFFSET]
        .try_into()
        .expect("fixed slice");
    let kdf_bytes = raw[KDF_OFFSET..NONCE_OFFSET]
        .try_into()
        .expect("fixed slice");
    let kdf_params = match KdfParams::from_bytes(kdf_bytes) {
        Ok(params) => params,
        Err(VaultError::Corrupt(_) | VaultError::KdfError(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let nonce = raw[NONCE_OFFSET..CIPHERTEXT_OFFSET]
        .try_into()
        .expect("fixed slice");

    Ok(Some(ParsedSlot {
        raw,
        slot,
        generation,
        salt,
        kdf_params,
        nonce,
    }))
}

/// Attempts to decrypt a header slot using the provided password.
/// Returns `Ok(None)` if authentication fails or the payload has invalid fields.
/// Errors deriving or protecting a key still propagate: a temporary resource
/// failure doesn't tell us this header copy is damaged.
pub(super) fn decrypt_slot(
    parsed: &ParsedSlot,
    password: &Password,
) -> Result<Option<Candidate>, VaultError> {
    // Password derivation is the expensive part. Do it once for this slot,
    // then derive each attempt's protected encryption key from that result.
    let password_key = parsed.kdf_params.derive_key(password, &parsed.salt)?;
    let aad = header_aad(&parsed.raw, parsed.slot);

    // We want to support both ciphers without storing a readable cipher choice.
    // So the choice stays inside the encrypted payload, and we try both here.
    // I got this idea from VeraCrypt: https://veracrypt.io/en/Encryption%20Scheme.html
    // Our ciphers check an authentication tag before we accept the plaintext.
    // The choice inside that plaintext must also match the cipher that opened it.
    for cipher_id in [CipherId::XChaCha20Poly1305, CipherId::Aes256GcmSiv] {
        let encryption_key = expand_key(&password_key, KeyDomain::HeaderEncryption)?;
        let cipher = Cipher::new(cipher_id, encryption_key);
        let plaintext = match cipher.decrypt(
            &parsed.nonce[..cipher.nonce_size()],
            &aad,
            &parsed.raw[CIPHERTEXT_OFFSET..OUTER_MAC_OFFSET],
        ) {
            Ok(plaintext) => plaintext,
            // These fixed-size slices have the lengths this cipher needs.
            // A CryptoError here means authentication failed, so try the other
            // cipher. Key derivation and memory protection errors still escape.
            Err(VaultError::CryptoError(_)) => continue,
            Err(error) => return Err(error),
        };
        drop(cipher);
        let bytes: &[u8; PAYLOAD_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::corrupt("invalid encrypted header length"))?;
        let payload = match HeaderPayload::from_bytes(bytes, parsed.generation) {
            Ok(payload) => payload,
            Err(VaultError::Corrupt(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        drop(plaintext);
        if payload.fields().cipher_id != cipher_id
            || !outer_mac_valid(parsed, payload.master_key())?
        {
            return Ok(None);
        }
        return Ok(Some(Candidate {
            slot: parsed.slot,
            generation: parsed.generation,
            kdf_params: parsed.kdf_params,
            payload,
        }));
    }
    Ok(None)
}

/// Builds a header slot's bytes without writing them to disk.
/// Used when creating a vault, changing its password, or repairing a copy.
/// Each call generates a fresh salt and nonce. Password changes advance the
/// update number (generation); repairs keep the selected copy's number.
pub(crate) fn build_slot(
    slot: usize,
    generation: u64,
    password: &Password,
    kdf_params: KdfParams,
    payload: &HeaderPayload,
) -> Result<[u8; HEADER_SLOT_SIZE], VaultError> {
    validate_password_length(password)?;
    if generation == 0 {
        return Err(VaultError::corrupt("header generation must be non-zero"));
    }
    if slot >= HEADER_SLOT_COUNT {
        return Err(VaultError::corrupt("invalid header slot index"));
    }

    kdf_params.validate()?;

    let mut raw = [0u8; HEADER_SLOT_SIZE];
    raw[MAGIC_OFFSET..FORMAT_OFFSET].copy_from_slice(&CLEAR_MAGIC);
    raw[FORMAT_OFFSET..SLOT_VERSION_OFFSET].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    raw[SLOT_VERSION_OFFSET..GENERATION_OFFSET].copy_from_slice(&SLOT_VERSION.to_be_bytes());
    raw[GENERATION_OFFSET..SALT_OFFSET].copy_from_slice(&generation.to_be_bytes());

    fill(&mut raw[SALT_OFFSET..KDF_OFFSET])
        .map_err(|_| VaultError::CryptoError("failed to generate a header salt".to_string()))?;
    raw[KDF_OFFSET..NONCE_OFFSET].copy_from_slice(&kdf_params.to_bytes());
    // Keep all 24 bytes random for both ciphers. Zero-filled unused bytes would
    // give away AES, whose actual nonce needs only the first 12 bytes.
    fill(&mut raw[NONCE_OFFSET..CIPHERTEXT_OFFSET])
        .map_err(|_| VaultError::CryptoError("failed to generate a header nonce".to_string()))?;

    let salt: &[u8; SALT_LEN] = raw[SALT_OFFSET..KDF_OFFSET]
        .try_into()
        .expect("fixed slice");

    // The payload holds the vault's random master key. The password-derived
    // key protects that payload, so a password change only needs to encrypt
    // the payload again. The master key and file encryption keys stay the same.
    let password_key = kdf_params.derive_key(password, salt)?;
    let encryption_key = expand_key(&password_key, KeyDomain::HeaderEncryption)?;
    drop(password_key);
    let cipher = Cipher::new(payload.fields().cipher_id, encryption_key);
    let plaintext = payload.to_bytes(generation);
    let encrypted = cipher
        .encrypt(
            &raw[NONCE_OFFSET..NONCE_OFFSET + cipher.nonce_size()],
            &header_aad(&raw, slot),
            plaintext.as_slice(),
        )
        .map_err(|_| VaultError::CryptoError("failed to encrypt a header slot".to_string()))?;
    drop(plaintext);
    drop(cipher);

    if encrypted.len() != PAYLOAD_LEN + TAG_LEN {
        return Err(VaultError::CryptoError(
            "header cipher returned an unexpected length".to_string(),
        ));
    }
    raw[CIPHERTEXT_OFFSET..TAG_OFFSET].copy_from_slice(&encrypted[..PAYLOAD_LEN]); // 256-byte encrypted payload.
    raw[TAG_OFFSET..OUTER_MAC_OFFSET].copy_from_slice(&encrypted[PAYLOAD_LEN..]); // Appended 16-byte authentication tag.
    let mac = outer_mac_bytes(&raw, slot, payload.master_key())?;
    raw[OUTER_MAC_OFFSET..RESERVED_OFFSET].copy_from_slice(&mac);
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TEST_CIPHERS, password};

    fn cipher_for_header(parsed: &ParsedSlot, password: &Password, id: CipherId) -> Cipher {
        let password_key = parsed
            .kdf_params
            .derive_key(password, &parsed.salt)
            .unwrap();
        let key = expand_key(&password_key, KeyDomain::HeaderEncryption).unwrap();
        Cipher::new(id, key)
    }

    #[test]
    fn headers_are_encrypted_with_the_selected_cipher() {
        let pw = password(b"example password");
        for cipher_id in TEST_CIPHERS {
            let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
            let raw = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
            let parsed = parse_slot(raw, 0).unwrap().unwrap();

            // Open the stored bytes directly with the chosen cipher. A general
            // round trip alone could pass if writing and reading both ignored it.
            let cipher = cipher_for_header(&parsed, &pw, cipher_id);
            let plaintext = cipher
                .decrypt(
                    &parsed.nonce[..cipher.nonce_size()],
                    &header_aad(&raw, 0),
                    &raw[CIPHERTEXT_OFFSET..OUTER_MAC_OFFSET],
                )
                .unwrap();
            assert_eq!(plaintext.as_slice(), payload.to_bytes(1).as_slice());
            assert!(
                decrypt_slot(&parsed, &pw)
                    .unwrap()
                    .unwrap()
                    .payload
                    .equivalent(&payload)
            );
        }
    }

    #[test]
    fn both_header_ciphers_fill_the_entire_nonce_field_with_random_bytes() {
        let pw = password(b"example password");
        for cipher_id in TEST_CIPHERS {
            let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
            let first = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
            let second = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
            assert_ne!(
                first[NONCE_OFFSET..NONCE_OFFSET + 12],
                second[NONCE_OFFSET..NONCE_OFFSET + 12]
            );
            assert_ne!(
                first[NONCE_OFFSET + 12..CIPHERTEXT_OFFSET],
                second[NONCE_OFFSET + 12..CIPHERTEXT_OFFSET]
            );
        }
    }

    #[test]
    fn the_cipher_named_inside_the_header_must_match_its_encryption() {
        let pw = password(b"example password");
        for cipher_id in TEST_CIPHERS {
            let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
            let mut raw = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
            let parsed = parse_slot(raw, 0).unwrap().unwrap();
            let cipher = cipher_for_header(&parsed, &pw, cipher_id);

            // Make a valid encrypted payload that names the other cipher.
            // Both authentication checks pass, but the two choices disagree.
            let mut plaintext = payload.to_bytes(1);
            plaintext[20] = match cipher_id {
                CipherId::XChaCha20Poly1305 => CipherId::Aes256GcmSiv.into(),
                CipherId::Aes256GcmSiv => CipherId::XChaCha20Poly1305.into(),
            };
            let encrypted = cipher
                .encrypt(
                    &parsed.nonce[..cipher.nonce_size()],
                    &header_aad(&raw, 0),
                    plaintext.as_slice(),
                )
                .unwrap();
            raw[CIPHERTEXT_OFFSET..OUTER_MAC_OFFSET].copy_from_slice(&encrypted);
            let mac = outer_mac_bytes(&raw, 0, payload.master_key()).unwrap();
            raw[OUTER_MAC_OFFSET..RESERVED_OFFSET].copy_from_slice(&mac);
            let mismatched = parse_slot(raw, 0).unwrap().unwrap();
            assert!(outer_mac_valid(&mismatched, payload.master_key()).unwrap());
            assert!(decrypt_slot(&mismatched, &pw).unwrap().is_none());
        }
    }

    #[test]
    fn changing_stored_header_nonce_bytes_is_rejected_even_with_a_valid_mac() {
        let pw = password(b"example password");
        for cipher_id in TEST_CIPHERS {
            let payload = HeaderPayload::create(cipher_id, 4096, 100, 256).unwrap();
            let original = build_slot(0, 1, &pw, KdfParams::for_tests(), &payload).unwrap();
            // Cover the actual nonce and the first and last extra AES bytes.
            for index in [0, 12, NONCE_LEN - 1] {
                let mut raw = original;
                raw[NONCE_OFFSET + index] ^= 1;
                let mac = outer_mac_bytes(&raw, 0, payload.master_key()).unwrap();
                raw[OUTER_MAC_OFFSET..RESERVED_OFFSET].copy_from_slice(&mac);
                let tampered = parse_slot(raw, 0).unwrap().unwrap();
                assert!(outer_mac_valid(&tampered, payload.master_key()).unwrap());
                assert!(decrypt_slot(&tampered, &pw).unwrap().is_none());
            }
        }
    }
}
