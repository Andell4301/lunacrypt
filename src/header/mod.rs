mod payload;
mod slot;

use std::fs::File;

pub(crate) use payload::HeaderPayload;
use slot::{ParsedSlot, decrypt_slot, outer_mac_valid, outer_mac_valid_raw, parse_slot, read_slot};
pub(crate) use slot::{build_slot, write_slot};

use crate::{
    Password,
    errors::VaultError,
    kdf::{KdfParams, validate_password_length},
};

pub(crate) const HEADER_SLOT_SIZE: usize = 4096;
pub(crate) const HEADER_SLOT_COUNT: usize = 2;
pub(crate) const DATA_AREA_OFFSET: u64 = (HEADER_SLOT_SIZE * HEADER_SLOT_COUNT) as u64;
pub(crate) const CONTAINER_ID_LEN: usize = 16;

pub(crate) struct OpenedHeader {
    pub payload: HeaderPayload,
    pub generation: u64,
    pub degraded: bool,
    pub kdf_params: KdfParams,
    pub healthy_slots: [bool; HEADER_SLOT_COUNT],
}

/// Builds both header copies for the same update number (generation).
/// Each copy gets its own salt and nonce, even though the payload is the same.
pub(crate) fn build_pair(
    generation: u64,
    password: &Password,
    kdf_params: KdfParams,
    payload: &HeaderPayload,
) -> Result<[[u8; HEADER_SLOT_SIZE]; HEADER_SLOT_COUNT], VaultError> {
    Ok([
        build_slot(0, generation, password, kdf_params, payload)?,
        build_slot(1, generation, password, kdf_params, payload)?,
    ])
}

/// Chooses a usable header copy after checking both for newer or conflicting state.
/// This only reads the vault; repairing a damaged copy is a separate step.
pub(crate) fn open_pair(file: &File, password: &Password) -> Result<OpenedHeader, VaultError> {
    validate_password_length(password)?;

    // Read and parse both header slot copies.
    let raws = [read_slot(file, 0)?, read_slot(file, 1)?];
    let parsed: [Option<ParsedSlot>; HEADER_SLOT_COUNT] =
        [parse_slot(raws[0], 0)?, parse_slot(raws[1], 1)?];

    let mut candidates = Vec::new();
    // See if any of the parsed slots can be decrypted with the provided password.
    for slot in parsed.iter().flatten() {
        if let Some(candidate) = decrypt_slot(slot, password)? {
            candidates.push(candidate);
        }
    }
    if candidates.is_empty() {
        return Err(VaultError::CryptoError(
            "invalid password or no recoverable header copy".to_string(),
        ));
    }

    // We couldn't check the outer MAC until a decrypted copy gave us the
    // master key. Now revisit slots whose public fields failed parsing. If
    // their MAC is valid, those invalid bytes are authenticated state. We
    // can't safely treat that as ordinary damage and repair over it.
    for candidate in &candidates {
        for (slot, raw) in raws.iter().enumerate() {
            if parsed[slot].is_none()
                && outer_mac_valid_raw(raw, slot, candidate.payload.master_key())?
            {
                return Err(VaultError::corrupt(
                    "an authenticated header slot is structurally malformed",
                ));
            }
        }
    }

    // The master key stays the same when the password changes. So even if
    // this password only decrypts an older copy, its recovered master key can
    // authenticate a newer copy's public update number. Don't accept the older
    // state when a newer authenticated copy exists.
    let mut keep = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let mut highest_authenticated = candidate.generation;
        let mut same_generation_unreadable = false;
        for parsed_slot in parsed.iter().flatten() {
            // A parsed slot still needs authentication before we trust its number.
            if outer_mac_valid(parsed_slot, candidate.payload.master_key())? {
                highest_authenticated = highest_authenticated.max(parsed_slot.generation);
                // At the same update number, both authenticated copies must
                // open to the same payload. An unreadable or conflicting copy
                // means we can't confirm that they agree.
                if parsed_slot.generation == candidate.generation
                    && !candidates.iter().any(|other| {
                        other.slot == parsed_slot.slot
                            && other.generation == candidate.generation
                            && other.payload.equivalent(&candidate.payload)
                    })
                {
                    same_generation_unreadable = true;
                }
            }
        }
        // Keep only the newest authenticated state with no unresolved copy
        // at the same update number.
        keep.push(highest_authenticated == candidate.generation && !same_generation_unreadable);
    }
    candidates = candidates
        .into_iter()
        .zip(keep)
        .filter_map(|(candidate, keep)| keep.then_some(candidate))
        .collect();

    if candidates.is_empty() {
        return Err(VaultError::CryptoError(
            "no consistent header state can be recovered with this password".to_string(),
        ));
    }

    let newest_generation = candidates
        .iter()
        .map(|candidate| candidate.generation)
        .max()
        .expect("non-empty candidates");
    let selected_index = candidates
        .iter()
        .position(|candidate| candidate.generation == newest_generation)
        .expect("newest generation has a candidate");
    let selected = &candidates[selected_index];
    if candidates
        .iter()
        .filter(|candidate| candidate.generation == newest_generation)
        .any(|candidate| !candidate.payload.equivalent(&selected.payload))
    {
        return Err(VaultError::corrupt(
            "header copies disagree at the same generation",
        ));
    }

    let healthy: [bool; HEADER_SLOT_COUNT] = std::array::from_fn(|slot| {
        candidates.iter().any(|candidate| {
            candidate.slot == slot
                && candidate.generation == newest_generation
                && candidate.payload.equivalent(&selected.payload)
        })
    });

    let selected = candidates.swap_remove(selected_index);
    Ok(OpenedHeader {
        payload: selected.payload,
        generation: newest_generation,
        degraded: healthy.iter().filter(|is_healthy| **is_healthy).count() != HEADER_SLOT_COUNT,
        kdf_params: selected.kdf_params,
        healthy_slots: healthy,
    })
}

/// Rebuilds header copies that need repair after the vault layout and catalog
/// have been checked. Leave healthy copies alone, so an interrupted repair still
/// has a working copy to recover from.
pub(crate) fn repair_pair(
    file: &File,
    password: &Password,
    generation: u64,
    payload: &HeaderPayload,
    kdf_params: KdfParams,
    healthy_slots: [bool; HEADER_SLOT_COUNT],
) -> Result<(), VaultError> {
    kdf_params.validate()?;
    for (slot, healthy) in healthy_slots.iter().copied().enumerate() {
        if healthy {
            continue;
        }
        let replacement = build_slot(slot, generation, password, kdf_params, payload)?;
        write_slot(file, slot, &replacement)?;
        file.sync_all().map_err(|error| {
            VaultError::from_io("failed to synchronize a repaired header slot", error)
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
