use std::sync::Arc;

use super::{
    Volume,
    allocator::ChunkAllocator,
    file_table::Catalog,
    metadata::{
        METADATA_COPY_COUNT, MetadataCopyState, PreparedMetadata, SnapshotWriteError,
        SnapshotWritePhase, prepare_catalog_snapshot, read_copy, write_snapshot,
    },
    reader::ReaderSession,
};
use crate::errors::VaultError;

/// A catalog together with the bytes we'll save and the matching free-chunk
/// map. We keep these fields private so the catalog can't change after its
/// bytes and chunk reservations have been checked.
pub(super) struct PreparedCatalog {
    catalog: Catalog,
    metadata: PreparedMetadata,
    allocator: ChunkAllocator,
    session: Arc<ReaderSession>,
    generation: u64,
}

pub(super) struct LoadedMetadata {
    pub catalog: Catalog,
    pub allocator: ChunkAllocator,
    pub generation: u64,
    pub degraded: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct MetadataSelection {
    generation: u64,
    selected_slot: usize,
    healthy_slots: [bool; METADATA_COPY_COUNT],
    fallback_generation: Option<u64>,
}

/// Chooses a catalog copy from the read results, without doing more file I/O
/// or rebuilding the catalog. The result holds no catalog bytes, so callers
/// can release the other copy's bytes before decoding the chosen one.
fn select_metadata(
    states: &[MetadataCopyState; METADATA_COPY_COUNT],
) -> Result<MetadataSelection, VaultError> {
    // A read can fail because of a storage problem, even if the saved copy is
    // perfectly valid. So we stop here: overwriting it as a repair could
    // destroy a copy we simply weren't able to read.
    if let Some(error) = states.iter().find_map(|state| match state {
        MetadataCopyState::Unreadable(error)
        | MetadataCopyState::AuthenticatedInvalid { error, .. }
            if matches!(error, VaultError::FileError(_)) =>
        {
            Some(error)
        }
        _ => None,
    }) {
        return Err(VaultError::FileError(format!(
            "failed to read a metadata copy: {error}"
        )));
    }

    if let Some(error) = states.iter().find_map(|state| match state {
        MetadataCopyState::AuthenticatedInvalid {
            generation: None,
            error,
            ..
        } => Some(error),
        _ => None,
    }) {
        return Err(VaultError::corrupt(format!(
            "an authenticated metadata head is malformed: {error}"
        )));
    }

    let authenticated = states.iter().filter_map(|state| match state {
        MetadataCopyState::Authenticated(candidate) => Some(candidate),
        _ => None,
    });
    let Some(selected) = authenticated.clone().reduce(|selected, candidate| {
        if candidate.generation > selected.generation {
            candidate
        } else {
            selected
        }
    }) else {
        let details = states
            .iter()
            .enumerate()
            .map(|(slot, state)| match state {
                MetadataCopyState::Authenticated(_) => {
                    format!("copy {slot}: authenticated")
                }
                MetadataCopyState::Unreadable(error) => {
                    format!("copy {slot}: unreadable: {error}")
                }
                MetadataCopyState::AuthenticatedInvalid { error, .. } => {
                    format!("copy {slot}: authenticated but invalid: {error}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(VaultError::corrupt(format!(
            "no recoverable metadata copy ({details})"
        )));
    };

    // A newer authenticated head is evidence of an update, even when we can't
    // use its catalog. Choosing an older copy would hide that update, so fail
    // instead of silently going back to the older contents.
    let newest_generation = selected.generation;
    if let Some((generation, error)) = states.iter().find_map(|state| match state {
        MetadataCopyState::AuthenticatedInvalid {
            generation: Some(generation),
            error,
            ..
        } if *generation > newest_generation => Some((*generation, error)),
        _ => None,
    }) {
        return Err(VaultError::corrupt(format!(
            "metadata generation {generation} authenticated but is invalid; refusing to roll back to generation {newest_generation}: {error}"
        )));
    }

    // Copies with the same update number should describe the same catalog.
    // If their hashes differ, we have no safe way to decide which one is right.
    if states.iter().any(|state| {
        matches!(
            state,
            MetadataCopyState::AuthenticatedInvalid {
                generation: Some(generation),
                digest,
                ..
            } if *generation == newest_generation && *digest != selected.digest
        )
    }) || authenticated.clone().any(|candidate| {
        candidate.generation == newest_generation && candidate.digest != selected.digest
    }) {
        return Err(VaultError::corrupt(
            "metadata copies disagree at the same generation",
        ));
    }

    let healthy_slots: [bool; METADATA_COPY_COUNT] = std::array::from_fn(|slot| {
        authenticated.clone().any(|candidate| {
            candidate.slot == slot
                && candidate.generation == newest_generation
                && candidate.digest == selected.digest
        })
    });
    let fallback_generation = authenticated
        .filter(|candidate| candidate.generation < newest_generation)
        .map(|candidate| candidate.generation)
        .max();
    Ok(MetadataSelection {
        generation: newest_generation,
        selected_slot: selected.slot,
        healthy_slots,
        fallback_generation,
    })
}

impl Volume {
    pub(super) fn load_metadata(&mut self, repair: bool) -> Result<LoadedMetadata, VaultError> {
        let states = std::array::from_fn(|slot| {
            read_copy(
                &self.file,
                &self.metadata_cipher,
                &self.container_id,
                self.chunk_size,
                self.metadata_copy_chunks,
                slot,
            )
        });

        let MetadataSelection {
            generation: newest_generation,
            selected_slot,
            healthy_slots,
            fallback_generation,
        } = select_metadata(&states)?;

        let degraded = healthy_slots.iter().any(|healthy| !healthy);

        // Keep only the chosen copy's bytes before rebuilding the catalog.
        // This avoids holding two expanded catalogs in memory while opening.
        let mut selected = None;
        for state in states {
            if let MetadataCopyState::Authenticated(candidate) = state {
                if candidate.slot == selected_slot {
                    selected = Some(candidate);
                }
            }
        }
        let selected =
            selected.ok_or_else(|| VaultError::corrupt("selected metadata copy disappeared"))?;
        let decoded = selected
            .decode(self.data_chunk_count, self.chunk_size)
            .map_err(|error| {
                if let Some(fallback_generation) = fallback_generation {
                    VaultError::corrupt(format!(
                        "metadata generation {newest_generation} authenticated but its catalog is invalid; refusing to roll back to generation {fallback_generation}: {error}"
                    ))
                } else {
                    VaultError::corrupt(format!(
                        "metadata generation {newest_generation} has an invalid catalog: {error}"
                    ))
                }
            })?;
        let catalog = decoded.catalog;
        let allocator = decoded.allocator;

        if repair && degraded {
            let prepared =
                prepare_catalog_snapshot(&catalog, self.metadata_copy_chunks, self.chunk_size)?;
            for (slot, slot_healthy) in healthy_slots.into_iter().enumerate() {
                if !slot_healthy {
                    write_snapshot(
                        &self.file,
                        &self.metadata_cipher,
                        &self.container_id,
                        self.chunk_size,
                        self.metadata_copy_chunks,
                        slot,
                        newest_generation,
                        &prepared,
                    )
                    .map_err(|failure| {
                        VaultError::FileError(format!(
                            "failed to repair metadata copy {slot}: {}",
                            failure.error
                        ))
                    })?;
                }
            }
        }

        Ok(LoadedMetadata {
            catalog,
            allocator,
            generation: newest_generation,
            degraded: degraded && !repair,
        })
    }

    /// Checks the catalog, available space, and chunk reservations before any
    /// new file data or catalog bytes are written.
    ///
    /// We don't want to write file contents and only then discover that the
    /// catalog can't describe them or doesn't fit. Preparing everything here
    /// also means we won't need to rebuild or validate the catalog and its
    /// free-chunk map after the new catalog has been saved.
    pub(super) fn prepare_catalog(&self, catalog: Catalog) -> Result<PreparedCatalog, VaultError> {
        self.ensure_writable()?;
        let generation = self
            .metadata_generation
            .checked_add(1)
            .ok_or_else(|| VaultError::FileError("metadata generation exhausted".to_string()))?;
        let metadata =
            prepare_catalog_snapshot(&catalog, self.metadata_copy_chunks, self.chunk_size)?;
        let allocator = catalog.build_allocator(self.data_chunk_count)?;
        Ok(PreparedCatalog {
            catalog,
            metadata,
            allocator,
            session: Arc::clone(&self.reader_session),
            generation,
        })
    }

    /// Stops existing readers, saves both copies, then updates the catalog in
    /// memory. The new catalog takes effect when the first copy's head is
    /// written. We still have to save and synchronize the second copy before
    /// reusing removed files' chunks: the older catalog might still refer to
    /// them if recovery has to use that copy.
    pub(super) fn commit_catalog(&mut self, prepared: PreparedCatalog) -> Result<(), VaultError> {
        self.ensure_writable()?;
        if !Arc::ptr_eq(&prepared.session, &self.reader_session)
            || Some(prepared.generation) != self.metadata_generation.checked_add(1)
        {
            return Err(VaultError::FileError(
                "prepared catalog does not belong to the current vault generation".to_string(),
            ));
        }
        let PreparedCatalog {
            catalog,
            metadata,
            allocator,
            generation,
            ..
        } = prepared;

        // These readers remember where files lived in the old catalog. Once
        // those chunks can be reused, an old reader could read a different
        // file's storage. Stop them before saving the change that allows this.
        self.reader_session.invalidate();
        let first = (generation as usize) % METADATA_COPY_COUNT;
        let second = 1 - first;

        if let Err(failure) = write_snapshot(
            &self.file,
            &self.metadata_cipher,
            &self.container_id,
            self.chunk_size,
            self.metadata_copy_chunks,
            first,
            generation,
            &metadata,
        ) {
            self.poison(format!(
                "metadata update failed while writing copy {first}: {}",
                failure.error
            ));
            return Err(match failure.phase {
                SnapshotWritePhase::BeforeHead => VaultError::FileError(format!(
                    "metadata update did not publish, but redundancy may be degraded: {}",
                    failure.error
                )),
                SnapshotWritePhase::PublishingHead => VaultError::CommitUncertain(format!(
                    "metadata commit record for copy {first} could not be confirmed: {}",
                    failure.error
                )),
            });
        }

        if let Err(SnapshotWriteError { error, .. }) = write_snapshot(
            &self.file,
            &self.metadata_cipher,
            &self.container_id,
            self.chunk_size,
            self.metadata_copy_chunks,
            second,
            generation,
            &metadata,
        ) {
            self.poison(format!(
                "the new catalog committed to one copy, but mirroring copy {second} failed: {error}"
            ));
            return Err(VaultError::CommitUncertain(format!(
                "the new catalog is committed, but metadata redundancy was not restored: {error}"
            )));
        }

        // Both copies are saved to storage. Preparation already built the new
        // catalog and free-chunk map, so adopting them cannot fail.
        self.catalog = catalog;
        self.allocator = allocator;
        self.metadata_generation = generation;
        self.redundancy_degraded = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::metadata::MetadataCandidate;

    fn valid(slot: usize, generation: u64, digest: u8) -> MetadataCopyState {
        MetadataCopyState::Authenticated(MetadataCandidate::for_selection_test(
            slot,
            generation,
            [digest; 32],
        ))
    }

    fn invalid(generation: Option<u64>, digest: u8) -> MetadataCopyState {
        MetadataCopyState::AuthenticatedInvalid {
            generation,
            digest: [digest; 32],
            error: VaultError::corrupt("invalid test snapshot"),
        }
    }

    #[test]
    fn catalog_selection_chooses_the_newest_copy_and_marks_which_copies_match() {
        let selected = select_metadata(&[valid(0, 7, 1), valid(1, 7, 1)]).unwrap();
        assert_eq!(
            selected,
            MetadataSelection {
                generation: 7,
                selected_slot: 0,
                healthy_slots: [true, true],
                fallback_generation: None,
            }
        );

        for current_slot in 0..METADATA_COPY_COUNT {
            let states = std::array::from_fn(|slot| {
                if slot == current_slot {
                    valid(slot, 7, 1)
                } else {
                    valid(slot, 6, 2)
                }
            });
            let selected = select_metadata(&states).unwrap();
            assert_eq!(selected.generation, 7);
            assert_eq!(selected.selected_slot, current_slot);
            assert!(selected.healthy_slots[current_slot]);
            assert!(!selected.healthy_slots[1 - current_slot]);
            assert_eq!(selected.fallback_generation, Some(6));
        }

        let selected = select_metadata(&[valid(0, 7, 1), invalid(Some(7), 1)]).unwrap();
        assert_eq!(selected.healthy_slots, [true, false]);
        assert_eq!(selected.fallback_generation, None);
    }

    #[test]
    fn catalog_selection_rejects_invalid_or_conflicting_updates() {
        for states in [
            [valid(0, 6, 1), invalid(Some(7), 1)],
            [valid(0, 7, 1), invalid(None, 1)],
            [valid(0, 7, 1), invalid(Some(7), 2)],
            [valid(0, 7, 1), valid(1, 7, 2)],
            [invalid(Some(7), 1), invalid(Some(7), 1)],
        ] {
            assert!(matches!(
                select_metadata(&states),
                Err(VaultError::Corrupt(_))
            ));
            let [first, second] = states;
            assert!(matches!(
                select_metadata(&[second, first]),
                Err(VaultError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn catalog_read_errors_stop_recovery_but_failed_authentication_allows_repair() {
        for damaged in [
            MetadataCopyState::Unreadable(VaultError::FileError("test read failure".to_string())),
            MetadataCopyState::AuthenticatedInvalid {
                generation: Some(6),
                digest: [1; 32],
                error: VaultError::FileError("test body read failure".to_string()),
            },
        ] {
            assert!(matches!(
                select_metadata(&[valid(0, 7, 1), damaged]),
                Err(VaultError::FileError(_))
            ));
        }

        let selected = select_metadata(&[
            valid(0, 7, 1),
            MetadataCopyState::Unreadable(VaultError::CryptoError(
                "test authentication failure".to_string(),
            )),
        ])
        .unwrap();
        assert_eq!(selected.healthy_slots, [true, false]);
    }
}
