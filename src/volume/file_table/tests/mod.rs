use super::{
    codec::{ENTRY_FIXED_LEN, HEADER_LEN},
    *,
};

#[test]
fn paths_reject_names_unsafe_on_supported_platforms() {
    for bad in [
        "",
        "../x",
        "a//b",
        "a\\b",
        "CON",
        "aux.txt",
        "com1.log",
        "COM¹.txt",
        "CON .txt",
        "NUL  .tar.gz",
        "LPT1 .log",
        "COM¹ .txt",
        " name",
        "docs/ name",
        "name.",
        "name ",
        "a:b",
        "a\u{0001}b",
        "a\u{0085}b",
        "a\u{061c}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\u{202e}b",
    ] {
        assert!(validate_path(bad).is_err(), "accepted {bad:?}");
    }
    assert!(validate_path("Documents/Résumé.txt").is_ok());
    assert!(validate_path("Documents/Meeting notes.txt").is_ok());
    assert!(validate_path("Documents/ordinary .txt").is_ok());
}

#[test]
fn catalog_saves_and_loads_unchanged_and_rejects_names_differing_only_in_case() {
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_directory("Docs".to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_file("Docs/a.txt".to_string(), 1, 3, 1).unwrap())
        .unwrap();
    assert!(
        catalog
            .insert(FileEntry::new_directory("docs".to_string()).unwrap())
            .is_err()
    );
    let bytes = catalog.to_bytes().unwrap();
    assert_eq!(catalog.encoded_len().unwrap(), bytes.len());
    let decoded = Catalog::from_bytes(&bytes, 10, 4096).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
}

#[test]
fn catalog_bytes_match_the_expected_storage_format() {
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry {
            path: "docs".to_string(),
            kind: EntryKind::Directory,
            file_id: [0x11; FILE_ID_LEN],
            size: 0,
            start_chunk: 0,
            num_chunks: 0,
        })
        .unwrap();
    catalog
        .insert(FileEntry {
            path: "docs/a.txt".to_string(),
            kind: EntryKind::File,
            file_id: [0x22; FILE_ID_LEN],
            size: 3,
            start_chunk: 7,
            num_chunks: 1,
        })
        .unwrap();

    let mut expected = b"LUNACAT1".to_vec();
    expected.extend_from_slice(&[0, 1, 0, 0, 0, 2]);
    expected.extend_from_slice(&[0, 0, 0, 4]);
    expected.extend_from_slice(b"docs");
    expected.push(2);
    expected.extend_from_slice(&[0x11; FILE_ID_LEN]);
    expected.extend_from_slice(&[0; 24]);
    expected.extend_from_slice(&[0, 4, 0, 6]);
    expected.extend_from_slice(b"/a.txt");
    expected.push(1);
    expected.extend_from_slice(&[0x22; FILE_ID_LEN]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 3]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);

    assert_eq!(catalog.to_bytes().unwrap().as_slice(), expected);
    let decoded = Catalog::from_bytes(&expected, 10, 4096).unwrap();
    assert_eq!(decoded.to_bytes().unwrap().as_slice(), expected);
}

#[test]
fn catalog_rejects_names_that_compare_the_same_despite_different_unicode_spelling() {
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_directory("Straße".to_string()).unwrap())
        .unwrap();
    assert!(
        catalog
            .insert(FileEntry::new_directory("STRASSE".to_string()).unwrap())
            .is_err()
    );

    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_directory("Ｋ".to_string()).unwrap())
        .unwrap();
    assert!(
        catalog
            .insert(FileEntry::new_directory("k".to_string()).unwrap())
            .is_err()
    );
}

#[test]
fn sharing_path_prefixes_makes_the_saved_catalog_smaller() {
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_directory("projects".to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_directory("projects/lunacrypt".to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_directory("projects/lunacrypt/assets".to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_directory("projects/lunacrypt/assets/images".to_string()).unwrap())
        .unwrap();
    for index in 0..100u64 {
        catalog
            .insert(
                FileEntry::new_file(
                    format!("projects/lunacrypt/assets/images/frame-{index:04}.bin"),
                    1,
                    index,
                    1,
                )
                .unwrap(),
            )
            .unwrap();
    }

    let uncompressed_len = HEADER_LEN
        + catalog
            .entries()
            .map(|entry| 2 + 1 + FILE_ID_LEN + 8 + 8 + 8 + entry.path.len())
            .sum::<usize>();
    let encoded = catalog.to_bytes().unwrap();
    assert_eq!(catalog.encoded_len().unwrap(), encoded.len());
    assert!(
        encoded.len() * 3 < uncompressed_len * 2,
        "front-coded size {} was not substantially smaller than {uncompressed_len}",
        encoded.len()
    );
    assert_eq!(
        Catalog::from_bytes(&encoded, 100, 4096)
            .unwrap()
            .to_bytes()
            .unwrap(),
        encoded
    );
}

#[test]
fn loading_rejects_paths_that_do_not_use_the_longest_shared_prefix() {
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_directory("root".to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_directory("root/child".to_string()).unwrap())
        .unwrap();
    let mut bytes = catalog.to_bytes().unwrap();

    let second_entry = HEADER_LEN + ENTRY_FIXED_LEN + "root".len();
    let suffix_start = second_entry + 4;
    assert_eq!(
        u16::from_be_bytes(bytes[second_entry..second_entry + 2].try_into().unwrap()),
        4
    );
    assert_eq!(
        u16::from_be_bytes(
            bytes[second_entry + 2..second_entry + 4]
                .try_into()
                .unwrap()
        ),
        6
    );

    // `root/child` normally reuses all four bytes of `root` and stores `/child`.
    // Here we reuse only `roo` and store `t/child`. The name comes out the same,
    // but we reject it so there aren't multiple ways to save the same catalog.
    bytes[second_entry..second_entry + 2].copy_from_slice(&3u16.to_be_bytes());
    bytes[second_entry + 2..second_entry + 4].copy_from_slice(&7u16.to_be_bytes());
    bytes.insert(suffix_start, b't');
    assert!(Catalog::from_bytes(&bytes, 10, 4096).is_err());
}

#[test]
fn paths_still_load_when_a_shared_prefix_ends_inside_a_unicode_character() {
    // In UTF-8, `é` and `ê` share their first byte. Saving that shared byte is
    // fine as long as rebuilding each full path produces valid UTF-8 again.
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_directory("root".to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_file("root/é.txt".to_string(), 1, 0, 1).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_file("root/ê.txt".to_string(), 1, 1, 1).unwrap())
        .unwrap();

    let bytes = catalog.to_bytes().unwrap();
    let decoded = Catalog::from_bytes(&bytes, 2, 4096).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
}

#[test]
fn paths_must_be_normalized_before_they_are_valid() {
    let decomposed = "Cafe\u{301}.txt";
    let normalized = normalize_path(decomposed);
    assert_eq!(normalized, "Café.txt");
    assert!(validate_path(decomposed).is_err());
    assert!(validate_path(&normalized).is_ok());
}

#[test]
fn paths_reject_control_and_text_direction_characters_but_allow_emoji() {
    assert!(validate_path("root/C1-\u{0085}.txt").is_err());
    assert!(validate_path("root/bidi-\u{202e}.txt").is_err());
    assert!(validate_path("root/shaking-face-\u{1fae8}.txt").is_ok());
}

#[test]
fn catalog_limits_memory_used_by_stored_paths() {
    let mut catalog = Catalog::new();
    let root = "root";
    let child = "root/child";
    let root_cost = root.len() * 2 + portable_key(root).0.len();
    let child_cost = child.len() * 2 + portable_key(child).0.len();
    catalog
        .insert(FileEntry::new_directory(root.to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_directory(child.to_string()).unwrap())
        .unwrap();
    assert_eq!(catalog.stored_path_bytes, root_cost + child_cost);
    catalog.remove(child).unwrap();
    assert_eq!(catalog.stored_path_bytes, root_cost);

    // Pretend the path budget is full so we can check the limit without
    // allocating millions of bytes of names.
    let mut full_catalog = Catalog::new();
    full_catalog.stored_path_bytes = MAX_CATALOG_STORED_PATH_BYTES;

    let error = full_catalog
        .insert(FileEntry::new_directory("next".to_string()).unwrap())
        .unwrap_err();
    assert!(matches!(error, VaultError::FileError(message) if message.contains("in-memory limit")));
    assert!(full_catalog.entries.is_empty());
}

#[test]
fn loading_rejects_missing_catalog_bytes_extra_bytes_and_zero_chunk_sizes() {
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_directory("docs".to_string()).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_file("docs/note.txt".to_string(), 4097, 0, 2).unwrap())
        .unwrap();
    let mut bytes = catalog.to_bytes().unwrap();
    for length in 0..bytes.len() {
        assert!(
            Catalog::from_bytes(&bytes[..length], 10, 4096).is_err(),
            "accepted catalog truncated at byte {length}"
        );
    }
    assert!(Catalog::from_bytes(&bytes, 10, 0).is_err());
    bytes.push(0);
    assert!(Catalog::from_bytes(&bytes, 10, 4096).is_err());
}

#[test]
fn loading_rejects_invalid_file_storage_and_duplicate_file_ids() {
    let mut catalog = Catalog::new();
    catalog
        .insert(FileEntry::new_file("a".to_string(), 1, 0, 1).unwrap())
        .unwrap();
    catalog
        .insert(FileEntry::new_file("b".to_string(), 1, 1, 1).unwrap())
        .unwrap();

    for (kind, size, start, chunks) in [
        (EntryKind::Directory, 1, 0, 0),
        (EntryKind::Directory, 0, 1, 0),
        (EntryKind::Directory, 0, 0, 1),
        (EntryKind::File, 0, 1, 0),
        (EntryKind::File, 0, 0, 1),
        (EntryKind::File, 1, 0, 0),
        (EntryKind::File, 1, 0, 2),
        (EntryKind::File, 1, 1, 1), // Uses the same chunk as file b.
        (EntryKind::File, 1, 10, 1),
        (EntryKind::File, 8192, u64::MAX, 2),
    ] {
        let mut malformed = catalog.clone();
        let entry = malformed.entries.get_mut("a").unwrap();
        entry.kind = kind;
        entry.size = size;
        entry.start_chunk = start;
        entry.num_chunks = chunks;
        assert!(
            Catalog::from_bytes(&malformed.to_bytes().unwrap(), 10, 4096).is_err(),
            "accepted {kind:?} with size {size}, start {start}, chunks {chunks}"
        );
    }

    // Change both entries directly so loading has to catch the duplicate IDs.
    // Inserting them normally would reject the duplicate before we could save it.
    for duplicate_id in [[0; FILE_ID_LEN], [1; FILE_ID_LEN]] {
        let mut malformed = catalog.clone();
        for entry in malformed.entries.values_mut() {
            entry.file_id = duplicate_id;
        }
        assert!(Catalog::from_bytes(&malformed.to_bytes().unwrap(), 10, 4096).is_err());
    }
}

#[test]
fn all_zero_file_ids_can_be_saved_and_loaded() {
    for (kind, size, num_chunks) in [
        (EntryKind::File, 1, 1),
        (EntryKind::File, 0, 0),
        (EntryKind::Directory, 0, 0),
    ] {
        let mut catalog = Catalog::new();
        catalog
            .insert(FileEntry {
                path: "entry".to_string(),
                kind,
                file_id: [0; FILE_ID_LEN],
                size,
                start_chunk: 0,
                num_chunks,
            })
            .unwrap();
        let bytes = catalog.to_bytes().unwrap();
        let decoded = Catalog::from_bytes(&bytes, 10, 4096).unwrap();
        assert_eq!(decoded.find("entry").unwrap().file_id, [0; FILE_ID_LEN]);
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
    }
}
