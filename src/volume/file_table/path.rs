use std::cmp::Ordering;

use focaccia::CaseFold;
use unicode_normalization::{
    UNICODE_VERSION as NORMALIZATION_UNICODE_VERSION, UnicodeNormalization,
};
use zeroize::Zeroizing;

use crate::errors::VaultError;

// These Unicode rules decide which names count as the same path. If a library
// update changed them, names we'd previously allowed together could conflict.
// Keep the tables fixed as part of the vault format.
const _: () = {
    let (major, minor, patch) = NORMALIZATION_UNICODE_VERSION;
    assert!(major == 16 && minor == 0 && patch == 0);
};

pub(super) const MAX_PATH_LEN: usize = 4096;
const MAX_PATH_SEGMENT_LEN: usize = 255;

#[derive(Debug, Clone)]
pub(super) struct PortablePathKey(pub(super) Zeroizing<String>);

impl PartialEq for PortablePathKey {
    fn eq(&self, other: &Self) -> bool {
        CaseFold::Full.case_eq(&self.0, &other.0)
    }
}

impl Eq for PortablePathKey {}

impl PartialOrd for PortablePathKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PortablePathKey {
    fn cmp(&self, other: &Self) -> Ordering {
        CaseFold::Full.casecmp(&self.0, &other.0)
    }
}

// The catalog keeps the original spelling for display. This separate key lets
// us also catch names that would conflict when case and Unicode spelling are
// compared, such as `Notes.txt` and `notes.txt`.
pub(super) fn portable_key(path: &str) -> PortablePathKey {
    // This conversion can make a name longer. Count the bytes first so the
    // string won't have to grow after we've put a path in it. Growing could
    // release an old allocation without wiping the path it contained.
    let len = path.nfkc().map(char::len_utf8).sum();
    let mut normalized = Zeroizing::new(String::with_capacity(len));
    normalized.extend(path.nfkc());
    PortablePathKey(normalized)
}

fn is_windows_reserved(segment: &str) -> bool {
    // Windows ignores spaces before the extension when recognizing device
    // names (for example, `NUL .txt` still refers to its null device).
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .trim_end_matches(' ');
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }

    let Some(prefix) = stem.get(..3) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case("COM") && !prefix.eq_ignore_ascii_case("LPT") {
        return false;
    }
    let suffix = &stem[3..];
    let mut chars = suffix.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('1'..='9' | '\u{00b9}' | '\u{00b2}' | '\u{00b3}'), None)
    )
}

fn is_unicode_control(character: char) -> bool {
    matches!(character as u32, 0x0000..=0x001f | 0x007f..=0x009f)
}

fn is_unsafe_unicode_format(character: char) -> bool {
    is_unicode_control(character)
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn validate_segment(segment: &str) -> Result<(), VaultError> {
    if segment.is_empty() || segment == "." || segment == ".." {
        return Err(VaultError::FileError(
            "vault paths must contain only normal, non-empty components".to_string(),
        ));
    }
    if segment.len() > MAX_PATH_SEGMENT_LEN {
        return Err(VaultError::FileError(format!(
            "path component exceeds the {MAX_PATH_SEGMENT_LEN}-byte limit"
        )));
    }
    if segment.starts_with(' ') || segment.ends_with(' ') || segment.ends_with('.') {
        return Err(VaultError::FileError(
            "path components may not start with a space or end in a dot or space".to_string(),
        ));
    }
    if segment.bytes().any(|byte| {
        byte == b'\\'
            || byte == 0
            || byte < 0x20
            || byte == 0x7f
            || matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*')
    }) || segment.chars().any(is_unsafe_unicode_format)
    {
        return Err(VaultError::FileError(
            "path contains characters that are unsafe on supported platforms".to_string(),
        ));
    }
    if is_windows_reserved(segment) {
        return Err(VaultError::FileError(format!(
            "'{segment}' is a reserved filename on Windows"
        )));
    }
    Ok(())
}

/// Checks the shared filename rules for paths inside the vault. A vault may be
/// opened on different systems, so these checks don't depend on which system
/// is running the library.
///
/// Paths use UTF-8 and `/` separators. Unicode text must already use NFC,
/// the standard spelling returned by [`normalize_path`].
pub fn validate_path(path: &str) -> Result<(), VaultError> {
    if path.is_empty() {
        return Err(VaultError::FileError(
            "vault path must not be empty".to_string(),
        ));
    }
    if path.len() > MAX_PATH_LEN {
        return Err(VaultError::FileError(format!(
            "path exceeds the {MAX_PATH_LEN}-byte limit"
        )));
    }
    if !path.nfc().eq(path.chars()) {
        return Err(VaultError::FileError(
            "vault paths must use NFC Unicode normalization".to_string(),
        ));
    }
    for segment in path.split('/') {
        validate_segment(segment)?;
    }
    Ok(())
}

/// Converts Unicode text to the NFC spelling required by [`validate_path`].
///
/// Unicode can represent the same text in different ways. For example, `é`
/// can be one character or an `e` followed by an accent. This makes those forms
/// consistent. It doesn't check the other filename rules, so the result still
/// needs to go through [`validate_path`].
pub fn normalize_path(path: &str) -> String {
    path.nfc().collect()
}

pub(super) fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}
