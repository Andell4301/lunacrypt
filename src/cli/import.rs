use std::path::Path;

use lunacrypt::{VaultError, normalize_vault_path};

pub(super) fn resolve_vault_destination(
    destination: Option<String>,
    source: &Path,
) -> Result<String, VaultError> {
    let path = match destination {
        Some(path) => path,
        None => source
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
            .ok_or_else(|| {
                VaultError::FileError("source has no portable UTF-8 filename".to_string())
            })?,
    };
    Ok(normalize_vault_path(&path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provided_and_default_destination_names_use_consistent_accents() {
        // Both an explicit destination and the default filename should use
        // the same form of accented characters.
        assert_eq!(
            resolve_vault_destination(
                Some("docs/cafe\u{301}.txt".to_string()),
                Path::new("source")
            )
            .unwrap(),
            "docs/café.txt"
        );
        // Without --dest, only the source filename becomes the vault path.
        assert_eq!(
            resolve_vault_destination(None, Path::new("directory/cafe\u{301}.txt")).unwrap(),
            "café.txt"
        );
        // An empty source path has no filename to use as the default.
        assert!(resolve_vault_destination(None, Path::new("")).is_err());
    }
}
