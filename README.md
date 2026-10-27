# LunaCrypt

> **LunaCrypt is still in early development / pre-release.**

[![CI](https://github.com/Andell4301/lunacrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Andell4301/lunacrypt/actions/workflows/ci.yml)

LunaCrypt stores files and folders inside one encrypted vault file. It's written
in Rust and can be used from the command line or as a library in another
application.

You choose the vault's capacity when you create it. File contents are encrypted,
as are their names and the catalog that keeps track of them. LunaCrypt checks
the headers and catalog for damage or tampering when opening a vault, then
checks file contents as you read them.

LunaCrypt hasn't had an independent security audit. Keep separate backups of
important files, and read [SECURITY.md](SECURITY.md)
for what it protects and where its limits are.

## Install

Download an executable from [Releases](https://github.com/Andell4301/lunacrypt/releases/latest).
There are archives for Linux x86-64, Windows x86-64, and Intel and Apple Silicon
Macs. Each archive includes the executable, documentation, and license notices.
A SHA-256 checksum file accompanies each download. Linux downloads require
glibc 2.35 or newer. See the release notes for the build and test environments.

Extract the archive and run `./lunacrypt --help`, or `.\lunacrypt.exe --help`
in Windows PowerShell. You can move the executable to a directory on your `PATH`.

To build from source, you'll need Rust 1.87 or newer:

```sh
git clone https://github.com/Andell4301/lunacrypt.git
cd lunacrypt
cargo install --path . --locked
lunacrypt --help
```

To build without installing, use `cargo build --release --locked`. The executable
will be `target/release/lunacrypt`, or `target/release/lunacrypt.exe` on Windows.
Linux, macOS, and Windows are the intended desktop platforms. The operating
system must support the file access and key-memory protection described in
[SECURITY.md](SECURITY.md).

## Use the command line

Here's an example of creating a vault, adding a folder, and extracting it again:

```sh
lunacrypt create documents.luna --size 1GiB
lunacrypt add documents.luna ./documents --dest documents
lunacrypt list documents.luna
lunacrypt info documents.luna
lunacrypt verify documents.luna
lunacrypt extract documents.luna documents ./restored
```

Commands prompt for a password when they need one. Passwords aren't passed as
command-line arguments. `add` accepts a file or a folder and its contents.
`--dest` chooses its path inside the vault; if omitted, the source's name is used.
Creation and extraction refuse to overwrite existing files.

`list` shows what's inside. `info` shows space usage and whether either saved
header or catalog copy needs repair. `verify` reads every current file and checks
for damaged or altered contents. It can detect damage, but it can't repair file
contents.

There are also commands to create an empty folder, remove an entry, and change
the password:

```sh
lunacrypt mkdir documents.luna drafts
lunacrypt remove documents.luna drafts
lunacrypt change-password documents.luna
```

Removing a folder with contents requires `--recursive`. Changing the password
keeps the vault's master key, so it doesn't need to encrypt all the files again.
Someone who can open an older copy of the vault can still recover that same
master key. A password change doesn't revoke that access.

Paths inside the vault use `/`, such as `documents/notes.txt`. Imports make
Unicode spellings consistent and reject names that would conflict across
supported platforms. They also reject symbolic links and special files. Run
`lunacrypt <command> --help` for the full arguments and options.

### Choose the vault's size and encryption

| Option | What it does |
| --- | --- |
| `--size 1GiB` | Reserves at least this much space for file contents. Required. |
| `--cipher chacha` | Uses XChaCha20-Poly1305, the default. Use `aes` for AES-256-GCM-SIV. |
| `--chunk-size 64KiB` | Chooses how many bytes each file chunk holds. Defaults to 64 KiB; must be a power of two from 4 KiB to 16 MiB. |
| `--metadata-capacity 16MiB` | Reserves at least this much space for each catalog copy. The library chooses a capacity if omitted. |
| `--fill` | Fills the space after the headers with random bytes at creation. This takes more time and avoids the disk-space savings of a sparse file. |

The catalog stores file names, sizes, and locations. It has its own capacity,
separate from the space for file contents, and is saved twice to help recovery.
Headers, catalog copies, and encryption overhead make the vault file larger
than the size requested with `--size`.

Sizes can be plain byte counts or use units such as `MB` and `MiB`. Decimal units
use powers of 1,000; binary units use powers of 1,024. Fractional sizes such as
`0.5MiB` are accepted and fractional bytes round up. Units through `EB` and `EiB`
are supported, subject to the vault's size limits.

For example, to create a vault using AES:

```sh
lunacrypt create archive.luna --size 2GiB --cipher aes
```

The selected cipher encrypts the headers, catalog, and file contents. The cipher
choice is stored inside the encrypted header. Opening tries both supported
ciphers, so you don't have to specify it again. Changing the cipher requires a
new vault and transferring the files. See [SECURITY.md](SECURITY.md) for the
usage limits of AES-GCM-SIV.

## Use the library

The library does the storage and encryption work; the CLI handles arguments,
password prompts, and output. A GUI can use the same library without bringing in
those terminal dependencies. From an application beside the source checkout:

```toml
[dependencies]
lunacrypt = { path = "../lunacrypt", default-features = false }
```

```no_run
use lunacrypt::{Password, Plaintext, VaultError, Volume};
use std::path::Path;

fn create_vault(path: &Path, password_bytes: Vec<u8>) -> Result<Volume, VaultError> {
    let password = Password::new(Box::new(password_bytes));
    let mut vault = Volume::create_container(
        path,
        &password,
        64 * 1024 * 1024,
        64 * 1024,
    )?;
    drop(password);

    vault.add_file("notes/message.txt", b"hello")?;
    let preview: Plaintext = vault.read_range("notes/message.txt", 0, 5)?;
    assert_eq!(preview.as_slice(), b"hello");
    drop(preview);

    Ok(vault)
}
```

This creates a vault with at least 64 MiB for file contents and 64 KiB chunks.
`create_container` uses XChaCha20-Poly1305. To choose AES, use
`create_container_with_options` and set `CreateOptions::cipher` to
`CipherId::Aes256GcmSiv`.

| What you need | API |
| --- | --- |
| Import a local file or folder | `Volume::import_path` |
| Add or extract a file through a stream | `add_file_from_reader` / `extract_file_to_writer` |
| Get decrypted bytes | `extract_file` / `read_range` |
| Read different parts of a file for a preview | `open_file_reader` |
| Use a file handle from a platform file picker | `create_container_on_file` / `open_container_file` |

The APIs are synchronous. In a GUI, run password derivation and file operations
away from the UI thread so the interface doesn't freeze. Preview readers can be
cloned across threads, but their `Volume` must stay open. Catalog changes,
password changes, storage failures that poison the volume, and closing the
volume revoke those readers.

`Password`, `Plaintext`, and `FileInfo` wipe the memory they own when dropped.
Bytes or names copied into ordinary buffers need their own cleanup, as do GUI
buffers and bytes sent to a stream.
Avoid logging decrypted values: `Plaintext` and `FileInfo` debug output can show
their contents. Keys use locked memory, but passwords, plaintext, and catalog
buffers do not. If the OS can't lock the key memory, the operation fails rather
than storing the key unprotected. [SECURITY.md](SECURITY.md) explains what this
means.

Library callers must supply valid vault paths. `normalize_vault_path` makes
Unicode spellings consistent; `validate_vault_path` checks all the naming rules.

A file handle supplied by an application must support the required regular-file
operations, synchronization, and locks. If a document provider only offers a
stream, the encrypted transport APIs can copy the vault into storage owned by
the application. The application handles provider permissions and saving the
result back.

Generate API documentation with `cargo doc --no-default-features --open`.

## A few things to keep in mind

- Data and catalog capacities are fixed. Each file needs enough free chunks next
  to each other, so a file may not fit even when the total free space looks large
  enough.
- Opening for writing repairs a recoverable header or catalog copy. Opening
  read-only reports the problem without changing the vault. The two copies help
  with recovery; they aren't a backup of your file contents.
- `CommitUncertain` means a write or output file may already have been saved.
  Inspect the affected vault or destination before retrying. If a volume returns
  `Poisoned`, close it and reopen it before continuing.
- Importing or extracting a folder happens one entry at a time. An interruption
  can leave only part of the folder copied. Removing a file doesn't securely
  erase its old encrypted bytes.

## Read more

- [Security and limitations](SECURITY.md)
- [How the code and file format fit together](ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)

## License

Copyright (c) 2026 LunaCrypt contributors.

LunaCrypt uses the GNU General Public License, version 3 only (`GPL-3.0-only`).
See the [full license](LICENSE-GPL-3.0).

If you distribute LunaCrypt or a modified version, you must make the corresponding
source code available to recipients under the GPL. An application distributed
as a combined program with this library must also be licensed under the GPL.
You can still charge money for the software. Changes used privately do not need
to be published.

Dependencies keep their own licenses. Their required copyright notices, license
texts, and other applicable notices must also be kept when distributing them.
