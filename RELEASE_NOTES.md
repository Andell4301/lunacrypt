# LunaCrypt 0.1.0

LunaCrypt stores files and folders in an encrypted vault. It includes a command
line interface and a Rust library for applications that provide their own UI.

- XChaCha20-Poly1305 or AES-256-GCM-SIV encryption for headers, catalogs, and files.
- Argon2id password derivation and protected key memory.
- File and directory import, extraction, verification, and password changes.
- Two header copies and two catalog copies for recovery from interrupted writes.
- Positioned file reads and seekable readers for previews.

## Downloads

| Archive target | Build and test environment |
| --- | --- |
| `x86_64-unknown-linux-gnu` | Ubuntu 22.04; requires glibc 2.35 or newer. |
| `x86_64-pc-windows-msvc` | Windows Server 2022. |
| `x86_64-apple-darwin` | macOS 15, Intel. |
| `aarch64-apple-darwin` | macOS 15, Apple Silicon. |

Extract the archive and run `./lunacrypt --help`, or `.\lunacrypt.exe --help` in
PowerShell. These executables are unsigned. Each archive includes documentation,
the GPLv3 license, and dependency notices. The source archive contains the code
and build scripts for this version.

Each download has a matching `.sha256` file. On Linux, check it with
`sha256sum --check <archive>.sha256`; on macOS, use
`shasum -a 256 --check <archive>.sha256`. In PowerShell, use
`Get-FileHash <archive> -Algorithm SHA256` and compare it with the checksum file.

## Things to know

The vault's file-data and catalog capacities are fixed when it is created.
Headers and catalogs have recovery copies; file contents do not. `verify`
detects damaged file contents but cannot repair them.

Changing the password keeps the same master key. It does not revoke access to
older copies of the vault. If the master key is exposed, transfer the contents
into a new vault with a new key.

Key memory must be locked successfully or opening fails. Passwords, decrypted
file contents, and catalog buffers are wiped when released, but are not locked
against swapping. LunaCrypt has not had an independent security audit.

See `README.md` for usage and `SECURITY.md` for the protections and their limits.
