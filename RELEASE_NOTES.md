# LunaCrypt 0.1.2

This release updates direct dependency requirements and the locked dependencies
used for source builds and release executables.

## Security update

The locked dependencies now use `rustix` 1.1.6 instead of 1.1.5, addressing
[RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html).
Affected extended-attribute functions can mark unwritten memory as initialized
when called with a zero-length buffer. The advisory lists 1.1.6 and newer as
patched. The minimum `rustix` requirement is also raised to 1.1.6.

## Dependency updates

- Raise dependency requirements for `cap-std`, `getrandom`, `memmap2`, `rustix`,
  `thiserror`, and `zeroize` to their updated patch versions.
- Refresh `Cargo.lock`, including `ctutils` 0.4.8, `zeroize` 1.9.2,
  `rustix` 1.1.6, and updates to CLI and transitive dependencies.
- Keep the Unicode normalization and case-folding dependency pins unchanged.

## Compatibility and upgrading

- Building from source still requires Rust 1.87 or newer. Downloaded executables
  do not require Rust.
- The public API, CLI commands, and vault format are unchanged. Existing vaults
  remain compatible; no migration is required.
- CLI users should replace their executable with the 0.1.2 download. Source
  builds should use `--locked` to select this release's dependency versions.
- Library users should update LunaCrypt and their application's `Cargo.lock`.
  LunaCrypt's lockfile does not control dependency versions in consuming
  applications.

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
