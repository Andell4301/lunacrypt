# Contributing

Changes should keep LunaCrypt usable by both the CLI and embedding applications,
with clear security boundaries and few dependencies.
Start with the [architecture](ARCHITECTURE.md) and [security guide](SECURITY.md).
Report vulnerabilities through the private process in the security policy.

## Development

Use Rust 1.85 or newer. From a checkout:

```sh
cargo fmt --all -- --check
RUST_TEST_THREADS=2 cargo test --locked --all-targets --all-features
RUST_TEST_THREADS=2 cargo test --locked --no-default-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --no-default-features --all-targets -- -D warnings
```

The library-only run also checks the Rust example in `README.md`, which is
included in the crate documentation. In PowerShell, set
`$env:RUST_TEST_THREADS = '2'` before running the Cargo commands without their
`RUST_TEST_THREADS=2` prefixes.

## Tests

Keep small tests beside the code they test. Tests that involve several parts of
the volume belong in `src/volume/tests/`; tests that run the CLI executable belong
in `tests/cli.rs`. Reuse `src/test_support.rs` and `src/volume/tests/support.rs`
for passwords, cipher choices, and temporary files. Temporary data should be
cleaned up even when a test fails. Test both ciphers when changing shared
encryption or storage behavior.

Two test threads limit how many keys need locked memory at once. If the OS's
locked-memory limit is too low, report that problem; don't remove key protection
to make a test pass. Tests that change process resource limits must run in a
separate child process.

The [CI workflow](https://github.com/Andell4301/lunacrypt/blob/HEAD/.github/workflows/ci.yml) has the commands for release tests,
Rust 1.85, documentation, source packaging, and Android, iOS, and 32-bit builds.
Use the checks that fit the change. Building for another platform doesn't prove
that its file locking, memory protection, or recovery works: those need tests on
that platform. For dependency changes, also run `cargo audit --deny warnings`
with an up-to-date RustSec database, as in the
[security workflow](https://github.com/Andell4301/lunacrypt/blob/HEAD/.github/workflows/security.yml).

## Releases

Update the package version in `Cargo.toml` and describe the release in
`RELEASE_NOTES.md`. Commit those changes, then push a matching version tag:

```sh
git tag -a v0.1.0 -m "LunaCrypt 0.1.0"
git push origin v0.1.0
```

The release workflow checks that the tag matches the package version and runs
the full CI suite. It then builds Linux, Windows, and both macOS executables,
bundles their license notices, and calculates SHA-256 checksums. A matching
source archive is included. The GitHub release is published after every build
and upload succeeds. A failed run can resume an existing draft; it won't replace
an already published release.

The workflow publishes GitHub downloads. Publishing a crate to crates.io is a
separate step.

## Changes and review

- Keep a pull request focused on one problem. Describe the resulting behavior,
  how it was verified, and any remaining limitations. Include a reproduction
  for bug fixes when practical.
- Keep storage and cryptographic behavior in the library. Frontends should own
  presentation, user interaction, and host-specific permissions or process policy.
- Preserve explicit authentication, validation, and publication boundaries.
  Explain changes to key handling, storage formats, crash recovery, or platform
  guarantees. Ordinary refactoring should preserve existing format versions.
- Add dependencies only when they solve a concrete need. Review their platform
  support, minimum Rust version, security properties, and required features.
  Commit `Cargo.lock`; normalization and case-folding data are format-sensitive.
- Use comments to explain invariants, ordering requirements, and non-obvious
  platform behavior. Keep comments current; remove obsolete explanations and
  avoid narrating code that is already clear.
- Prefer focused regressions that demonstrate observable behavior. Preserve
  failure-path, tampering, and recovery assertions when reorganizing tests.
  Run platform-specific filesystem changes on the affected platform when possible
  and state when validation was limited to cross-compilation.

The crate forbids application-level unsafe Rust. Use established cryptographic
implementations and keep new abstractions small enough that ownership and failure
handling remain easy to inspect.

## License

Contributions are accepted under the GNU General Public License, version 3 only
(`GPL-3.0-only`). See the [full license](LICENSE-GPL-3.0).
