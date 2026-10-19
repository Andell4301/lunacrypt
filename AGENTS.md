# Working on LunaCrypt

Prioritize **security**, then **maintainability**, then **leanness**. These rules
apply to the whole repository. LunaCrypt must work as both a CLI and a library
for cross-platform GUI applications.

## Making changes

Read [CONTRIBUTING.md](CONTRIBUTING.md). Before changing storage or cryptography,
also read [SECURITY.md](SECURITY.md) and the relevant parts of
[ARCHITECTURE.md](ARCHITECTURE.md), which includes the source map.

- Stay within the requested scope and preserve unrelated edits. Make routine,
  reversible changes without adding approval steps. Do not reset history, push,
  or publish unless asked.
- Explain the compatibility impact of public API and file-format changes. Update version numbers when those changes require it.
- Keep modules focused and reuse existing mechanisms. Avoid parallel
  implementations and abstractions without a concrete need.
- Write plain comments explaining why an order, rule, or platform workaround
  matters. Document public API ownership, errors, and recovery behavior. Keep
  explanations current; don't hide missing documentation by suppressing warnings.
- Keep comments about the current behavior and its reasoning. Don't add comments
  solely to announce a change, rename, move, or removal; Git records that history.
  Mention past behavior only when it explains a current constraint or design
  decision.
- Add dependencies only for a concrete need. Check platform support, required
  features, and Rust 1.85 compatibility. Keep `Cargo.lock` committed. Changes to
  Unicode normalization or case-folding pins need a filename-format review.
- Keep README examples, API docs, and security claims accurate. Passing tests
  and source review are not an independent security audit.

## Library and CLI

Storage, encryption, import, and recovery belong in the library. `src/cli/`
handles arguments, password prompts, and presentation. GUI applications should
use the same library operations. Keep terminal dependencies behind the `cli`
feature and preserve builds with `--no-default-features`.

Escape untrusted terminal text and handle output failures without panicking.

## Security and storage

- Keep `forbid(unsafe_code)` and use established cryptographic implementations.
  Don't weaken authentication, parameter bounds, key protection, or cleanup to
  simplify code or pass a test.
- Protect raw key memory before writing key bytes. Wipe it before unlocking or
  unmapping. Protection failure must return an error, with no unlocked fallback.
  Avoid unnecessary secret copies and never log secrets. Plaintext and catalog
  buffers do not have the same protections as key memory.
- Prepare the catalog and validate its capacity before writing file data.
  Synchronize file data first, then each catalog's body, then its head. Both
  catalog copies must commit before reusing old file chunks. Adopt prepared
  state only after commit.
- Preserve poisoning, `CommitUncertain`, and preview-reader revocation behavior.
- Recovery must distinguish read failures from damaged copies. Never repair
  over an I/O failure, accept conflicting copies at the same authenticated
  generation, or fall back past known newer invalid metadata.
- Keep canonical portable paths and use directory handles to anchor filesystem
  operations. Authenticate each extracted file before publishing it. Publication
  must not replace an existing target.

## Validation

Test at the narrowest boundary that reproduces the behavior. Follow the
[test placement guidance](CONTRIBUTING.md#tests) and reuse `src/test_support.rs`
and `src/volume/tests/support.rs`. Use disposable data and owned temporary
directories that clean up on exit and panic. Cover both ciphers for shared
encryption or storage changes.

For Rust behavior changes, run focused tests while editing, then run the
applicable checks below:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --no-default-features --all-targets -- -D warnings
RUST_TEST_THREADS=2 cargo test --locked --all-targets --all-features
RUST_TEST_THREADS=2 cargo test --locked --no-default-features
```

Two test threads limit locked-memory use. If the runner's quota is too low,
report it; don't disable key locking. Resource-limit failure tests must run in
separate child processes.

Use the additional checks in [CONTRIBUTING.md](CONTRIBUTING.md#tests) when the
change calls for them. For prose-only changes, check links and consistency.
Compile doctests if Rust examples change.

Report what changed, which checks ran, and any limitations. Distinguish tests
run on a platform from cross-compilation, and say which checks couldn't run.
Put test results in the task report, not repository policy documents.
