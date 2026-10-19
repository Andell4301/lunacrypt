# Security

LunaCrypt encrypts the files and filenames stored in a vault. It also checks
whether protected data has changed before accepting it (authentication). It detects damage or tampering, but it cannot bring missing data
back. Keep backups.

LunaCrypt has not had an independent security audit. Passing tests and reviewing
the code are useful, but neither is an independent audit or certification.

## What this protects against

The application, operating system, and random number generator need to be
trusted. A weak password can still be guessed. Encryption also cannot protect
an unlocked vault from someone who can read the application's memory or control
the computer.

Some information is still visible without the password: the vault's total
size, its public header fields and password-derivation settings, when it changes,
and which parts of a sparse file have storage allocated. A sparse file leaves
unused regions unallocated. `--fill` writes random bytes into the space after
the headers when the vault is created, hiding that initial allocation pattern.
It does not hide later reads or writes.

The library can use newer authenticated copies to detect an attempt to fall
back to older contents. But someone who replaces the whole vault with an old
backup, or destroys all evidence of a newer state, may go undetected. Detecting
every such rollback would require a trusted counter or record outside the vault.

Removing a file makes its space available for reuse. It does not securely erase
the old encrypted bytes.

## Cryptography

Creating a vault generates a random 256-bit master key. Separate keys are derived
from it for file contents, the catalog, and header authentication. The catalog
stores filenames, file locations, and other metadata.

The password has a different job. Argon2id turns it into a key, from which we
derive the key that encrypts the header containing the master key. The defaults
are 64 MiB of memory, three passes, and four lanes. The stored Argon2 settings
are public, so they are checked against limits before allocating its work memory.
An edited header cannot request arbitrary amounts of memory or computation.

Changing the password encrypts the same master key under a new password-derived
key. It does not replace the master key or re-encrypt the files. Someone who can
recover the master key from an old backup can still use that key; changing the
password does not revoke that access.

### Using either cipher without publishing the choice

The selected cipher encrypts the header, catalog, and file contents:

- **XChaCha20-Poly1305** is the default. Each encryption gets a random 192-bit nonce.
- **AES-256-GCM-SIV** uses a random 96-bit nonce.

A nonce is a value generated for an encryption operation. It is stored alongside
the encrypted bytes and does not need to be secret. Both ciphers also produce
an authentication tag, which decryption checks before accepting the plaintext.

We want to support both ciphers without exposing the choice in a readable field.
So the choice is inside the encrypted header, and opening tries both. The
password key is derived once per header copy. A successful attempt must pass
authentication, contain the matching cipher choice, and pass the separate
header authentication check. This approach was inspired by
[VeraCrypt's encryption scheme](https://veracrypt.io/en/Encryption%20Scheme.html).

Both choices use the same stored sizes and a 24-byte random nonce field. AES
uses only the first 12 bytes as its nonce. We still fill the rest with random
bytes: leaving them zero would give away the cipher. The entire field is
authenticated, so changing those extra bytes also makes decryption fail. This
hides the explicit cipher choice; it does not hide the vault format, public
Argon2 settings, or operation timing.

Authentication also checks context, called *associated data*. That distinguishes
file data from catalog data. For a file chunk, it includes which vault and file
it belongs to, its position within the file, and where it is stored. Catalog
chunks include their copy and position instead.
This prevents accepting a valid encrypted chunk in the wrong place. Each new
file gets a random identity, so a replacement file does not inherit the old
file's context.

### Limits when using AES

AES-GCM-SIV avoids the catastrophic loss of secrecy and authentication that
AES-GCM can suffer when a nonce repeats. Repeats can still reveal that messages
are equal, so fresh random nonces are still required.

For AES vaults, the supported limit is **at most 2^32 record encryptions with the
file-data key, and separately at most 2^32 with the catalog key**. A record is one
encrypted chunk. Each contains at most 16 MiB of plaintext and uses a fresh
random 96-bit nonce. This limit is conservative relative to the random-nonce
limits in [RFC 8452, section 9](https://www.rfc-editor.org/rfc/rfc8452.html#section-9).

Count rewrites and encrypted writes that later fail, as well as writes to every
copy of the vault that shares its master key. The library does not enforce a
global counter: it cannot see other copies, and restoring an old backup could
also restore an old count. Create a new vault and transfer the contents before
reaching the limit. A password change does not reset it.

The [RustCrypto AES-GCM-SIV crate](https://docs.rs/aes-gcm-siv/0.12.1/aes_gcm_siv/#security-warning)
has not been audited as a complete crate, although some components have. Its
portable implementation needs multiplication that takes the same time regardless
of its inputs. Processors with variable-time multiplication are unsupported.

## Integrity and interrupted operations

The vault keeps two headers and two catalog copies. When saving a file, we first
write and synchronize its encrypted data. Only then do we save a catalog that
points to it. Each catalog copy has a body and an authenticated head. We save
the body before its head, so a head cannot announce a completed update before
the rest has been saved. Space retired by an update can be reused only after
both catalog copies have been saved.

Opening checks the authenticated update numbers, called *generations*, and
summaries of the catalog contents. Copies at the same generation must agree.
If a newer copy is authenticated but its contents are invalid, we report an
error instead of quietly opening an older version. An I/O error is also an
error, rather than permission to overwrite that copy during repair. Authenticated
but malformed headers and catalog heads are rejected too.

When one copy can safely repair the other, a writable open performs the repair.
A read-only open leaves the file alone and reports that a redundant copy is
missing, damaged, or out of date. [ARCHITECTURE.md](ARCHITECTURE.md) explains
the save and recovery steps in more detail.

A failed write or synchronization while updating vault records leaves the open
handle *poisoned*. That means further operations are refused, and existing
preview readers stop working. Close and reopen it to inspect the recovered
state. `CommitUncertain` means the change may already have been saved, so
inspect that state before retrying.

`CommitUncertain` can also mean that creation, extraction, or export made its
output visible, but could not confirm that it would survive a crash or power
loss. Inspect the destination before retrying. These errors do not necessarily
poison an existing vault.

### Imports, extraction, and partial output

Encrypted stream imports authenticate the fixed-size header before reading the
body. They check that the body matches the declared layout and verify the
contents before making the destination visible. A valid header can still
describe a large supported vault. Applications accepting documents from other
people should set storage quotas and I/O timeouts.

Different ways of reading or writing files have different failure behavior:

- A preview read into a supplied buffer erases that buffer on failure.
- `extract_file_to_writer` can leave an already verified prefix in the caller's
  output if a later chunk fails.
- Filesystem extraction writes each file to a temporary file and makes it
  visible at its final path only after the whole file authenticates. Extracting
  a directory tree can leave completed files and directories after a later error.
- Recursive local imports try to roll back after ordinary errors. The whole
  tree is not one transaction, so an interruption can leave a partial import.

## Memory handling

Raw keys get their own memory regions, with no file behind them. This includes
the master key, Argon2 and HKDF output keys, and keys used for encryption and
preview readers. Each region follows this order:

```text
Allocate memory -> Lock it -> Write key bytes -> Use key -> Wipe it -> Unlock and release it
```

The OS can make room in RAM by moving some of its contents to disk, called
swapping. Locking keeps these key regions out of ordinary swap space. On Linux,
we also require `MADV_DONTDUMP`, which excludes these regions from ordinary core dumps
(saved copies of a crashed process's memory). Other platforms do not have the
same dump-exclusion guarantee here.

If allocation or protection fails, the operation returns
`VaultError::SecretKeyProtection`. We do not continue with an unlocked key.
Even a small key takes at least one OS page of locked memory. Larger page sizes,
temporary keys, and multiple open vaults all increase the required quota. The
host application controls that quota and process-wide crash reporting; the
library does not change those settings.

The cipher libraries also create temporary internal state from the raw keys.
We create it for each operation instead of retaining it between operations.
Cleanup features are enabled for AES, POLYVAL, and HMAC, alongside our key and
working-buffer cleanup. This does not guarantee that every intermediate value
inside a dependency is erased.

### What gets wiped, and what can still reach disk

The library wipes its owned password buffers, Argon2 workspace, decrypted records,
header payloads, encoded catalogs, decoding buffers, and stored catalog names
when they are released. Returned `Plaintext` buffers also wipe their spare
capacity when dropped. `FileInfo` wipes its owned path and file metadata.
The CLI avoids extra full copies of the password and releases its input after
use. Preview-reader `Debug` output leaves out the filename.

**Only key regions are locked.** Passwords, the Argon2 workspace, plaintext,
and catalog memory can still be swapped or included in dumps. The protections
also do not cover compiler-made stack or register copies, temporary values in
password-input or Unicode-normalization libraries, hibernation, or the host's
crash reporting.

Callers need to manage their own copies, including GUI and stream buffers.
Growing a vector or string can release an old allocation without wiping it.
`Plaintext` and `FileInfo` also show their contents through `Debug`, so logging
them can expose data. Wiping runs during normal cleanup or panic unwinding;
it cannot be relied on if the process ends abruptly.

### Forking a process

Do not use inherited vault handles in a child created with `fork()`. On Linux,
the child inherits the key memory but
[does not inherit its locks](https://man7.org/linux/man-pages/man2/mlock.2.html).
Start worker processes before opening vaults, or have the child promptly call
`exec()` and open a fresh session.

## Filesystem and platform requirements

Vault locks coordinate applications that respect them. Their enforcement varies
by platform, and they do not replace filesystem permissions. If you provide a
file handle, do not retain copies that seek, truncate, write, or change its flags
while the library is using it.

Use private application directories or other protected destinations. The library
holds parent-directory handles so replacing an ancestor path cannot redirect
where it publishes or cleans up files. This does not protect against someone
who can replace temporary entries inside the destination directory itself.

Creation, path export, and extraction use private temporary files in the same
directory as the destination. Making a completed file visible at its final path
is atomic and refuses to replace anything already there. On Unix, newly created
files request mode `0600` (owner read/write), and extracted directories request
`0700` (owner only). Windows uses the directory's access-control rules. Permissions
on caller-supplied handles are the caller's responsibility. Named temporary
files, including plaintext extraction files, can remain after an abrupt exit.

The details depend on the platform:

- Linux, Android, Apple platforms, and Redox use a rename operation that refuses
  to replace an existing destination.
- Other platforms, including Windows, use atomic hard-link creation instead.
  This step fails on filesystems without hard links, such as Windows FAT/exFAT.
- On Unix, failures to synchronize the parent directory are reported. There is
  no equivalent directory-sync guarantee here on Windows, so survival after
  power loss depends on its filesystem behavior.
- Device files and document providers that cannot supply the required file I/O
  behavior are rejected.

Filesystem behavior and memory protection need runtime tests on the actual
platform. Cross-compilation checks that code builds; it does not establish
these guarantees.

## Report a vulnerability

Use the repository's **Security → Advisories → Report a vulnerability** option.
Include the affected commit, operating system, likely impact, and a small
reproduction using made-up data. Do not send real vaults, passwords, keys, or
personal files.

Keep findings private until a fix and disclosure plan can be coordinated.
