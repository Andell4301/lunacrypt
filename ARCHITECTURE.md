# How LunaCrypt works

LunaCrypt stores files in a single encrypted vault with a fixed capacity. The
library handles encryption, file storage, and recovery. The CLI calls those same
operations, and a GUI can use them too.

An open `Volume` holds the vault file, its keys, the list of files inside it, and
a map of free space. Most of the other modules exist to help it do one of those
jobs. This guide explains how they fit together. The
[security guide](SECURITY.md) covers the limits of these protections.

## What's in the vault file?

```text
Start of file
    |
    v
+----------+----------+-----------+-----------+-----------------------+
| Header A | Header B | Catalog A | Catalog B | File contents          |
| 4096 B   | 4096 B   |           |           |                       |
+----------+----------+-----------+-----------+-----------------------+
                      <---- All of this is stored in chunks -------->
```

The **headers** contain the settings needed to open the vault and an encrypted
payload holding its master key. We keep two copies so one can survive a damaged
or interrupted write to the other. Each copy gets its own salt and nonce, so
their encrypted bytes differ even when they describe the same vault.

The **catalog** is the list of files and directories. A file entry tells us its
path, size, identity, and which chunks hold its contents. We also keep two copies
of the catalog. These are separate from the two header copies: the header tells
us how to open the vault, while the catalog tells us what's currently in it.

Catalog space is reserved when the vault is created. It doesn't compete with
file contents for space, but it can fill up independently. A vault can have room
for more file bytes and still lack room for another catalog entry.

The **file-data area** contains chunks reserved for file contents, including
chunks that are currently unused. Each file uses one consecutive range. This
makes lookup straightforward, but scattered free chunks might not fit a large
file even when their total size would be enough.

## The password and the master key do different jobs

We generate the master key randomly when creating the vault. It isn't made from
the password. The password protects the header that contains it.

```text
Password + this header's public salt and Argon2 settings
                         |
                      Argon2id
                         |
                  Password-derived key
                         |
               HKDF: "header encryption"
                         |
                  Header encryption key
                         |
                Decrypt the header payload
                         |
                  Vault's master key
              (randomly generated at creation)
                         |
                         +-- HKDF: "file data" ------------> File key
                         +-- HKDF: "metadata" -------------> Catalog key
                         +-- HKDF: "header authentication" -> Header MAC key
```

Argon2id makes password guesses expensive. HKDF gives each job its own key,
using a different fixed label for each purpose. The same input key and label
produce the same output, so we can derive these keys again instead of storing
them all in the vault.

Changing the password encrypts the header payload again with keys derived from
the new password. The master key stays the same, so we don't have to encrypt all
the files again. An old vault backup still works with its old password.

The public password-derivation settings are checked before allocating Argon2's
work memory. Otherwise, someone could edit a header to ask for unreasonable
amounts of memory or work. Creation also checks these settings before sizing or
filling the destination file.

### How do we know which cipher opens the header?

The selected cipher, either XChaCha20-Poly1305 or AES-256-GCM-SIV, encrypts the
headers, catalog, and file contents. But we keep that choice inside the encrypted
header because we don't want to publish which one was selected.

So, when opening a header, we try the supported ciphers. We derive the password
key once for that header, then use it for the attempts. We accept a result only
if authenticated decryption succeeds, the payload names the cipher that opened
it, and the outer MAC passes. A key-derivation or memory-protection failure still
returns an error; it doesn't mean we should try another cipher.

This idea came from [VeraCrypt's encryption scheme](https://veracrypt.io/en/Encryption%20Scheme.html).
Here, our ciphers check an authentication tag before we accept the decrypted
bytes.

Both ciphers use the same stored sizes. Headers and records each reserve 24
random bytes for the nonce field. XChaCha20 uses all 24 as its nonce; AES uses
the first 12. We authenticate the entire field, including AES's extra bytes.
Leaving those bytes zero would give away AES even with its cipher ID encrypted.
The vault still has a recognizable format and public password-derivation
settings; this doesn't make the whole file look like random data.

## Chunks, records, and authentication

A **chunk** is a fixed number of plaintext bytes. A **record** is what we write
to disk after encrypting that chunk:

```text
+----------------------+--------------------------+--------------------+
| Random nonce field   | Encrypted chunk          | Authentication tag |
| 24 bytes             | chunk_size bytes         | 16 bytes           |
+----------------------+--------------------------+--------------------+
```

The final chunk of a file is padded with zeros if needed. The catalog stores the
real file length, so readers know where its contents end and can check that the
padding is valid. Catalog chunks use this same record layout.

Authentication checks more than the encrypted bytes. We also supply the details
we expect the chunk to belong to, called **associated data**: the vault ID, the
file ID or catalog copy, the chunk's position, its size, and its purpose. The
stored nonce field is included too.

Those details come from the checked header and catalog. For example, moving an
encrypted chunk elsewhere doesn't make it valid there: the reader checks it
against the new position, which won't match its tag. A replacement file gets a
fresh identity, so it can't accept old encrypted chunks just because it reused
the same name or storage.

The catalog's saved format shortens repeated path prefixes. Loading it rebuilds
the full names, which can take much more memory than the saved bytes. We bound
both the saved size and the expanded path storage, along with the entry count.

Paths inside the vault are relative and use `/`, such as `docs/notes.txt`. The
catalog rejects names that would clash under its cross-platform filename rules.
Callers can use `normalize_vault_path` to make equivalent Unicode spellings
consistent; library operations expect paths to already follow the rules.

## Opening and choosing between copies

Opening takes a file lock, checks both headers, and chooses a consistent
authenticated header. It then checks that the file's length and chunk counts
match the header, opens the catalog copies, and rebuilds the free-space map
from the chosen catalog. The allocator initially considers every data chunk
free, then reserves each file's range.

Both headers and catalogs have an update number, called a **generation**. Header
generations advance when the password changes. Catalog generations advance when
the file list changes. Recovery uses authenticated generations to distinguish
an older copy from a newer one.

Each catalog copy starts with a **head**: a description containing its generation,
length, and a hash of the catalog bytes. The first chunk holds both the head and
the beginning of the catalog. Any remaining catalog bytes go in subsequent
chunks, called the body; unused reserved chunks aren't part of that snapshot.
The head can pass authentication even when the body is damaged. That distinction
matters: a valid head may prove that a newer update exists even though we can't
recover its contents.

The recovery rules are deliberately cautious:

- A storage read error stops opening. We can't assume bytes are damaged just
  because the operating system couldn't read them, and overwrite them as a repair.
- Authenticated fields must still make sense. We reject malformed authenticated
  headers or catalog heads rather than repairing over state we don't understand.
- A known newer catalog that fails validation prevents falling back to an older
  one. Otherwise, opening could silently hide a saved change.
- Copies at the same generation must agree. Catalog copies are compared using
  their authenticated hashes; header copies must contain equivalent payloads.
- A valid newest copy can repair an older or damaged copy when these checks allow
  it. A read-only open leaves the file alone and reports reduced redundancy.

The header's **outer MAC** is another authentication check, made with a key
derived from the master key. It lets us check both headers once either one has
revealed that master key. For example, an old password might decrypt an older
header while its recovered master key proves that the other header has a newer
password change. We mustn't accept the old header in that case.

We release the unchosen catalog's encoded bytes before expanding the chosen one,
so opening doesn't need two complete catalogs in memory. File contents are
checked as they are read; `verify` reads and authenticates every current file.

These checks rely on evidence still present in the vault. Replacing the whole
file with an older valid backup can remove that evidence. There's no external
counter that tells LunaCrypt a newer version once existed.

## Saving a change without losing the previous state

Before writing file contents, we build the proposed catalog, encode it, check
that it fits, and build its free-space map. `PreparedCatalog` keeps those pieces
together so the catalog can't change after we've checked the bytes we'll save.
It also belongs to a particular open session and next generation.

Adding a file then follows this order:

```text
Prepare and check the new catalog
                |
Write new file chunks, then synchronize them to storage
                |
Stop existing preview readers
                |
Write first catalog body -> synchronize -> write its head -> synchronize
                |
Write second catalog body -> synchronize -> write its head -> synchronize
                |
Adopt the prepared catalog and free-space map in memory
```

We save file data first so a new catalog never deliberately points at data that
hasn't been saved. We save each catalog's body before its head so an interruption
doesn't leave a new head announcing body bytes we haven't finished writing.

The new catalog takes effect when the first new head is written. We still need
both copies saved before reusing removed files' chunks: the older copy might
refer to them if recovery has to use it. Once both copies succeed, adopting the
prepared state in memory doesn't require another allocation or validation step.

A failure partway through writing can leave us unsure what reached storage.
The volume then stops further operations by marking the handle **poisoned**.
`CommitUncertain` means the change may already have taken effect. Close the
handle, reopen it, and inspect the recovered state before retrying.

Importing a directory uses these operations one entry at a time and attempts to
undo its additions after an ordinary error. The whole directory import is not
one indivisible operation that survives a crash.

## Readers, memory, and the host application

Preview readers share the volume's locked file handle. They remember where a
file lived, so a catalog change could make those positions stale. The reader
session waits for ongoing reads and stops old readers before a catalog change,
password change, poisoning, or closure. A reader can't keep using the vault
after its `Volume` is dropped.

Read-only volumes hold shared file locks; a writable volume needs an exclusive
lock. These locks coordinate applications that respect them. They don't replace
filesystem permissions or prevent an unrelated program from ignoring the lock.

The library's I/O helpers use explicit file positions on Unix and Windows.
Other platforms use a mutex around moving the shared file cursor and reading or
writing. Code outside those helpers must not move that cursor concurrently.

Raw keys live in separate memory mappings, locked before secret bytes are
written and wiped before unlocking. Owned plaintext and catalog buffers are
also wiped when released, but they aren't locked against swapping. The
[memory-handling section](SECURITY.md#memory-handling) explains the limits,
including caller copies and temporary values inside dependencies.

Local imports and outputs use open directory handles to keep operations tied
to the intended directories. Filesystem extraction writes each file to a
temporary file and checks all its contents before publishing the destination.
Publication refuses to replace an existing entry. A later failure during a tree
extraction can still leave earlier completed files in place.

The CLI owns arguments, password prompts, and terminal output. A GUI owns its
interface buffers, background work, platform document permissions, and process
settings. All vault operations are synchronous, so a GUI should keep expensive
password derivation and file I/O off its event loop. See
[CONTRIBUTING.md](CONTRIBUTING.md) for development guidance.

## A reading order for the source

Start with the public types, then follow the smaller building blocks into the
storage operations. Each row builds on the previous ones.

| Order | Files | What to look for |
| --- | --- | --- |
| 1 | [lib.rs](src/lib.rs), [errors.rs](src/errors.rs), [volume/types.rs](src/volume/types.rs) | The public API, password/plaintext wrappers, options, and errors callers need to handle. |
| 2 | [secret_key.rs](src/secret_key.rs), [cipher/mod.rs](src/cipher/mod.rs), [kdf/mod.rs](src/kdf/mod.rs) | Protected keys, encryption, password derivation, and keys for separate purposes. |
| 3 | [header/payload.rs](src/header/payload.rs), [header/slot.rs](src/header/slot.rs), [header/mod.rs](src/header/mod.rs) | The encrypted settings, one header copy, then choosing and repairing the pair. |
| 4 | [io.rs](src/io.rs), [volume/chunk_io.rs](src/volume/chunk_io.rs), [volume/geometry.rs](src/volume/geometry.rs) | Reading at offsets, encrypted records, and checking sizes and positions. |
| 5 | [volume/allocator.rs](src/volume/allocator.rs), [volume/file_table.rs](src/volume/file_table.rs), [its codec](src/volume/file_table/codec.rs), [its path rules](src/volume/file_table/path.rs) | Free ranges, file entries, saving the catalog, and portable filenames. |
| 6 | [volume/metadata.rs](src/volume/metadata.rs), [volume/persistence.rs](src/volume/persistence.rs) | Writing catalog copies in order, choosing a copy, and committing prepared changes. |
| 7 | [volume/mod.rs](src/volume/mod.rs), [volume/lifecycle.rs](src/volume/lifecycle.rs), [volume/operations.rs](src/volume/operations.rs), [volume/password.rs](src/volume/password.rs) | How `Volume` uses those pieces to create, open, change, and verify a vault. |
| 8 | [volume/content.rs](src/volume/content.rs), [volume/reader.rs](src/volume/reader.rs) | The shared authenticated read path, preview readers, and stopping stale readers. |
| 9 | [volume/path_io.rs](src/volume/path_io.rs), [volume/import.rs](src/volume/import.rs), [volume/extraction.rs](src/volume/extraction.rs), [volume/transport.rs](src/volume/transport.rs) | Local filesystem handling, importing files, extracting plaintext, and transferring encrypted vaults. |
| 10 | [main.rs](src/main.rs), [cli/mod.rs](src/cli/mod.rs) | The executable entry point, command parsing, and calls into the library. |

Tests beside each implementation show the smaller cases. The
[volume test suites](src/volume/tests/mod.rs) exercise complete operations,
including damaged copies, interrupted writes, reader shutdown, and filesystem
failures.
