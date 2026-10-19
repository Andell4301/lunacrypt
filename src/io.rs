use std::{fs::File, io::ErrorKind};

use crate::VaultError;

#[cfg(not(any(unix, windows)))]
static POSITIONED_IO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Given a buffer and an offset, read enough bytes to fill the buffer starting at the offset.
/// `read_at` can return fewer bytes than requested. This isn't a bug. So, repeatedly call it,
/// advancing the offset by however many bytes were read, until the mutable buffer is full.
///
/// A given file handle has a shared cursor, which defines where the next regular read or write
/// from the file will take place. Concurrent operations could mess this up. So, there are two
/// ways we handle it.
///
/// The first is, on Windows and Unix, which support "read from/write to a position", we simply
/// provide the position every time, so we never have to worry about one operation relying on
/// a cursor for a position that another operation has moved.
///
/// However, other platforms may not support reading/writing from a position. So for those,
/// we do two operations: we move the cursor and then perform the read or write.
/// The mutex guard prevents another call to these helpers from moving the cursor between
/// the seek and the read or write. But, it doesn't protect against any other code messing
/// with the cursor. The operations that take a position don't have this problem.
pub(crate) fn read_exact_at(
    file: &File,
    mut buffer: &mut [u8],
    mut offset: u64,
) -> Result<(), VaultError> {
    #[cfg(not(any(unix, windows)))]
    let _guard = POSITIONED_IO_LOCK
        .lock()
        .map_err(|_| VaultError::FileError("vault I/O lock was poisoned".into()))?;

    while !buffer.is_empty() {
        match read_at(file, buffer, offset) {
            Ok(0) => return Err(VaultError::corrupt("vault is truncated")),
            Ok(read) => {
                offset = offset
                    .checked_add(read as u64)
                    .ok_or_else(|| VaultError::corrupt("read offset overflow"))?;
                buffer = &mut buffer[read..];
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(VaultError::from_io("failed to read the vault", error)),
        }
    }
    Ok(())
}

/// Given a buffer and an offset, write all bytes from the buffer starting at the offset.
/// `write_at` can write fewer bytes than requested. This isn't a bug. So, repeatedly call it,
/// advancing the offset by however many bytes were written, until the entire buffer has
/// been written.
///
/// This uses the same protections against concurrent cursor changes as [`read_exact_at`].
pub(crate) fn write_all_at(
    file: &File,
    mut buffer: &[u8],
    mut offset: u64,
) -> Result<(), VaultError> {
    #[cfg(not(any(unix, windows)))]
    let _guard = POSITIONED_IO_LOCK
        .lock()
        .map_err(|_| VaultError::FileError("vault I/O lock was poisoned".into()))?;

    while !buffer.is_empty() {
        match write_at(file, buffer, offset) {
            Ok(0) => {
                return Err(VaultError::from_io(
                    "failed to write the vault",
                    std::io::Error::from(ErrorKind::WriteZero),
                ));
            }
            Ok(written) => {
                offset = offset
                    .checked_add(written as u64)
                    .ok_or_else(|| VaultError::corrupt("write offset overflow"))?;
                buffer = &buffer[written..];
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(VaultError::from_io("failed to write the vault", error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

#[cfg(unix)]
fn write_at(file: &File, buffer: &[u8], offset: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::write_at(file, buffer, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

#[cfg(windows)]
fn write_at(file: &File, buffer: &[u8], offset: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_write(file, buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_at(mut file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset))?;
    file.read(buffer)
}

#[cfg(not(any(unix, windows)))]
fn write_at(mut file: &File, buffer: &[u8], offset: u64) -> std::io::Result<usize> {
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(offset))?;
    file.write(buffer)
}
