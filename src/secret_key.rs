use memmap2::MmapMut;
use region::LockGuard;
use zeroize::Zeroize;

use crate::errors::VaultError;

pub(crate) const KEY_LEN: usize = 32;

/// Stores a 32-byte key in its own anonymous memory mapping. That asks the OS
/// for a separate memory region without a file behind it.
///
/// We lock this memory before writing key bytes, so the OS cannot move this
/// mapping into ordinary swap space. On Linux, we also require it to be excluded
/// from ordinary core dumps. If either protection fails, creation returns an
/// error; there is no fallback to unlocked memory.
///
/// Each key uses at least one OS page, even though the key itself is small.
/// Suppose two keys shared a page: `[ Key A | Key B | ... ]`. The OS locks whole
/// pages, and we cannot rely on locking twice requiring two unlocks. Dropping
/// Key A could therefore unlock Key B's memory too. Separate mappings avoid that.
///
/// Rust runs our Drop implementation before dropping the fields, then drops
/// fields in declaration order. We erase the key first, `_lock` unlocks the
/// page next, and `mapping` finally releases the memory. Keep that order.
///
/// These protections cover this mapping, not every temporary key value created
/// by the compiler or cryptographic libraries. They also do not cover hibernation
/// or provide a core-dump guarantee outside Linux. See SECURITY.md for the limits.
///
/// Platform lock behavior:
/// - Linux: <https://man7.org/linux/man-pages/man2/mlock.2.html>
/// - Windows: <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock>
/// - macOS/iOS: <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mlock.2.html>
pub(crate) struct SecretKey {
    _lock: LockGuard,
    mapping: MmapMut,
}

impl SecretKey {
    pub(crate) fn zeroed() -> Result<Self, VaultError> {
        let mapping = MmapMut::map_anon(KEY_LEN).map_err(|error| {
            VaultError::SecretKeyProtection(format!(
                "cannot allocate protected secret key memory: {error}"
            ))
        })?;
        let lock = region::lock(mapping.as_ptr(), mapping.len()).map_err(|error| {
            VaultError::SecretKeyProtection(format!(
                "cannot lock secret key memory against swapping: {error}"
            ))
        })?;
        #[cfg(target_os = "linux")]
        mapping.advise(memmap2::Advice::DontDump).map_err(|error| {
            VaultError::SecretKeyProtection(format!(
                "cannot exclude secret key memory from core dumps: {error}"
            ))
        })?;
        Ok(Self {
            _lock: lock,
            mapping,
        })
    }

    pub(crate) fn expose_secret(&self) -> &[u8; KEY_LEN] {
        self.mapping[..]
            .try_into()
            .expect("key mappings have a fixed length")
    }

    pub(crate) fn expose_secret_mut(&mut self) -> &mut [u8; KEY_LEN] {
        (&mut self.mapping[..])
            .try_into()
            .expect("key mappings have a fixed length")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.mapping[..].zeroize();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn creating_and_opening_vaults_fail_when_key_memory_cannot_be_locked() {
    use std::{path::PathBuf, process::Command};

    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    use crate::{
        CreateOptions, Volume,
        kdf::KdfParams,
        test_support::{TEST_CIPHERS, TestPath, password},
    };

    const CHILD_ROOT: &str = "LUNACRYPT_TEST_ZERO_MEMLOCK_ROOT";
    let password = password(b"disposable quota test password");

    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        // This limit applies to the whole process, not just this test's thread.
        // Change it only in the child, so other tests can still lock their keys.
        setrlimit(
            Resource::Memlock,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .unwrap();
        let root = PathBuf::from(root);
        for (index, cipher) in TEST_CIPHERS.into_iter().enumerate() {
            let rejected = root.join(format!("rejected-{index}"));
            assert!(matches!(
                Volume::create_container_with_options(
                    &rejected,
                    &password,
                    128 * 1024,
                    4096,
                    CreateOptions {
                        cipher,
                        ..CreateOptions::default()
                    },
                ),
                Err(VaultError::SecretKeyProtection(_))
            ));
            assert!(!rejected.exists());

            let existing = root.join(format!("existing-{index}"));
            for result in [
                Volume::open_container(&existing, &password),
                Volume::open_container_read_only(&existing, &password),
            ] {
                assert!(matches!(result, Err(VaultError::SecretKeyProtection(_))));
            }
        }
        std::fs::write(root.join("child-completed"), []).unwrap();
        return;
    }

    let fixture = TestPath::directory("zero-memlock");
    let mut original_bytes = Vec::new();
    for (index, cipher) in TEST_CIPHERS.into_iter().enumerate() {
        let path = fixture.path.join(format!("existing-{index}"));
        let mut vault = Volume::create_container_with_kdf_and_options(
            &path,
            &password,
            128 * 1024,
            4096,
            CreateOptions {
                cipher,
                ..CreateOptions::default()
            },
            KdfParams::for_tests(),
        )
        .unwrap();
        vault.add_file("fixture", b"authenticated data").unwrap();
        drop(vault);
        original_bytes.push(std::fs::read(path).unwrap());
    }

    let before = getrlimit(Resource::Memlock);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "secret_key::creating_and_opening_vaults_fail_when_key_memory_cannot_be_locked",
            "--test-threads=1",
        ])
        .env(CHILD_ROOT, &fixture.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "quota child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The child writes this marker only after its checks finish. Without it,
    // a typo in the test name could run zero tests and still report success.
    std::fs::remove_file(fixture.path.join("child-completed")).unwrap();
    assert_eq!(getrlimit(Resource::Memlock), before);
    // Only the two original vaults should remain. Their bytes must be unchanged,
    // and opening them again checks that they are still usable.
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 2);
    for (index, bytes) in original_bytes.iter().enumerate() {
        let path = fixture.path.join(format!("existing-{index}"));
        assert_eq!(&std::fs::read(&path).unwrap(), bytes);
        Volume::open_container(&path, &password)
            .unwrap()
            .verify()
            .unwrap();
    }
}

#[test]
fn new_keys_start_with_all_bytes_zero() {
    let key = SecretKey::zeroed().unwrap();
    assert_eq!(key.expose_secret(), &[0; KEY_LEN]);
}

/// Dropping one key must not remove another key's protections. Check the OS's
/// description of the second key's memory after the first key is gone.
#[cfg(target_os = "linux")]
#[test]
fn dropping_one_key_keeps_the_other_locked_and_excluded_from_core_dumps() {
    let first = SecretKey::zeroed().unwrap();
    let second = SecretKey::zeroed().unwrap();
    drop(first);
    let address = second.expose_secret().as_ptr() as usize;
    let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();

    let mut contains_key = false;
    for line in maps.lines() {
        // Each memory region starts with an address range, such as
        // 7f514222e000-7f514222f000. Other lines describe that region.
        // Convert the addresses to numbers: the ending address is outside this
        // region, so searching for the key address as text could pick the
        // wrong one. Once we find its range, check that region's VmFlags line.

        let first_word = line.split_whitespace().next().unwrap();

        if let Some((start, end)) = first_word.split_once('-') {
            let start = usize::from_str_radix(start, 16).unwrap();
            let end = usize::from_str_radix(end, 16).unwrap();
            contains_key = (start..end).contains(&address);
        }

        if contains_key && line.starts_with("VmFlags:") {
            let flags: Vec<_> = line.split_whitespace().collect();
            assert!(flags.contains(&"lo"), "key mapping was not locked");
            assert!(flags.contains(&"dd"), "key mapping allowed core dumps");
            return;
        }
    }

    panic!("key mapping was absent from /proc/self/smaps");
}
