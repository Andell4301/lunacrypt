use std::io::Write;

use super::TestPath;
use crate::volume::path_io::PendingFile;

#[test]
fn saving_a_temporary_file_does_not_replace_a_destination_created_in_the_meantime() {
    let directory = TestPath::directory("pending-no-clobber");
    let target = directory.path.join("target");
    let (pending, mut file) = PendingFile::create(&target).unwrap();
    file.write_all(b"new data").unwrap();
    file.sync_all().unwrap();
    std::fs::write(&target, b"keep me").unwrap();
    assert!(pending.publish().is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    assert_eq!(std::fs::read_dir(&directory.path).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn saving_and_cleanup_use_the_original_directory_even_after_it_is_renamed() {
    let directory = TestPath::directory("pending-parent-swap");
    let original = directory.path.join("original");
    let renamed = directory.path.join("renamed");
    std::fs::create_dir(&original).unwrap();
    let (pending, mut file) = PendingFile::create(&original.join("published")).unwrap();
    let (abandoned, other_file) = PendingFile::create(&original.join("abandoned")).unwrap();
    file.write_all(b"authenticated data").unwrap();
    file.sync_all().unwrap();
    std::fs::rename(&original, &renamed).unwrap();
    std::fs::create_dir(&original).unwrap();
    pending.publish().unwrap();
    drop(other_file);
    drop(abandoned);
    assert_eq!(
        std::fs::read(renamed.join("published")).unwrap(),
        b"authenticated data"
    );
    assert_eq!(std::fs::read_dir(&renamed).unwrap().count(), 1);
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
}
