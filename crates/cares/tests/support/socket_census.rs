//! Socket inode snapshots distinguish lifetimes even when descriptor numbers are reused.

use std::{collections::BTreeSet, fs, io, path::PathBuf};

pub(super) fn socket_identities() -> io::Result<BTreeSet<PathBuf>> {
    let mut identities = BTreeSet::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if target.to_string_lossy().starts_with("socket:[") {
            identities.insert(target);
        }
    }
    Ok(identities)
}
