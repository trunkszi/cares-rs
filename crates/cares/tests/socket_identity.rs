//! Real descriptor reuse must not hide the replacement socket from lifetime accounting.

#[path = "support/socket_census.rs"]
mod socket_census;

use std::{
    io,
    os::{fd::AsRawFd, unix::net::UnixDatagram},
};

#[test]
fn socket_inode_survives_fd_reuse() -> io::Result<()> {
    let first = UnixDatagram::unbound()?;
    let descriptor = first.as_raw_fd();
    let before = socket_census::socket_identities()?;
    drop(first);
    let replacement = UnixDatagram::unbound()?;
    assert_eq!(
        replacement.as_raw_fd(),
        descriptor,
        "controlled socket slot must be reused"
    );
    let after = socket_census::socket_identities()?;
    assert_eq!(
        before.difference(&after).count(),
        1,
        "retired socket must disappear"
    );
    assert_eq!(
        after.difference(&before).count(),
        1,
        "replacement socket must have a fresh identity"
    );
    drop(replacement);
    assert_eq!(socket_census::socket_identities()?.len() + 1, after.len());
    Ok(())
}
