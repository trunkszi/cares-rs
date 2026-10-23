//! File-descriptor inspection requires exclusive execution within this suite.

use std::{
    fs::{File, OpenOptions},
    io,
    os::fd::AsRawFd,
};

pub(super) fn serial_guard() -> io::Result<File> {
    let path = std::env::temp_dir().join(format!("cares-descriptors-{}.lock", std::process::id()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    loop {
        // SAFETY: the file descriptor is live and independently opened for each
        // caller. Closing the returned file releases its exclusive advisory lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
