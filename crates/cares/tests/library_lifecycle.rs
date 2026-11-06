//! Real initialization references overlap across owner threads and are reusable.

use std::{error::Error, io, thread};

use cares::LibraryGuard;

#[test]
fn integration_lifecycle_overlapping_library_guards() -> Result<(), Box<dyn Error>> {
    let workers: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(|| {
                for _ in 0..256 {
                    let first = LibraryGuard::acquire()?;
                    let second = LibraryGuard::acquire()?;
                    thread::yield_now();
                    drop(first);
                    drop(second);
                }
                Ok::<_, cares::AresError>(())
            })
        })
        .collect();
    for worker in workers {
        worker
            .join()
            .map_err(|_| io::Error::other("library owner panicked"))??;
    }
    drop(LibraryGuard::acquire()?);
    Ok(())
}
