//! Native allocator failure must reach the public completion driver.

use std::{
    cell::Cell,
    error::Error,
    net::UdpSocket,
    process::Command,
    rc::Rc,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use cares::{AresError, AresStatus, DnsRecordType, Resolver, ResolverOptions};

static FAIL: AtomicBool = AtomicBool::new(false);
static REJECTED: AtomicUsize = AtomicUsize::new(0);
static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static FAIL_AT: AtomicUsize = AtomicUsize::new(0);

fn reject_allocation() -> bool {
    let attempt = ATTEMPTS.fetch_add(1, Ordering::Relaxed) + 1;
    FAIL.load(Ordering::Relaxed) || attempt == FAIL_AT.load(Ordering::Relaxed)
}

unsafe extern "C" fn allocate(size: usize) -> *mut libc::c_void {
    if reject_allocation() {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        std::ptr::null_mut()
    } else {
        // SAFETY: This forwards the C allocator's requested byte count unchanged.
        unsafe { libc::malloc(size) }
    }
}

unsafe extern "C" fn resize(pointer: *mut libc::c_void, size: usize) -> *mut libc::c_void {
    if size != 0 && reject_allocation() {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        std::ptr::null_mut()
    } else {
        // SAFETY: c-ares owns this pointer from the matching malloc-compatible callback.
        unsafe { libc::realloc(pointer, size) }
    }
}

unsafe extern "C" fn release(pointer: *mut libc::c_void) {
    // SAFETY: c-ares releases each pointer from the malloc-compatible callbacks once.
    unsafe { libc::free(pointer) };
}

#[test]
fn native_allocation_error_reaches_driver() -> Result<(), Box<dyn Error>> {
    if std::env::var_os("CARES_NATIVE_ALLOC_CHILD").is_none() {
        let result = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "native_allocation_error_reaches_driver",
                "--nocapture",
            ])
            .env("CARES_NATIVE_ALLOC_CHILD", "1")
            .status()?;
        assert!(
            result.success(),
            "isolated native allocation scenario failed"
        );
        return Ok(());
    }
    // SAFETY: This isolated process has no initialized c-ares users; callbacks never unwind.
    let initialized =
        unsafe { cares_sys::ares_library_init_mem(0, Some(allocate), Some(release), Some(resize)) };
    assert_eq!(initialized, 0);
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut resolver = Resolver::new(ResolverOptions::default())?;
    resolver.set_servers_csv(&server.local_addr()?.to_string())?;
    resolver.submit_query("oom.example.", DnsRecordType::A, |_, _| {})?;
    let mut packet = [0u8; 512];
    let (length, peer) = server.recv_from(&mut packet)?;
    let mut end = 12;
    loop {
        let label = *packet.get(end).ok_or("missing label")? as usize;
        end += 1;
        if label == 0 {
            break;
        }
        end += label;
    }
    end += 4;
    assert!(end <= length);
    let mut response = packet[..end].to_vec();
    response[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1]);
    server.send_to(&response, peer)?;
    FAIL.store(true, Ordering::Relaxed);
    let result = resolver.wait_completions(Duration::from_secs(1));
    FAIL.store(false, Ordering::Relaxed);
    assert!(REJECTED.load(Ordering::Relaxed) > 0);
    assert_eq!(
        result.err().and_then(|error| error.status()),
        Some(AresStatus::OutOfMemory)
    );
    assert!(!resolver.is_poisoned());
    resolver.cancel()?;
    assert_eq!(resolver.active_queries(), 0);
    drop(resolver);
    // SAFETY: Resolver destruction balanced its own reference; this releases the isolated setup.
    unsafe { cares_sys::ares_library_cleanup() };
    Ok(())
}

fn response_failure(
    offset: usize,
    panicking: bool,
) -> Result<(Option<AresError>, bool, bool), Box<dyn Error>> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut resolver = Resolver::new(
        ResolverOptions::builder()
            .tries(1)
            .query_cache_ttl(Duration::ZERO)
            .build()?,
    )?;
    resolver.set_servers_csv(&server.local_addr()?.to_string())?;
    let called = Rc::new(Cell::new(false));
    let callback_called = Rc::clone(&called);
    resolver.submit_query("priority.example.", DnsRecordType::A, move |_, _| {
        callback_called.set(true);
        assert!(!panicking, "completion callback failed");
    })?;
    let mut packet = [0u8; 512];
    let (length, peer) = server.recv_from(&mut packet)?;
    let mut end = 12;
    loop {
        let label = *packet.get(end).ok_or("missing label")? as usize;
        end += 1;
        if label == 0 {
            break;
        }
        end += label;
    }
    end += 4;
    assert!(end <= length);
    let mut response = packet[..end].to_vec();
    response[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1]);
    server.send_to(&response, peer)?;
    let rejected = REJECTED.load(Ordering::Relaxed);
    FAIL_AT.store(ATTEMPTS.load(Ordering::Relaxed) + offset, Ordering::Relaxed);
    let result = resolver.wait_completions(Duration::from_secs(1));
    FAIL_AT.store(0, Ordering::Relaxed);
    let observed = (
        result.err(),
        called.get(),
        REJECTED.load(Ordering::Relaxed) > rejected,
    );
    drop(resolver);
    Ok(observed)
}

#[test]
fn callback_panic_precedes_native_error() -> Result<(), Box<dyn Error>> {
    if std::env::var_os("CARES_PANIC_NATIVE_CHILD").is_none() {
        let result = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "callback_panic_precedes_native_error",
                "--nocapture",
            ])
            .env("CARES_PANIC_NATIVE_CHILD", "1")
            .status()?;
        assert!(
            result.success(),
            "isolated callback priority scenario failed"
        );
        return Ok(());
    }
    // SAFETY: The isolated process has no c-ares users; the allocator callbacks never unwind.
    let initialized =
        unsafe { cares_sys::ares_library_init_mem(0, Some(allocate), Some(release), Some(resize)) };
    assert_eq!(initialized, 0);
    let mut verified = false;
    // Allocation ordinals vary by c-ares build; a control proves the same failure reaches C.
    for offset in 1..=64 {
        let (error, called, rejected) = response_failure(offset, false)?;
        if rejected
            && called
            && error.as_ref().and_then(AresError::status) == Some(AresStatus::OutOfMemory)
        {
            let (error, called, rejected) = response_failure(offset, true)?;
            assert!(called && rejected);
            assert_eq!(error, Some(AresError::CallbackPanicked));
            verified = true;
            break;
        }
    }
    assert!(
        verified,
        "no native ENOMEM with callback delivery was exercised"
    );
    // SAFETY: Each scenario dropped its resolver, leaving only the isolated setup reference.
    unsafe { cares_sys::ares_library_cleanup() };
    Ok(())
}
