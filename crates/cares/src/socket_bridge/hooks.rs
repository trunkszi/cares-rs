//! Raw socket callback implementations and their pointer validation.

use uarch::prelude::*;

use super::*;

/// Reports a socket readiness change to the bridge registered as `data`.
/// # Safety
/// `data` must be null or the pointer returned by
/// [`SharedChannelState::sock_state_binding`] for a state that is still alive.
#[inline]
pub unsafe extern "C" fn socket_state_callback(
    data: *mut c_void,
    socket_fd: ares_socket_t,
    readable: c_int,
    writable: c_int,
) {
    // SAFETY: this callback's contract requires `data` to be null or a live state pointer obtained
    // from `sock_state_binding`.
    let Some(state) = (unsafe { state_from_user_data(data) }) else {
        return;
    };
    state.on_socket_state(socket_fd, readable != 0, writable != 0);
}
/// Recovers the bridge from a hook's `user_data` pointer.
/// # Safety
/// `user_data` must be null or a pointer returned by [`SharedChannelState::install`]
/// or [`SharedChannelState::sock_state_binding`] for a live state.
#[hot_inline]
unsafe fn state_from_user_data<'a>(user_data: *mut c_void) -> Option<&'a SharedChannelState> {
    if unlikely(user_data.is_null()) {
        cold_path();
        return None;
    }
    // SAFETY: the caller guarantees that the non-null pointer refers to a live state that outlives
    // `'a`.
    Some(unsafe { &*user_data.cast::<SharedChannelState>() })
}
/// Copies a C `sockaddr` into aligned storage and returns it with its length.
/// # Safety
/// `address` must be valid for `len` readable bytes, and `len` must not exceed
/// `size_of::<sockaddr_storage>()`.
unsafe fn copy_sockaddr(
    address: *const sockaddr,
    len: usize,
) -> (sockaddr_storage, ares_socklen_t) {
    let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
    // SAFETY: the source is readable for `len` bytes and the destination has room for at least
    // `len` bytes, as required by this function's contract.
    unsafe {
        ptr::copy_nonoverlapping(address.cast::<u8>(), storage.as_mut_ptr().cast::<u8>(), len);
    }
    // SAFETY: every byte of the storage is initialized, first by zeroing and then by the copy
    // above, and `sockaddr_storage` has no validity invariants.
    (unsafe { storage.assume_init() }, len as ares_socklen_t)
}
#[cold_sink]
fn set_errno(value: c_int) {
    // SAFETY: `__errno_location` returns the address of the calling thread's errno, which is always
    // valid for the current thread.
    unsafe { *libc::__errno_location() = value };
}
#[cold_sink]
fn set_errno_from_io(error: &io::Error) {
    set_errno(error.raw_os_error().unwrap_or(libc::EIO));
}
#[inline]
pub(super) fn cvt(result: c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(last_io_error())
    }
}
#[hot_inline]
pub(super) fn read_int(value: &[u8]) -> Option<c_int> {
    let bytes = value.get(..size_of::<c_int>())?;
    let bytes = <[u8; size_of::<c_int>()]>::try_from(bytes).ok()?;
    Some(c_int::from_ne_bytes(bytes))
}
#[inline]
pub(super) unsafe extern "C" fn asocket(
    domain: c_int,
    socket_type: c_int,
    protocol: c_int,
    user_data: *mut c_void,
) -> ares_socket_t {
    // SAFETY: c-ares passes the pointer registered by `install`, which refers to a live bridge for
    // the duration of the channel.
    let Some(state) = (unsafe { state_from_user_data(user_data) }) else {
        set_errno(libc::EINVAL);
        return cares_sys::ARES_SOCKET_BAD;
    };
    match state.open_socket(domain, socket_type, protocol) {
        Ok(fd) => fd,
        Err(error) => {
            set_errno_from_io(&error);
            cares_sys::ARES_SOCKET_BAD
        }
    }
}
#[inline]
pub(super) unsafe extern "C" fn aclose(sock: ares_socket_t, user_data: *mut c_void) -> c_int {
    // SAFETY: c-ares passes the pointer registered by `install`, which refers to a live bridge for
    // the duration of the channel.
    let Some(state) = (unsafe { state_from_user_data(user_data) }) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match state.close_socket(sock) {
        Ok(()) => 0,
        Err(error) => {
            set_errno_from_io(&error);
            -1
        }
    }
}
#[inline]
pub(super) unsafe extern "C" fn asetsockopt(
    sock: ares_socket_t,
    opt: ares_socket_opt_t,
    val: *const c_void,
    val_size: ares_socklen_t,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: c-ares passes the pointer registered by `install`, which refers to a live bridge for
    // the duration of the channel.
    let Some(state) = (unsafe { state_from_user_data(user_data) }) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let value: &[u8] = if val.is_null() {
        if val_size != 0 {
            set_errno(libc::EINVAL);
            return -1;
        }
        &[]
    } else {
        // SAFETY: c-ares supplies a readable buffer of `val_size` bytes.
        unsafe { core::slice::from_raw_parts(val.cast::<u8>(), val_size as usize) }
    };
    match state.apply_socket_option(sock, opt, value) {
        Ok(()) => 0,
        Err(error) => {
            set_errno_from_io(&error);
            -1
        }
    }
}
#[inline]
pub(super) unsafe extern "C" fn aconnect(
    sock: ares_socket_t,
    address: *const sockaddr,
    address_len: ares_socklen_t,
    _flags: c_uint,
    user_data: *mut c_void,
) -> c_int {
    // SAFETY: c-ares passes the pointer registered by `install`, which refers to a live bridge for
    // the duration of the channel.
    let Some(state) = (unsafe { state_from_user_data(user_data) }) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let socket_type = match state.sockets.borrow().get(&sock) {
        Some(entry) => entry.socket_type,
        None => {
            set_errno(libc::EBADF);
            return -1;
        }
    };
    if address.is_null() {
        set_errno(libc::EFAULT);
        return -1;
    }
    if address_len as usize > size_of::<sockaddr_storage>() {
        set_errno(libc::EINVAL);
        return -1;
    }
    // SAFETY: `sock` is live and c-ares supplies a sockaddr valid for `address_len` bytes.
    let result = unsafe { libc::connect(sock, address, address_len) };
    if result != 0 {
        return -1;
    }
    if socket_type == libc::SOCK_DGRAM {
        // SAFETY: the pointer and length were validated above.
        let peer = unsafe { copy_sockaddr(address, address_len as usize) };
        if let Some(entry) = state.sockets.borrow_mut().get_mut(&sock) {
            entry.peer = Some(peer);
        }
    }
    0
}
#[inline]
pub(super) unsafe extern "C" fn arecvfrom(
    sock: ares_socket_t,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
    address: *mut sockaddr,
    address_len: *mut ares_socklen_t,
    _user_data: *mut c_void,
) -> ares_ssize_t {
    if address.is_null() != address_len.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    // SAFETY: c-ares supplies a writable buffer of `length` bytes and, when non-null, a writable
    // source address of the size pointed to by `address_len`; `sock` was created by `asocket`.
    unsafe { libc::recvfrom(sock, buffer, length, flags, address, address_len) }
}
#[inline]
pub(super) unsafe extern "C" fn asendto(
    sock: ares_socket_t,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
    address: *const sockaddr,
    address_len: ares_socklen_t,
    user_data: *mut c_void,
) -> ares_ssize_t {
    // SAFETY: c-ares passes the pointer registered by `install`, which refers to a live bridge for
    // the duration of the channel.
    let state = unsafe { state_from_user_data(user_data) };
    let cached = if address.is_null() {
        state.and_then(|state| state.cached_peer(sock))
    } else {
        None
    };
    let (destination, destination_len) = match cached.as_ref() {
        Some((storage, len)) => (ptr::from_ref(storage).cast::<sockaddr>(), *len),
        None => (address, address_len),
    };
    // SAFETY: c-ares supplies a readable buffer of `length` bytes; the destination is either its
    // own valid address or a cached copy owned by the bridge that lives until this call returns.
    // MSG_NOSIGNAL keeps a closed peer from raising SIGPIPE.
    unsafe {
        libc::sendto(
            sock,
            buffer,
            length,
            flags | libc::MSG_NOSIGNAL,
            destination,
            destination_len,
        )
    }
}
#[inline]
pub(super) unsafe extern "C" fn agetsockname(
    sock: ares_socket_t,
    address: *mut sockaddr,
    address_len: *mut ares_socklen_t,
    _user_data: *mut c_void,
) -> c_int {
    // SAFETY: c-ares supplies a writable address buffer and its length; `sock` was created by
    // `asocket`.
    unsafe { libc::getsockname(sock, address, address_len) }
}
#[inline]
pub(super) unsafe extern "C" fn abind(
    sock: ares_socket_t,
    _flags: c_uint,
    address: *const sockaddr,
    address_len: socklen_t,
    _user_data: *mut c_void,
) -> c_int {
    // SAFETY: c-ares supplies an address valid for `address_len` bytes; `sock` was created by
    // `asocket`.
    unsafe { libc::bind(sock, address, address_len) }
}
#[inline]
pub(super) unsafe extern "C" fn aif_nametoindex(
    ifname: *const c_char,
    _user_data: *mut c_void,
) -> c_uint {
    // SAFETY: c-ares supplies a NUL-terminated interface name.
    unsafe { libc::if_nametoindex(ifname) }
}
#[inline]
pub(super) unsafe extern "C" fn aif_indextoname(
    ifindex: c_uint,
    ifname_buf: *mut c_char,
    ifname_buf_len: usize,
    _user_data: *mut c_void,
) -> *const c_char {
    if ifname_buf.is_null() || ifname_buf_len < libc::IF_NAMESIZE {
        set_errno(libc::ENOSPC);
        return ptr::null();
    }
    // SAFETY: the buffer is writable for at least IF_NAMESIZE bytes, which is all the C function
    // writes.
    unsafe { libc::if_indextoname(ifindex, ifname_buf).cast_const() }
}

#[cold_sink]
fn last_io_error() -> io::Error {
    io::Error::last_os_error()
}
