//! Integration tests for `socket_bridge` and `timer`.

use std::{
    cell::RefCell,
    io,
    rc::Rc,
    time::{Duration, Instant},
};

use cares::{
    socket_bridge::{ReadinessSink, SOCKET_FUNCTIONS, SharedChannelState, SocketInterest},
    timer::{TimerDeadline, TimerState},
};
use cares_sys::{ares_channel_t, ares_fd_events_t, ares_socket_t};

#[derive(Default)]
struct RecordingSink {
    updates: RefCell<Vec<(ares_socket_t, SocketInterest)>>,
    removals: RefCell<Vec<ares_socket_t>>,
}

impl ReadinessSink for RecordingSink {
    fn update_interest(&self, fd: ares_socket_t, interest: SocketInterest) {
        self.updates.borrow_mut().push((fd, interest));
    }
    fn remove_interest(&self, fd: ares_socket_t) {
        self.removals.borrow_mut().push(fd);
    }
}

fn new_state() -> Box<SharedChannelState> {
    Box::new(SharedChannelState::new())
}

fn state_with_sink() -> (Box<SharedChannelState>, Rc<RecordingSink>) {
    let state = new_state();
    let sink = Rc::new(RecordingSink::default());
    state.set_readiness_sink(sink.clone());
    (state, sink)
}

fn open_datagram(state: &SharedChannelState) -> ares_socket_t {
    match state.open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
        Ok(fd) => fd,
        Err(error) => panic!("open_socket(AF_INET, SOCK_DGRAM) failed: {error}"),
    }
}

fn open_stream(state: &SharedChannelState) -> ares_socket_t {
    match state.open_socket(libc::AF_INET, libc::SOCK_STREAM, 0) {
        Ok(fd) => fd,
        Err(error) => panic!("open_socket(AF_INET, SOCK_STREAM) failed: {error}"),
    }
}

fn close_ok(state: &SharedChannelState, fd: ares_socket_t) {
    assert!(state.close_socket(fd).is_ok(), "close_socket({fd}) failed");
}

fn get_status_flags(fd: ares_socket_t) -> libc::c_int {
    // SAFETY: F_GETFL only reads descriptor flags and does not transfer
    // ownership; fd was returned by the bridge and is still open here.
    unsafe { libc::fcntl(fd, libc::F_GETFL) }
}

fn get_descriptor_flags(fd: ares_socket_t) -> libc::c_int {
    // SAFETY: F_GETFD only reads descriptor flags and does not transfer
    // ownership; fd was returned by the bridge and is still open here.
    unsafe { libc::fcntl(fd, libc::F_GETFD) }
}

fn io_error(result: io::Result<()>) -> io::Error {
    match result {
        Ok(()) => panic!("the operation returned Ok"),
        Err(error) => error,
    }
}

fn armed(timer: &TimerState, at: Instant) -> TimerDeadline {
    match timer.refresh_from_deadline(Some(at)) {
        Some(deadline) => deadline,
        None => panic!("refresh_from_deadline(Some({at:?})) returned None"),
    }
}

#[test]
fn open_socket_is_nonblocking_cloexec_and_visible_in_table() {
    let (state, sink) = state_with_sink();
    assert_eq!(state.socket_count(), 0);
    let datagram = open_datagram(&state);
    assert!(datagram >= 0);
    assert_eq!(state.socket_count(), 1);
    assert_ne!(get_status_flags(datagram) & libc::O_NONBLOCK, 0);
    assert_ne!(get_descriptor_flags(datagram) & libc::FD_CLOEXEC, 0);
    let stream = open_stream(&state);
    assert!(stream >= 0);
    assert_eq!(state.socket_count(), 2);
    assert_ne!(get_status_flags(stream) & libc::O_NONBLOCK, 0);
    assert_ne!(get_descriptor_flags(stream) & libc::FD_CLOEXEC, 0);
    close_ok(&state, datagram);
    assert_eq!(state.socket_count(), 1);
    close_ok(&state, stream);
    assert_eq!(state.socket_count(), 0);
    let removals = sink.removals.borrow();
    assert_eq!(removals.len(), 2);
    assert_eq!(removals[0], datagram);
    assert_eq!(removals[1], stream);
}

#[test]
fn close_socket_notifies_sink_and_rejects_unknown_fd() {
    let (state, sink) = state_with_sink();
    let fd = open_datagram(&state);
    assert!(sink.removals.borrow().is_empty());
    assert!(sink.updates.borrow().is_empty());
    close_ok(&state, fd);
    let removals = sink.removals.borrow();
    assert_eq!(removals.len(), 1);
    assert_eq!(removals[0], fd);
    let unknown = fd.wrapping_add(1000);
    let error = io_error(state.close_socket(unknown));
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    assert_eq!(state.socket_count(), 0);
}

#[test]
fn bind_to_device_reaches_the_kernel_without_ensys() {
    let state = new_state();
    let fd = open_datagram(&state);
    match state.bind_to_device(fd, "lo") {
        Ok(()) => {}
        Err(error) => assert_eq!(
            error.raw_os_error(),
            Some(libc::EPERM),
            "SO_BINDTODEVICE must fail only with EPERM when unprivileged"
        ),
    }
    let nul_error = io_error(state.bind_to_device(fd, "lo\0eth0"));
    assert_eq!(nul_error.raw_os_error(), Some(libc::EINVAL));
    close_ok(&state, fd);
}

#[test]
fn arecvfrom_preserves_would_block_errno() {
    let state = new_state();
    let user_data = hook_user_data(&state);
    let arecvfrom = match SOCKET_FUNCTIONS.arecvfrom {
        Some(hook) => hook,
        None => panic!("the vtable has no arecvfrom hook"),
    };
    let fd = open_datagram(&state);
    let mut buffer = [0u8; 64];
    // SAFETY: the buffer is writable for its length, the address pair is null
    // (the shape c-ares uses on the TCP path), and fd/user_data belong to this
    // state.
    let result = unsafe {
        arecvfrom(
            fd,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            user_data,
        )
    };
    assert_eq!(result, -1);
    let errno = io::Error::last_os_error().raw_os_error();
    assert!(
        errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK),
        "arecvfrom did not preserve EAGAIN/EWOULDBLOCK: {errno:?}"
    );
    close_ok(&state, fd);
}

#[test]
fn deferred_interest_queues_inside_process_scope() {
    let (state, sink) = state_with_sink();
    let fd = open_datagram(&state);
    let inside = state.with_process_scope(|| {
        state.on_socket_state(fd, true, false);
        state.on_socket_state(fd, false, true);
        (sink.updates.borrow().len(), state.pending_interest_count())
    });
    assert_eq!(inside.0, 0, "sink must not see updates inside the scope");
    assert_eq!(inside.1, 2, "both updates must be deferred");
    assert_eq!(state.pending_interest_count(), 0);
    let updates = sink.updates.borrow();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].0, fd);
    assert!(updates[0].1.readable && !updates[0].1.writable);
    assert_eq!(updates[1].0, fd);
    assert!(!updates[1].1.readable && updates[1].1.writable);
    close_ok(&state, fd);
}

#[test]
fn stale_deferred_update_is_dropped_when_fd_closes() {
    let (state, sink) = state_with_sink();
    let fd = open_datagram(&state);
    state.with_process_scope(|| {
        state.on_socket_state(fd, true, true);
        close_ok(&state, fd);
    });
    assert!(
        sink.updates.borrow().is_empty(),
        "an update for a closed generation must never reach the sink"
    );
    let removals = sink.removals.borrow();
    assert_eq!(removals.len(), 1);
    assert_eq!(removals[0], fd);
    assert_eq!(state.pending_interest_count(), 0);
    assert_eq!(state.socket_count(), 0);
}

#[test]
fn immediate_interest_outside_scope_reaches_sink() {
    let (state, sink) = state_with_sink();
    let fd = open_datagram(&state);
    state.on_socket_state(fd, false, true);
    let updates = sink.updates.borrow();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].0, fd);
    assert!(!updates[0].1.readable && updates[0].1.writable);
    assert_eq!(state.pending_interest_count(), 0);
    close_ok(&state, fd);
}

#[test]
fn on_socket_state_ignores_unknown_and_bad_fds() {
    let (state, sink) = state_with_sink();
    state.on_socket_state(-1, true, true);
    state.on_socket_state(987_654, true, true);
    assert!(sink.updates.borrow().is_empty());
    assert_eq!(state.pending_interest_count(), 0);
}

#[test]
fn on_ready_coalesces_flags_and_drain_ready_appends() {
    let state = new_state();
    let fd = open_datagram(&state);
    assert!(!state.has_pending());
    state.on_ready(fd, true, false);
    state.on_ready(fd, false, true);
    state.on_ready(fd, true, false);
    assert!(state.has_pending());
    let mut events: Vec<ares_fd_events_t> = Vec::new();
    let drained = state.drain_ready(&mut events);
    assert_eq!(drained, 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fd, fd);
    assert_eq!(
        events[0].events,
        cares_sys::ARES_FD_EVENT_READ.0 | cares_sys::ARES_FD_EVENT_WRITE.0
    );
    assert!(!state.has_pending());
    let mut prefilled = vec![ares_fd_events_t {
        fd: 40_000,
        events: 0,
    }];
    assert_eq!(state.drain_ready(&mut prefilled), 0);
    assert_eq!(prefilled.len(), 1, "drain must not clear the caller's vec");
    state.on_ready(fd, false, true);
    let appended = state.drain_ready(&mut prefilled);
    assert_eq!(appended, 1);
    assert_eq!(prefilled.len(), 2);
    assert_eq!(prefilled[0].fd, 40_000);
    assert_eq!(prefilled[1].fd, fd);
    assert_eq!(prefilled[1].events, cares_sys::ARES_FD_EVENT_WRITE.0);
    close_ok(&state, fd);
}

#[test]
fn shutdown_closes_sockets_and_is_idempotent() {
    let (state, sink) = state_with_sink();
    let first = open_datagram(&state);
    let _stream = open_stream(&state);
    state.on_ready(first, true, false);
    state.shutdown();
    assert_eq!(state.socket_count(), 0);
    assert!(!state.has_pending());
    assert_eq!(state.pending_interest_count(), 0);
    assert_eq!(sink.removals.borrow().len(), 2);
    let mut events: Vec<ares_fd_events_t> = Vec::new();
    assert_eq!(state.drain_ready(&mut events), 0);
    state.shutdown();
    assert_eq!(state.socket_count(), 0);
    assert_eq!(sink.removals.borrow().len(), 2);
}

fn hook_user_data(state: &SharedChannelState) -> *mut libc::c_void {
    let (_callback, user_data) = state.sock_state_binding();
    user_data
}

fn to_sockaddr_in(addr: std::net::SocketAddr) -> libc::sockaddr_in {
    match addr {
        std::net::SocketAddr::V4(v4) => libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            },
            sin_zero: [0; 8],
        },
        std::net::SocketAddr::V6(_) => panic!("expected an IPv4 loopback address"),
    }
}

#[test]
fn apply_socket_option_maps_buffers_and_rejects_fastopen_and_unknown() {
    let state = new_state();
    let fd = open_datagram(&state);
    let size: libc::c_int = 64 * 1024;
    let value = size.to_ne_bytes();
    assert!(
        state
            .apply_socket_option(fd, cares_sys::ARES_SOCKET_OPT_SENDBUF_SIZE, &value)
            .is_ok()
    );
    assert!(
        state
            .apply_socket_option(fd, cares_sys::ARES_SOCKET_OPT_RECVBUF_SIZE, &value)
            .is_ok()
    );
    match state.apply_socket_option(fd, cares_sys::ARES_SOCKET_OPT_BIND_DEVICE, b"lo") {
        Ok(()) => {}
        Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EPERM)),
    }
    let fastopen =
        io_error(state.apply_socket_option(fd, cares_sys::ARES_SOCKET_OPT_TCP_FASTOPEN, &[]));
    assert_eq!(fastopen.raw_os_error(), Some(libc::ENOSYS));
    let unknown = io_error(state.apply_socket_option(fd, cares_sys::ares_socket_opt_t(4), &value));
    assert_eq!(unknown.raw_os_error(), Some(libc::ENOSYS));
    let short =
        io_error(state.apply_socket_option(fd, cares_sys::ARES_SOCKET_OPT_SENDBUF_SIZE, &[0u8; 3]));
    assert_eq!(short.raw_os_error(), Some(libc::EINVAL));
    let empty_device =
        io_error(state.apply_socket_option(fd, cares_sys::ARES_SOCKET_OPT_BIND_DEVICE, b""));
    assert_eq!(empty_device.raw_os_error(), Some(libc::EINVAL));
    close_ok(&state, fd);
}

#[test]
fn udp_connect_caches_peer_and_recvfrom_reports_source() {
    let state = new_state();
    let user_data = hook_user_data(&state);
    let funcs = &SOCKET_FUNCTIONS;
    let (abind, agetsockname, aconnect, arecvfrom, asendto) = match (
        funcs.abind,
        funcs.agetsockname,
        funcs.aconnect,
        funcs.arecvfrom,
        funcs.asendto,
    ) {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
        _ => panic!("the vtable is missing a required socket hook"),
    };
    let peer = match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) => panic!("cannot bind the loopback peer: {error}"),
    };
    let peer_addr = match peer.local_addr() {
        Ok(addr) => addr,
        Err(error) => panic!("cannot read the peer address: {error}"),
    };
    assert!(
        peer.set_read_timeout(Some(Duration::from_secs(5))).is_ok(),
        "cannot bound the peer read timeout"
    );
    let fd = open_datagram(&state);
    let local = to_sockaddr_in(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let addr_len = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: local is a live sockaddr_in whose length matches, fd is
    // registered, and user_data is the state pointer.
    let bind_result = unsafe {
        abind(
            fd,
            0,
            (&local as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            addr_len,
            user_data,
        )
    };
    let bind_errno = io::Error::last_os_error().raw_os_error();
    assert_eq!(bind_result, 0, "abind failed with errno {bind_errno:?}");
    // SAFETY: sockaddr_in contains integer fields for which zero is valid.
    let mut actual: libc::sockaddr_in = unsafe { core::mem::zeroed() };
    let mut actual_len = addr_len;
    // SAFETY: actual and actual_len are live out-parameters of the right type.
    let name_result = unsafe {
        agetsockname(
            fd,
            (&mut actual as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
            &mut actual_len,
            user_data,
        )
    };
    let name_errno = io::Error::last_os_error().raw_os_error();
    assert_eq!(
        name_result, 0,
        "agetsockname failed with errno {name_errno:?}"
    );
    assert_eq!(actual.sin_family, libc::AF_INET as libc::sa_family_t);
    let bridge_addr = std::net::SocketAddr::from((
        std::net::Ipv4Addr::from(actual.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(actual.sin_port),
    ));
    let peer_sockaddr = to_sockaddr_in(peer_addr);
    // SAFETY: peer_sockaddr is a live sockaddr_in covered by addr_len.
    let connect_result = unsafe {
        aconnect(
            fd,
            (&peer_sockaddr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            addr_len,
            0,
            user_data,
        )
    };
    let connect_errno = io::Error::last_os_error().raw_os_error();
    assert_eq!(
        connect_result, 0,
        "aconnect failed with errno {connect_errno:?}"
    );
    let payload = b"bridge-udp-payload";
    match peer.send_to(payload, bridge_addr) {
        Ok(sent) => assert_eq!(sent, payload.len()),
        Err(error) => panic!("peer send_to failed: {error}"),
    }
    let mut buffer = [0u8; 64];
    // SAFETY: sockaddr_in contains integer fields for which zero is valid.
    let mut source: libc::sockaddr_in = unsafe { core::mem::zeroed() };
    let mut source_len = addr_len;
    let mut attempts = 0usize;
    let received = loop {
        // SAFETY: buffer, source and source_len are live for the call, and fd
        // and user_data name the same registered socket.
        let count = unsafe {
            arecvfrom(
                fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
                (&mut source as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
                &mut source_len,
                user_data,
            )
        };
        if count >= 0 {
            break count;
        }
        let errno = io::Error::last_os_error().raw_os_error();
        match errno {
            Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                attempts += 1;
                assert!(attempts < 2_000, "arecvfrom kept returning EAGAIN");
                std::thread::yield_now();
            }
            _ => panic!("arecvfrom failed with errno {errno:?}"),
        }
    };
    assert_eq!(received as usize, payload.len());
    assert_eq!(&buffer[..payload.len()], payload);
    assert_eq!(source.sin_family, libc::AF_INET as libc::sa_family_t);
    assert_eq!(source.sin_port, peer_addr.port().to_be());
    let expected_source = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("expected an IPv4 peer"),
    };
    assert_eq!(source.sin_addr.s_addr.to_ne_bytes(), expected_source);
    let reply = b"bridge-udp-reply";
    // SAFETY: reply is a live buffer, and a null destination is valid because
    // aconnect already installed the peer in the kernel socket.
    let sent = unsafe {
        asendto(
            fd,
            reply.as_ptr().cast::<libc::c_void>(),
            reply.len(),
            0,
            core::ptr::null(),
            0,
            user_data,
        )
    };
    let sent_errno = io::Error::last_os_error().raw_os_error();
    assert_eq!(
        sent as usize,
        reply.len(),
        "asendto failed with errno {sent_errno:?}"
    );
    let mut reply_buffer = [0u8; 64];
    match peer.recv_from(&mut reply_buffer) {
        Ok((count, from)) => {
            assert_eq!(count, reply.len());
            assert_eq!(&reply_buffer[..reply.len()], reply);
            assert_eq!(from, bridge_addr);
        }
        Err(error) => panic!("peer recv_from failed: {error}"),
    }
    close_ok(&state, fd);
}

#[test]
fn install_rejects_a_null_channel() {
    let state = new_state();
    let bad_channel = state.process_fds(std::ptr::null_mut(), std::ptr::null(), 0, 0);
    assert_ne!(bad_channel.0, 0);
    match state.install(std::ptr::null_mut()) {
        Err(cares::error::AresError::InvalidInput(_)) => {}
        Err(other) => panic!("install(null) returned the wrong error: {other:?}"),
        Ok(()) => panic!("install(null) returned Ok"),
    }
}

#[test]
fn install_binds_the_vtable_to_a_live_channel() {
    let state = new_state();
    let (callback, data) = state.sock_state_binding();
    assert!(callback.is_some(), "sock_state_binding has no callback");
    assert!(!data.is_null(), "sock_state_binding has no state pointer");
    // SAFETY: an all-zero `ares_options` is a valid value for the C struct:
    // every field is an integer or a nullable pointer, and only the
    // ARES_OPT_SOCK_STATE_CB fields are read under this mask.
    let mut options: cares_sys::ares_options = unsafe { core::mem::zeroed() };
    options.sock_state_cb = callback;
    options.sock_state_cb_data = data;
    let mut channel: *mut ares_channel_t = std::ptr::null_mut();
    // SAFETY: `options` points to a live, fully initialized struct that c-ares
    // copies from, and `channel` is a writable out-pointer.
    let status = unsafe {
        cares_sys::ares_init_options(&mut channel, &options, cares_sys::ARES_OPT_SOCK_STATE_CB)
    };
    assert_eq!(status, 0, "ares_init_options failed");
    assert!(!channel.is_null());
    let install_result = state.install(channel);
    assert!(install_result.is_ok());
    assert_ne!(state.process_fds(channel, std::ptr::null(), 1, 0).0, 0);
    let processed = state.process_fds(
        channel,
        std::ptr::null(),
        0,
        cares_sys::ARES_PROCESS_FLAG_NONE.0,
    );
    assert_eq!(processed.0, 0, "ares_process_fds reported a failure");
    // SAFETY: the channel was created by ares_init_options above and is
    // destroyed exactly once here, while `state` is still alive.
    unsafe { cares_sys::ares_destroy(channel) };
}

#[test]
fn timer_refresh_with_null_channel_is_none() {
    let timer = TimerState::new();
    let channel: *mut ares_channel_t = std::ptr::null_mut();
    assert!(timer.refresh(channel).is_none());
    assert!(timer.deadline().is_none());
    assert_eq!(timer.refresh_from_deadline(None), None);
}

#[test]
fn timer_refresh_on_an_idle_channel_is_none() {
    let mut channel: *mut ares_channel_t = std::ptr::null_mut();
    // SAFETY: a null options pointer with a zero mask asks c-ares to
    // initialize a default channel, and `channel` is a writable out-pointer.
    let status = unsafe { cares_sys::ares_init_options(&mut channel, std::ptr::null(), 0) };
    assert_eq!(status, 0, "ares_init_options failed");
    assert!(!channel.is_null());
    let timer = TimerState::new();
    assert!(timer.refresh(channel).is_none());
    assert!(timer.deadline().is_none());
    // SAFETY: the channel was created by ares_init_options above and is
    // destroyed exactly once here.
    unsafe { cares_sys::ares_destroy(channel) };
}

#[test]
fn refresh_from_deadline_keeps_generation_within_tolerance() {
    let timer = TimerState::new();
    let base = Instant::now() + Duration::from_secs(5);
    let first = armed(&timer, base);
    let near = armed(&timer, base + Duration::from_micros(200));
    assert_eq!(near.generation, first.generation);
    let far = armed(&timer, base + Duration::from_millis(5));
    assert_ne!(far.generation, first.generation);
    assert_eq!(timer.deadline(), Some(far));
}

#[test]
fn lifecycle_disarming_clears_expiry_and_forces_a_new_generation() {
    let timer = TimerState::new();
    let base = Instant::now() + Duration::from_secs(1);
    let first = armed(&timer, base);
    assert!(timer.on_timer(first.generation));
    timer.disarm();
    assert!(timer.deadline().is_none());
    assert!(!timer.take_expired());
    let rearmed = armed(&timer, base);
    assert_ne!(rearmed.generation, first.generation);
    assert_eq!(timer.deadline(), Some(rearmed));
}

#[test]
fn clearing_the_deadline_invalidates_the_previous_generation() {
    let timer = TimerState::new();
    let base = Instant::now() + Duration::from_secs(1);
    let first = armed(&timer, base);
    assert_eq!(timer.refresh_from_deadline(None), None);
    assert!(timer.deadline().is_none());
    let rearmed = armed(&timer, base + Duration::from_secs(1));
    assert_ne!(rearmed.generation, first.generation);
    assert!(!timer.on_timer(first.generation));
}

#[test]
fn on_timer_accepts_only_the_current_generation() {
    let timer = TimerState::new();
    let base = Instant::now() + Duration::from_secs(1);
    let current = armed(&timer, base);
    assert!(!timer.on_timer(current.generation.wrapping_add(1)));
    assert!(!timer.take_expired(), "a stale generation must not expire");
    assert!(timer.on_timer(current.generation));
    assert!(timer.take_expired());
    assert!(!timer.take_expired(), "expiry is one-shot");
}

#[test]
fn scenario_consumed_deadline_rearms_within_tolerance() {
    for consume_expiry in [false, true] {
        for delta in [Duration::ZERO, Duration::from_micros(200)] {
            let timer = TimerState::new();
            let base = Instant::now() + Duration::from_secs(1);
            let first = armed(&timer, base);
            assert!(timer.on_timer(first.generation));
            if consume_expiry {
                assert!(timer.take_expired());
                assert!(!timer.take_expired());
            }
            let next = armed(&timer, base + delta);
            assert_ne!(next.generation, first.generation);
            assert_eq!(next.at, base + delta);
            assert_eq!(timer.deadline(), Some(next));
            assert_eq!(timer.take_expired(), !consume_expiry);
            assert!(!timer.take_expired());
            assert!(!timer.on_timer(first.generation), "old SQE is stale");
            assert!(timer.on_timer(next.generation));
            assert!(!timer.on_timer(next.generation), "completion is one-shot");
            assert!(timer.take_expired());
        }
    }
}

#[test]
fn scenario_ready_for_closed_or_unowned_descriptors_is_discarded() {
    let state = new_state();
    state.on_ready(987_654, true, true);
    assert!(!state.has_pending());
    let fd = open_datagram(&state);
    state.on_ready(fd, true, true);
    close_ok(&state, fd);
    assert!(!state.has_pending());
    state.on_ready(fd, true, false);
    let mut events = Vec::new();
    assert_eq!(state.drain_ready(&mut events), 0);
    assert!(events.is_empty());
}

#[path = "socket_bridge_and_timer_tests/lifecycle.rs"]
mod lifecycle;
