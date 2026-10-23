//! Socket ownership and panic isolation across reentrant lifecycle boundaries.

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Weak,
};

use super::*;

fn isolated_case(name: &str, mode: &str) -> bool {
    if let Ok(child_mode) = std::env::var("CARES_BRIDGE_TEST_CHILD") {
        return child_mode != mode;
    }
    let executable =
        std::env::current_exe().unwrap_or_else(|error| panic!("test executable: {error}"));
    let status = std::process::Command::new(executable)
        .args(["--exact", name, "--nocapture"])
        .env("CARES_BRIDGE_TEST_CHILD", mode)
        .status()
        .unwrap_or_else(|error| panic!("start isolated callback case: {error}"));
    assert!(status.success(), "callback case {mode} failed: {status}");
    true
}

struct ReentrantSink {
    state: Weak<SharedChannelState>,
    entered: Cell<bool>,
    removals: RefCell<Vec<ares_socket_t>>,
    replacement: RefCell<Option<std::net::UdpSocket>>,
}
impl ReadinessSink for ReentrantSink {
    fn update_interest(&self, _fd: ares_socket_t, _interest: SocketInterest) {}
    fn remove_interest(&self, fd: ares_socket_t) {
        self.removals.borrow_mut().push(fd);
        if self.entered.replace(true) {
            return;
        }
        let state = self
            .state
            .upgrade()
            .unwrap_or_else(|| panic!("state remains live"));
        state.shutdown();
        if get_status_flags(fd) < 0 {
            use std::os::fd::AsRawFd;
            let replacement = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap_or_else(|error| panic!("replacement socket: {error}"));
            assert_eq!(replacement.as_raw_fd(), fd, "isolated fd must be reusable");
            *self.replacement.borrow_mut() = Some(replacement);
        }
    }
}

#[test]
fn lifecycle_scenario_reentrant_shutdown_closes_each_descriptor_once() {
    let name = "lifecycle::lifecycle_scenario_reentrant_shutdown_closes_each_descriptor_once";
    if isolated_case(name, "reentrant") {
        return;
    }
    let state = Rc::new(SharedChannelState::new());
    let sink = Rc::new(ReentrantSink {
        state: Rc::downgrade(&state),
        entered: Cell::new(false),
        removals: RefCell::new(Vec::new()),
        replacement: RefCell::new(None),
    });
    state.set_readiness_sink(sink.clone());
    let fd = open_datagram(&state);
    state.shutdown();
    if let Some(replacement) = sink.replacement.borrow().as_ref() {
        use std::os::fd::AsRawFd;
        assert!(
            get_status_flags(replacement.as_raw_fd()) >= 0,
            "reused fd was closed twice"
        );
    }
    assert_eq!(*sink.removals.borrow(), [fd]);
    assert_eq!(state.socket_count(), 0);
    state.shutdown();
    assert_eq!(*sink.removals.borrow(), [fd]);
}

struct PanickingSink {
    state: Weak<SharedChannelState>,
    panic_on_drop: bool,
}
impl Drop for PanickingSink {
    fn drop(&mut self) {
        assert!(!self.panic_on_drop, "user sink destructor failed");
    }
}
impl ReadinessSink for PanickingSink {
    fn update_interest(&self, _fd: ares_socket_t, _interest: SocketInterest) {
        if self.panic_on_drop {
            let state = self.state.upgrade().unwrap_or_else(|| panic!("live state"));
            state.set_readiness_sink(Rc::new(RecordingSink::default()));
        }
        panic!("user update callback failed");
    }
    fn remove_interest(&self, _fd: ares_socket_t) {
        panic!("user removal callback failed");
    }
}

#[test]
fn scenario_extern_callbacks_contain_sink_panics_and_fail_closed() {
    let name = "lifecycle::scenario_extern_callbacks_contain_sink_panics_and_fail_closed";
    for mode in ["update-panic", "close-panic", "drop-panic"] {
        if isolated_case(name, mode) {
            continue;
        }
        let state = Rc::new(SharedChannelState::new());
        state.set_readiness_sink(Rc::new(PanickingSink {
            state: Rc::downgrade(&state),
            panic_on_drop: mode == "drop-panic",
        }));
        let fd = open_datagram(&state);
        let (callback, data) = state.sock_state_binding();
        if mode != "close-panic" {
            let callback = callback.unwrap_or_else(|| panic!("socket state callback"));
            // SAFETY: data comes from this live stable state; fd is owned by it.
            unsafe { callback(data, fd, 1, 0) };
        } else {
            let close = SOCKET_FUNCTIONS
                .aclose
                .unwrap_or_else(|| panic!("close callback"));
            // SAFETY: data comes from this live stable state; fd is owned by it.
            assert_eq!(unsafe { close(fd, data) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EIO));
        }
        assert_eq!(state.socket_count(), 0);
        assert!(!state.has_pending());
        assert!(
            state
                .open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0)
                .is_err()
        );
    }
}

struct ShutdownOnDrop(Weak<SharedChannelState>);
impl ReadinessSink for ShutdownOnDrop {
    fn update_interest(&self, _fd: ares_socket_t, _interest: SocketInterest) {}
    fn remove_interest(&self, _fd: ares_socket_t) {}
}
impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0
            .upgrade()
            .unwrap_or_else(|| panic!("live replacement owner"))
            .shutdown();
    }
}

#[test]
fn replacing_sole_owned_sink_allows_destructor_shutdown_reentry() {
    let name = "lifecycle::replacing_sole_owned_sink_allows_destructor_shutdown_reentry";
    if isolated_case(name, "replace-reentry") {
        return;
    }
    let state = Rc::new(SharedChannelState::new());
    state.set_readiness_sink(Rc::new(ShutdownOnDrop(Rc::downgrade(&state))));
    let fds = [open_datagram(&state), open_stream(&state)];
    let replacement = Rc::new(RecordingSink::default());
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            state.set_readiness_sink(replacement.clone());
        }))
        .is_ok()
    );
    assert!(!state.readiness_sink_failed());
    assert_eq!(state.socket_count(), 0);
    assert_eq!(replacement.removals.borrow().len(), fds.len());
    for fd in fds {
        assert_eq!(get_descriptor_flags(fd), -1, "reentrant shutdown leaked fd");
    }
    let fd = open_datagram(&state);
    close_ok(&state, fd);
}

#[test]
fn final_owner_drop_closes_every_descriptor_even_when_removal_panics() {
    let name = "lifecycle::final_owner_drop_closes_every_descriptor_even_when_removal_panics";
    for mode in ["drop-plain", "drop-remove-panic", "shutdown-remove-panic"] {
        if isolated_case(name, mode) {
            continue;
        }
        let state = Rc::new(SharedChannelState::new());
        if mode != "drop-plain" {
            state.set_readiness_sink(Rc::new(PanickingSink {
                state: Rc::downgrade(&state),
                panic_on_drop: false,
            }));
        }
        let fds = [
            open_datagram(&state),
            open_stream(&state),
            open_datagram(&state),
        ];
        if mode == "shutdown-remove-panic" {
            state.shutdown();
            assert!(state.readiness_sink_failed());
            assert_eq!(state.socket_count(), 0);
            state.shutdown();
        }
        assert!(catch_unwind(AssertUnwindSafe(|| drop(state))).is_ok());
        for fd in fds {
            assert_eq!(get_descriptor_flags(fd), -1, "final owner leaked fd");
        }
    }
}

struct ExplosivePayload(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for ExplosivePayload {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::panic::panic_any(Self(self.0.clone()));
    }
}
struct PayloadSink(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl ReadinessSink for PayloadSink {
    fn update_interest(&self, _fd: ares_socket_t, _interest: SocketInterest) {
        std::panic::panic_any(ExplosivePayload(self.0.clone()));
    }
    fn remove_interest(&self, _fd: ares_socket_t) {}
}

#[test]
fn final_owner_isolates_retained_payload_destructor_and_its_panic_payload() {
    let name = "lifecycle::final_owner_isolates_retained_payload_destructor_and_its_panic_payload";
    for mode in ["payload-drop", "payload-unwinding"] {
        if isolated_case(name, mode) {
            continue;
        }
        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = SharedChannelState::new();
        state.set_readiness_sink(Rc::new(PayloadSink(drops.clone())));
        let fd = open_datagram(&state);
        state.on_socket_state(fd, true, false);
        assert!(state.readiness_sink_failed());
        assert_eq!(get_descriptor_flags(fd), -1);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _state = state;
            if mode == "payload-unwinding" {
                panic!("outer unwind");
            }
        }));
        assert_eq!(result.is_err(), mode == "payload-unwinding");
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
