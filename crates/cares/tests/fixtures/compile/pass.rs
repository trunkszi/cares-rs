pub fn accept(_: cares::Resolver, _: cares::LibraryGuard) {}

pub fn raw_channel_control() {
    let timer = cares::timer::TimerState::new();
    let bridge = cares::socket_bridge::SharedChannelState::new();
    // SAFETY: Null channels and a null zero-length event array are explicitly rejected or disarmed.
    unsafe {
        let _ = timer.refresh(core::ptr::null_mut());
        let _ = bridge.install(core::ptr::null_mut());
        let _ = bridge.process_fds(core::ptr::null_mut(), core::ptr::null(), 0, 0);
    }
}
