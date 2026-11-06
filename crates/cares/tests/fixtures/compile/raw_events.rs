pub fn requires_unsafe() {
    let _ = cares::socket_bridge::SharedChannelState::new().process_fds(
        core::ptr::null_mut(),
        core::ptr::null(),
        0,
        0,
    );
}
