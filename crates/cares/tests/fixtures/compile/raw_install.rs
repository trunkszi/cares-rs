pub fn requires_unsafe() {
    let _ = cares::socket_bridge::SharedChannelState::new().install(core::ptr::null_mut());
}
