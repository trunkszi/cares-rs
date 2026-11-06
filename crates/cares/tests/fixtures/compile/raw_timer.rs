pub fn requires_unsafe() {
    let _ = cares::timer::TimerState::new().refresh(core::ptr::null_mut());
}
