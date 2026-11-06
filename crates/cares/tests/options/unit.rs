use super::*;

#[test]
fn unit_scenario_failover_delay_respects_signed_time_boundary() -> Result<()> {
    let maximum = i64::MAX as u64;
    for chance in [0, 1] {
        let options = ResolverBuilder::new()
            .server_failover(chance, Duration::from_millis(maximum))
            .build()?;
        assert_eq!(
            options.raw_options().server_failover_opts.retry_delay,
            maximum as usize
        );
        assert_eq!(
            options.raw_options().server_failover_opts.retry_chance,
            chance
        );
        assert!(matches!(
            ResolverBuilder::new()
                .server_failover(chance, Duration::from_millis(maximum + 1))
                .build(),
            Err(AresError::InvalidInput(_))
        ));
    }
    Ok(())
}

#[test]
fn channel_copies_servers_domains_and_lookups_before_options_drop() -> Result<()> {
    // SAFETY: this unit-test process initializes c-ares once and never
    // cleans it up while any test-owned C allocations remain live.
    AresError::check(unsafe { cares_sys::ares_library_init(cares_sys::ARES_LIB_INIT_ALL) })?;
    let options = ResolverBuilder::new()
        .servers([Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 53)])
        .search_domains(["one.test", "two.test"])
        .lookup_strategy(LookupStrategy::FilesThenDns)
        .resolvconf_path("/dev/null")
        .hosts_path("/dev/null")
        .build()?;
    let moved = Box::new(options);
    let (raw, mask) = moved.as_raw();
    let mut channel = ptr::null_mut();
    // SAFETY: moved owns every input allocation throughout initialization;
    // channel points to writable storage for the new channel allocation.
    AresError::check(unsafe { cares_sys::ares_init_options(&mut channel, raw, mask) })?;
    struct Channel(*mut cares_sys::ares_channel_t);
    impl Drop for Channel {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the initialized channel.
            unsafe { cares_sys::ares_destroy(self.0) };
        }
    }
    let channel = Channel(channel);
    drop(moved);
    struct Saved(cares_sys::ares_options);
    impl Drop for Saved {
        fn drop(&mut self) {
            // SAFETY: save_options initializes this independent C-owned
            // options aggregate; destroy_options frees only its contents.
            unsafe { cares_sys::ares_destroy_options(&mut self.0) };
        }
    }
    let mut saved = Saved(empty_options());
    let mut mask = 0;
    // SAFETY: channel is live and the output aggregates are writable;
    // saved owns all C allocations produced by this call, even on failure.
    AresError::check(unsafe { cares_sys::ares_save_options(channel.0, &mut saved.0, &mut mask) })?;
    assert_eq!((saved.0.nservers, saved.0.ndomains), (2, 2));
    // SAFETY: successful save_options produced the validated counts above
    // and independently allocated NUL-terminated strings and address data.
    unsafe {
        assert_eq!((*saved.0.servers).s_addr.to_ne_bytes(), [127, 0, 0, 1]);
        assert_eq!(
            (*saved.0.servers.add(1)).s_addr.to_ne_bytes(),
            [192, 0, 2, 53]
        );
        assert_eq!(
            std::ffi::CStr::from_ptr(*saved.0.domains).to_bytes(),
            b"one.test"
        );
        assert_eq!(
            std::ffi::CStr::from_ptr(*saved.0.domains.add(1)).to_bytes(),
            b"two.test"
        );
        assert_eq!(std::ffi::CStr::from_ptr(saved.0.lookups).to_bytes(), b"fb");
        assert_eq!(
            std::ffi::CStr::from_ptr(saved.0.resolvconf_path).to_bytes(),
            b"/dev/null"
        );
        assert_eq!(
            std::ffi::CStr::from_ptr(saved.0.hosts_path).to_bytes(),
            b"/dev/null"
        );
    }
    let empty = ResolverBuilder::new()
        .servers([])
        .search_domains([] as [&str; 0])
        .build()?;
    assert!(empty.raw_options().servers.is_null());
    assert!(empty.raw_options().domains.is_null());
    assert_eq!(
        (empty.raw_options().nservers, empty.raw_options().ndomains),
        (0, 0)
    );
    assert_ne!(empty.optmask() & cares_sys::ARES_OPT_SERVERS, 0);
    Ok(())
}
