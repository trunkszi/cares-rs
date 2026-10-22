//! Wire-format, configuration ownership, and synchronous callback contracts.

#![allow(clippy::expect_used, reason = "Test assertions fail with context.")]

use std::{
    cell::{Cell, RefCell},
    ffi::CStr,
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
    rc::{Rc, Weak},
    time::Duration,
};

use cares::{
    callbacks::{self, CallbackSlot, CallbackState, NotificationSlot, SocketStateEvent},
    error::{AresError, AresStatus, ErrorKind, Result},
    options::{LookupStrategy, ResolverBuilder, ResolverOptions},
    record::{DnsRecord, DnsRecordRef},
    record_rr::*,
    types::{DnsClass, DnsFlags, DnsRecordType, DnsSection},
};
use cares_sys as sys;

fn round_trip<T>(value: T) -> Result<()>
where
    T: FromDnsRr + IntoDnsRr + Debug + PartialEq,
{
    let mut record = DnsRecord::builder()
        .id(0x1234)
        .flags(DnsFlags::QR | DnsFlags::RD | DnsFlags::RA)
        .question("example.test", <T as FromDnsRr>::RECORD_TYPE, DnsClass::IN)
        .build()?;
    for section in [
        DnsSection::Answer,
        DnsSection::Authority,
        DnsSection::Additional,
    ] {
        record.add_record(section, "example.test", DnsClass::IN, 300, &value)?;
    }
    let parsed = DnsRecord::parse_wire(&record.write_wire()?)?;
    assert_eq!(parsed.id(), 0x1234);
    assert_eq!(parsed.flags(), record.flags());
    assert_eq!(parsed.question(0)?.name, "example.test");
    for section in [
        DnsSection::Answer,
        DnsSection::Authority,
        DnsSection::Additional,
    ] {
        let values = parsed.records::<T>(section)?;
        assert_eq!(values.len(), 1);
        assert_eq!(&values[0], &value);
        assert_eq!(parsed.rr(section, 0)?.name()?, "example.test");
        assert_eq!(parsed.rr(section, 0)?.ttl(), 300);
        assert_eq!(&parsed.rr(section, 0)?.extract::<T>()?, &value);
    }
    Ok(())
}

#[test]
fn all_fourteen_typed_records_round_trip() -> Result<()> {
    round_trip(NsRecord {
        nsdname: "ns.test".into(),
    })?;
    round_trip(ARecord {
        address: Ipv4Addr::new(192, 0, 2, 17),
    })?;
    round_trip(AaaaRecord {
        address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x17),
    })?;
    round_trip(CnameRecord {
        cname: "canonical.test".into(),
    })?;
    round_trip(MxRecord {
        preference: 10,
        exchange: "mail.test".into(),
    })?;
    round_trip(TxtRecord {
        chunks: vec![b"first\0binary".to_vec(), vec![], vec![0xff, 0x80]],
    })?;
    round_trip(SrvRecord {
        priority: 10,
        weight: 20,
        port: 443,
        target: "service.test".into(),
    })?;
    round_trip(PtrRecord {
        dname: "reverse.test".into(),
    })?;
    round_trip(SoaRecord {
        mname: "ns.test".into(),
        rname: "admin.test".into(),
        serial: 4_000_000_001,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: 30,
    })?;
    round_trip(NaptrRecord {
        order: 10,
        preference: 20,
        flags: "S".into(),
        services: "SIP+D2U".into(),
        regexp: String::new(),
        replacement: "_sip._udp.test".into(),
    })?;
    round_trip(UriRecord {
        priority: 10,
        weight: 20,
        target: "https://example.test/resource".into(),
    })?;
    round_trip(CaaRecord {
        critical: 128,
        tag: "issue".into(),
        value: b"ca.test".to_vec(),
    })?;
    round_trip(TlsaRecord {
        cert_usage: 3,
        selector: 1,
        matching_type: 1,
        data: vec![0, 255, 128, 7],
    })?;
    let params = vec![(1, vec![2, b'h', b'2']), (65400, vec![0, 255])];
    round_trip(HttpsRecord {
        priority: 1,
        target: "https.test".into(),
        params: params.clone(),
    })?;
    round_trip(SvcbRecord {
        priority: 1,
        target: "svc.test".into(),
        params,
    })?;
    Ok(())
}

#[test]
fn txt_rejects_unrepresentable_segments_without_changing_existing_data() -> Result<()> {
    let mut record = DnsRecord::builder()
        .question("txt.test", DnsRecordType::TXT, DnsClass::IN)
        .build()?;
    let valid = TxtRecord {
        chunks: vec![vec![0; 255], vec![]],
    };
    record.add_record(DnsSection::Answer, "txt.test", DnsClass::IN, 0, &valid)?;
    for chunks in [vec![], vec![vec![0; 256]]] {
        assert!(
            record
                .rr_mut(DnsSection::Answer, 0)?
                .set(&TxtRecord { chunks })
                .is_err()
        );
        assert_eq!(record.rr(DnsSection::Answer, 0)?.as_txt()?, valid);
    }
    let parsed = DnsRecord::parse_wire(&record.write_wire()?)?;
    assert_eq!(parsed.rr(DnsSection::Answer, 0)?.as_txt()?, valid);
    Ok(())
}

#[test]
fn owned_and_borrowed_duplication_survive_source_destruction() -> Result<()> {
    let mut source = DnsRecord::builder()
        .id(5)
        .question("original.test", DnsRecordType::A, DnsClass::IN)
        .build()?;
    source.add_record(
        DnsSection::Answer,
        "original.test",
        DnsClass::IN,
        12,
        &ARecord {
            address: Ipv4Addr::LOCALHOST,
        },
    )?;
    let cloned = source.try_clone()?;
    let borrowed_copy = source.as_ref().to_owned_record()?;
    source.set_id(77)?;
    source.query_set_name(0, "changed.test")?;
    source.rr_mut(DnsSection::Answer, 0)?.set(&ARecord {
        address: Ipv4Addr::UNSPECIFIED,
    })?;
    drop(source);
    for copy in [cloned, borrowed_copy] {
        assert_eq!(copy.id(), 5);
        assert_eq!(copy.question(0)?.name, "original.test");
        assert_eq!(
            copy.rr(DnsSection::Answer, 0)?.as_a()?.address,
            Ipv4Addr::LOCALHOST
        );
    }
    Ok(())
}

#[test]
fn malformed_input_and_failed_rr_add_are_rejected() -> Result<()> {
    for wire in [&[][..], &[0][..], &[0; 11][..], &[0xff; 32][..]] {
        assert!(DnsRecord::parse_wire(wire).is_err());
    }
    assert!(
        DnsRecord::builder()
            .question("bad\0name", DnsRecordType::A, DnsClass::IN)
            .build()
            .is_err()
    );
    let mut record = DnsRecord::builder().build()?;
    assert!(
        record
            .add_record(
                DnsSection::Answer,
                "example.test",
                DnsClass::IN,
                1,
                &MxRecord {
                    preference: 10,
                    exchange: "bad\0name".into()
                }
            )
            .is_err()
    );
    assert_eq!(record.rr_count(DnsSection::Answer), 0);
    record.add_record(
        DnsSection::Answer,
        "example.test",
        DnsClass::IN,
        1,
        &ARecord {
            address: Ipv4Addr::LOCALHOST,
        },
    )?;
    assert!(record.rr(DnsSection::Answer, 0)?.as_mx().is_err());
    assert!(record.rr(DnsSection::Answer, 1).is_err());
    assert!(record.question(0).is_err());
    Ok(())
}

#[test]
fn opt_payload_class_and_unknown_options_survive_wire() -> Result<()> {
    let mut record = DnsRecord::builder()
        .question("example.test", DnsRecordType::A, DnsClass::IN)
        .build()?;
    let value = OptRecord {
        udp_size: 4096,
        version: 0,
        flags: 0x8000,
        options: vec![(65000, vec![0, 255, 1])],
    };
    record.add_record(DnsSection::Additional, "", DnsClass::IN, 0, &value)?;
    let parsed = DnsRecord::parse_wire(&record.write_wire()?)?;
    let rr = parsed.rr(DnsSection::Additional, 0)?;
    assert_eq!(rr.class()?, DnsClass::IN);
    assert_eq!(DnsClass::new(4096).as_raw(), 4096);
    assert_eq!(rr.as_opt()?, value);
    Ok(())
}

#[test]
fn all_c_statuses_preserve_codes_and_upstream_descriptions() {
    for code in 0..=26 {
        let status = AresStatus::from_raw(code);
        assert_eq!(status.as_raw(), code);
        assert!(!status.message().is_empty());
        assert_eq!(AresError::check(code).is_ok(), code == 0);
    }
    for code in [-1, 999] {
        assert_eq!(AresStatus::from_raw(code).as_raw(), code);
        assert_eq!(
            AresError::from_status(code)
                .status()
                .map(AresStatus::as_raw),
            Some(code)
        );
    }
    assert_eq!(AresStatus::Timeout.kind(), Some(ErrorKind::Temporal));
    assert_eq!(AresStatus::ServerFail.kind(), Some(ErrorKind::Temporal));
    assert_eq!(AresStatus::NotFound.kind(), Some(ErrorKind::Fatal));
    assert_eq!(AresStatus::Cancelled.kind(), Some(ErrorKind::Fatal));
}

#[test]
fn options_preserve_raw_values_and_pointers_across_moves() -> Result<()> {
    let options = ResolverBuilder::new()
        .timeout(Duration::from_millis(1250))
        .tries(3)
        .ndots(2)
        .udp_max_queries(17)
        .udp_port(5300)
        .tcp_port(5301)
        .socket_send_buffer_size(8192)
        .socket_receive_buffer_size(16384)
        .edns0_payload_size(4096)
        .dns0x20(true)
        .primary(true)
        .rotate(true)
        .servers([Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 53)])
        .search_domains(["one.test", "two.test"])
        .lookup_strategy(LookupStrategy::FilesThenDns)
        .resolvconf_path("/tmp/cares-c3-resolv.conf")
        .hosts_path("/tmp/cares-c3-hosts")
        .max_timeout(Duration::from_millis(4000))
        .query_cache_ttl(Duration::from_secs(90))
        .server_failover(7, Duration::from_millis(2000))
        .build()?;
    let original_domains = options.raw_options().domains;
    let moved = Box::new(options);
    let (raw, mask) = moved.as_raw();
    assert_eq!(raw.timeout, 1250);
    assert_eq!((raw.tries, raw.ndots, raw.udp_max_queries), (3, 2, 17));
    assert_eq!((raw.udp_port, raw.tcp_port), (5300, 5301));
    assert_eq!(
        (raw.socket_send_buffer_size, raw.socket_receive_buffer_size),
        (8192, 16384)
    );
    assert_eq!(raw.ednspsz, 4096);
    assert_eq!(raw.maxtimeout, 4000);
    assert_eq!(raw.qcache_max_ttl, 90);
    assert_eq!(raw.server_failover_opts.retry_chance, 7);
    assert_eq!(raw.server_failover_opts.retry_delay, 2000);
    assert_eq!(
        raw.flags,
        sys::ARES_FLAG_EDNS | sys::ARES_FLAG_DNS0x20 | sys::ARES_FLAG_PRIMARY
    );
    let required = sys::ARES_OPT_FLAGS
        | sys::ARES_OPT_TIMEOUTMS
        | sys::ARES_OPT_TRIES
        | sys::ARES_OPT_NDOTS
        | sys::ARES_OPT_UDP_MAX_QUERIES
        | sys::ARES_OPT_UDP_PORT
        | sys::ARES_OPT_TCP_PORT
        | sys::ARES_OPT_SOCK_SNDBUF
        | sys::ARES_OPT_SOCK_RCVBUF
        | sys::ARES_OPT_EDNSPSZ
        | sys::ARES_OPT_DOMAINS
        | sys::ARES_OPT_LOOKUPS
        | sys::ARES_OPT_RESOLVCONF
        | sys::ARES_OPT_HOSTS_FILE
        | sys::ARES_OPT_ROTATE
        | sys::ARES_OPT_MAXTIMEOUTMS
        | sys::ARES_OPT_QUERY_CACHE
        | sys::ARES_OPT_SERVER_FAILOVER
        | sys::ARES_OPT_SERVERS;
    assert_eq!(mask, required);
    assert_eq!(mask & sys::ARES_OPT_EVENT_THREAD, 0);
    assert_eq!(raw.domains, original_domains);
    assert_eq!(raw.ndomains, 2);
    assert_eq!(raw.nservers, 2);
    // SAFETY: moved retains all CString and pointer-array allocations; ndomains is two.
    unsafe {
        assert_eq!((*raw.servers).s_addr.to_ne_bytes(), [127, 0, 0, 1]);
        assert_eq!((*raw.servers.add(1)).s_addr.to_ne_bytes(), [192, 0, 2, 53]);
        assert_eq!(CStr::from_ptr(*raw.domains).to_bytes(), b"one.test");
        assert_eq!(CStr::from_ptr(*raw.domains.add(1)).to_bytes(), b"two.test");
        assert_eq!(CStr::from_ptr(raw.lookups).to_bytes(), b"fb");
        assert_eq!(
            CStr::from_ptr(raw.resolvconf_path).to_bytes(),
            b"/tmp/cares-c3-resolv.conf"
        );
        assert_eq!(
            CStr::from_ptr(raw.hosts_path).to_bytes(),
            b"/tmp/cares-c3-hosts"
        );
    }
    Ok(())
}

#[test]
fn option_defaults_zero_values_and_invalid_configuration() -> Result<()> {
    assert_eq!(ResolverOptions::default().optmask(), 0);
    let zero = ResolverBuilder::new()
        .udp_max_queries(0)
        .query_cache_ttl(Duration::ZERO)
        .server_failover(0, Duration::ZERO)
        .rotate(false)
        .build()?;
    assert_eq!(zero.raw_options().udp_max_queries, 0);
    assert_eq!(zero.raw_options().server_failover_opts.retry_chance, 0);
    assert_ne!(zero.optmask() & sys::ARES_OPT_NOROTATE, 0);
    assert_eq!(zero.optmask() & sys::ARES_OPT_ROTATE, 0);
    for invalid in [
        ResolverBuilder::new().timeout(Duration::from_nanos(1)),
        ResolverBuilder::new().timeout(Duration::from_secs(u64::MAX)),
        ResolverBuilder::new().tries(0),
        ResolverBuilder::new().ndots(u32::MAX),
        ResolverBuilder::new().tcp_max_queries(10),
        ResolverBuilder::new().edns0_payload_size(65536),
        ResolverBuilder::new().socket_send_buffer_size(usize::MAX),
        ResolverBuilder::new().search_domains(["bad\0name"]),
        ResolverBuilder::new().hosts_path("bad\0path"),
        ResolverBuilder::new().lookups("invalid"),
        ResolverBuilder::new().query_cache_ttl(Duration::from_millis(1)),
    ] {
        assert!(invalid.build().is_err());
    }
    Ok(())
}

#[test]
fn socket_notifications_are_injected_before_channel_initialization() {
    unsafe extern "C" fn socket_state(
        _: *mut std::ffi::c_void,
        _: sys::ares_socket_t,
        _: i32,
        _: i32,
    ) {
    }
    let mut marker = 0_u8;
    let data = std::ptr::from_mut(&mut marker).cast();
    let options = ResolverOptions::default().with_sock_state_cb(Some(socket_state), data);
    let (raw, mask) = options.as_raw();
    assert_eq!(raw.sock_state_cb_data, data);
    assert!(raw.sock_state_cb.is_some());
    assert_eq!(mask, sys::ARES_OPT_SOCK_STATE_CB);
}

type DnsCallback = Box<dyn for<'cb> FnOnce(Result<DnsRecordRef<'cb>>, usize)>;
type DnsSlot = Rc<CallbackSlot<DnsCallback>>;

fn deliver_dns(slot: &DnsSlot, status: sys::ares_status_t, record: Option<&DnsRecord>) {
    let arg = Rc::into_raw(Rc::clone(slot)).cast_mut().cast();
    // SAFETY: arg transfers exactly one Rc of the matching slot type; the
    // optional record remains alive and immutably borrowed until return.
    unsafe {
        callbacks::dns_rec_trampoline::<DnsCallback>(
            arg,
            status,
            2,
            record.map_or(std::ptr::null(), DnsRecord::as_ptr),
        );
    }
}

#[test]
fn dns_callback_borrow_is_duplicated_before_c_record_is_destroyed() -> Result<()> {
    let state = Rc::new(CallbackState::new());
    let output = Rc::new(RefCell::new(None));
    let captured = Rc::clone(&output);
    let callback: DnsCallback = Box::new(move |result, timeouts| {
        assert_eq!(timeouts, 2);
        *captured.borrow_mut() = Some(result.and_then(|record| record.to_owned_record()));
    });
    let slot = CallbackSlot::new(Rc::clone(&state), callback);
    let source = DnsRecord::builder()
        .id(41)
        .question("callback.test", DnsRecordType::A, DnsClass::IN)
        .build()?;
    deliver_dns(&slot, sys::ARES_SUCCESS, Some(&source));
    drop(source);
    let saved = output
        .borrow_mut()
        .take()
        .ok_or_else(|| AresError::invalid_input("missing callback"))??;
    assert_eq!(saved.id(), 41);
    assert!(slot.is_completed());
    assert!(!state.is_poisoned());
    assert_eq!(Rc::strong_count(&slot), 1);
    Ok(())
}

#[test]
fn callback_can_reenter_slot_storage_without_a_live_mutable_borrow() {
    let state = Rc::new(CallbackState::new());
    let self_slot: Rc<RefCell<Weak<CallbackSlot<DnsCallback>>>> = Rc::default();
    let counts = Rc::new(Cell::new(0));
    let weak_slot = Rc::clone(&self_slot);
    let inside_state = Rc::clone(&state);
    let inside_counts = Rc::clone(&counts);
    let callback: DnsCallback = Box::new(move |result, _| {
        assert!(result.is_err());
        assert_eq!(inside_state.depth(), 1);
        let current = weak_slot.borrow().upgrade().expect("live outer slot");
        assert!(current.take().is_none());
        let nested_state = Rc::clone(&inside_state);
        let nested_counts = Rc::clone(&inside_counts);
        let nested: DnsCallback = Box::new(move |_, _| {
            assert_eq!(nested_state.depth(), 2);
            nested_counts.set(nested_counts.get() + 1);
        });
        let slot = CallbackSlot::new(Rc::clone(&inside_state), nested);
        deliver_dns(&slot, sys::ARES_ENOTFOUND, None);
        assert!(slot.is_completed());
        inside_counts.set(inside_counts.get() + 1);
    });
    let outer = CallbackSlot::new(Rc::clone(&state), callback);
    *self_slot.borrow_mut() = Rc::downgrade(&outer);
    deliver_dns(&outer, sys::ARES_ENOTFOUND, None);
    assert_eq!(counts.get(), 2);
    assert!(!state.is_poisoned());
    assert_eq!(state.depth(), 0);
}

#[test]
fn logical_cancellation_waits_for_final_c_delivery_and_preserves_other_slots() {
    let state = Rc::new(CallbackState::new());
    let cancelled: DnsCallback = Box::new(|_, _| panic!("cancelled callback executed"));
    let cancelled = CallbackSlot::new(Rc::clone(&state), cancelled);
    drop(cancelled.take());
    assert!(!cancelled.is_completed());
    let delivered = Rc::new(Cell::new(false));
    let capture = Rc::clone(&delivered);
    let other: DnsCallback = Box::new(move |_, _| capture.set(true));
    let other = CallbackSlot::new(Rc::clone(&state), other);
    deliver_dns(&cancelled, sys::ARES_ECANCELLED, None);
    assert!(cancelled.is_completed());
    assert!(!other.is_completed());
    assert!(!delivered.get());
    deliver_dns(&other, sys::ARES_ENOTFOUND, None);
    assert!(delivered.get());
    assert!(!state.is_poisoned());
}

#[test]
fn panicking_dns_callback_is_poisoned_and_retains_its_payload() {
    let state = Rc::new(CallbackState::new());
    let callback: DnsCallback = Box::new(|_, _| std::panic::panic_any(String::from("dns panic")));
    let slot = CallbackSlot::new(Rc::clone(&state), callback);
    deliver_dns(&slot, sys::ARES_ENOTFOUND, None);
    assert!(slot.is_completed());
    assert!(state.is_poisoned());
    assert!(!state.in_callback());
    let payload = state.take_panic().expect("retained panic");
    assert_eq!(
        payload.downcast_ref::<String>().map(String::as_str),
        Some("dns panic")
    );
    assert!(state.take_panic().is_none());
    assert!(state.is_poisoned());
}

#[test]
fn success_with_null_record_is_an_error() {
    let state = Rc::new(CallbackState::new());
    let delivered = Rc::new(Cell::new(false));
    let capture = Rc::clone(&delivered);
    let callback: DnsCallback = Box::new(move |result, _| {
        capture.set(matches!(result, Err(AresError::InvalidRecord(_))));
    });
    let slot = CallbackSlot::new(Rc::clone(&state), callback);
    deliver_dns(&slot, sys::ARES_SUCCESS, None);
    assert!(delivered.get());
    assert!(!state.is_poisoned());
}

#[test]
fn host_and_nameinfo_callbacks_copy_all_borrowed_data() {
    use cares::types::{HostEntry, NameInfo};
    type HostCallback = Box<dyn FnOnce(Result<HostEntry>, usize)>;
    type NameCallback = Box<dyn FnOnce(Result<NameInfo>, usize)>;
    let state = Rc::new(CallbackState::new());
    let host_output = Rc::new(RefCell::new(None));
    let capture = Rc::clone(&host_output);
    let callback: HostCallback = Box::new(move |result, _| *capture.borrow_mut() = Some(result));
    let slot = CallbackSlot::new(Rc::clone(&state), callback);
    let name = std::ffi::CString::new("canonical.test").expect("valid name");
    let alias = std::ffi::CString::new("alias.test").expect("valid alias");
    let mut aliases = [alias.as_ptr().cast_mut(), std::ptr::null_mut()];
    let mut addr = [192_u8, 0, 2, 7];
    let mut addresses = [addr.as_mut_ptr().cast(), std::ptr::null_mut()];
    let mut host = libc::hostent {
        h_name: name.as_ptr().cast_mut(),
        h_aliases: aliases.as_mut_ptr(),
        h_addrtype: libc::AF_INET,
        h_length: 4,
        h_addr_list: addresses.as_mut_ptr(),
    };
    // SAFETY: all hostent arrays include null terminators and their buffers stay
    // alive until return; arg transfers exactly one matching strong reference.
    unsafe {
        callbacks::host_trampoline::<HostCallback>(
            Rc::into_raw(Rc::clone(&slot)).cast_mut().cast(),
            0,
            0,
            &mut host,
        );
    }
    drop((name, alias));
    let result = host_output
        .borrow_mut()
        .take()
        .expect("host callback")
        .expect("host result");
    assert_eq!(result.name, "canonical.test");
    assert_eq!(result.aliases, ["alias.test"]);
    assert_eq!(
        result.addresses,
        [std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
    );
    let output = Rc::new(RefCell::new(None));
    let capture = Rc::clone(&output);
    let callback: NameCallback = Box::new(move |result, _| *capture.borrow_mut() = Some(result));
    let slot = CallbackSlot::new(Rc::clone(&state), callback);
    let service = std::ffi::CString::new("https").expect("valid service");
    // SAFETY: service is a live NUL-terminated C string; the slot Rc is consumed once.
    unsafe {
        callbacks::nameinfo_trampoline::<NameCallback>(
            Rc::into_raw(Rc::clone(&slot)).cast_mut().cast(),
            0,
            0,
            std::ptr::null_mut(),
            service.as_ptr().cast_mut(),
        );
    }
    drop(service);
    let result = output
        .borrow_mut()
        .take()
        .expect("name callback")
        .expect("name result");
    assert_eq!(result.node, None);
    assert_eq!(result.service.as_deref(), Some("https"));
    assert!(!state.is_poisoned());
}

#[test]
fn persistent_socket_notifications_queue_recursive_delivery_and_catch_panics() {
    type SocketCallback = Box<dyn FnMut(SocketStateEvent)>;
    type SocketSlot = NotificationSlot<SocketCallback, SocketStateEvent>;
    let state = Rc::new(CallbackState::new());
    let weak: Rc<RefCell<Weak<SocketSlot>>> = Rc::default();
    let slot_ref = Rc::clone(&weak);
    let events = Rc::new(RefCell::new(Vec::new()));
    let capture = Rc::clone(&events);
    let callback: SocketCallback = Box::new(move |event| {
        capture.borrow_mut().push(event.socket);
        if event.socket == 1 {
            let slot = slot_ref.borrow().upgrade().expect("notification owner");
            // SAFETY: a strong reference retains this exact persistent slot;
            // recursive delivery borrows it without consuming its raw pointer.
            unsafe {
                callbacks::sock_state_trampoline::<SocketCallback>(
                    Rc::as_ptr(&slot).cast_mut().cast(),
                    2,
                    1,
                    0,
                );
            }
        } else if event.socket == 3 {
            panic!("notification panic");
        }
    });
    let slot = NotificationSlot::new(Rc::clone(&state), callback);
    *weak.borrow_mut() = Rc::downgrade(&slot);
    // SAFETY: slot remains alive for both C callback invocations and has the
    // exact concrete type expected by the generic trampoline.
    unsafe {
        callbacks::sock_state_trampoline::<SocketCallback>(
            Rc::as_ptr(&slot).cast_mut().cast(),
            1,
            1,
            0,
        );
        callbacks::sock_state_trampoline::<SocketCallback>(
            Rc::as_ptr(&slot).cast_mut().cast(),
            3,
            1,
            0,
        );
    }
    assert_eq!(*events.borrow(), [1, 2, 3]);
    assert!(state.is_poisoned());
    assert!(state.take_panic().is_some());
    assert_eq!(state.depth(), 0);
}

#[test]
fn actual_c_ares_immediate_completion_can_submit_a_followup_query() -> Result<()> {
    use std::sync::OnceLock;
    static INITIALIZED: OnceLock<i32> = OnceLock::new();
    AresError::check(*INITIALIZED.get_or_init(|| {
        // SAFETY: initialization is performed once; this build is threadless
        // and no cleanup runs while other record tests may use C allocations.
        unsafe { sys::ares_library_init(sys::ARES_LIB_INIT_ALL) }
    }))?;
    let mut raw = std::ptr::null_mut();
    // SAFETY: raw is a writable output for a new, thread-local C channel.
    AresError::check(unsafe { sys::ares_init(&mut raw) })?;
    struct Channel(*mut sys::ares_channel_t);
    impl Drop for Channel {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the successfully initialized channel.
            unsafe { sys::ares_destroy(self.0) };
        }
    }
    let channel = Channel(raw);
    let state = Rc::new(CallbackState::new());
    let calls = Rc::new(Cell::new(0));
    let captured_calls = Rc::clone(&calls);
    let captured_state = Rc::clone(&state);
    let callback: DnsCallback = Box::new(move |result, _| {
        assert_eq!(
            result.expect_err("onion name rejected").status(),
            Some(AresStatus::NotFound)
        );
        captured_calls.set(captured_calls.get() + 1);
        let calls = Rc::clone(&captured_calls);
        let callback: DnsCallback = Box::new(move |result, _| {
            assert!(result.is_err());
            calls.set(calls.get() + 1);
        });
        let nested = CallbackSlot::new(Rc::clone(&captured_state), callback);
        // SAFETY: nested is pre-registered, transfers one Rc, and the .onion
        // name completes synchronously without network traffic. raw stays live.
        unsafe {
            sys::ares_query_dnsrec(
                raw,
                c"followup.onion".as_ptr(),
                sys::ARES_CLASS_IN,
                sys::ARES_REC_TYPE_A,
                Some(callbacks::dns_trampoline::<DnsCallback>),
                Rc::into_raw(Rc::clone(&nested)).cast_mut().cast(),
                std::ptr::null_mut(),
            );
        }
        assert!(nested.is_completed());
    });
    let slot = CallbackSlot::new(Rc::clone(&state), callback);
    // SAFETY: the slot is registered before entering c-ares, which consumes
    // exactly one C reference even when it completes before this call returns.
    unsafe {
        sys::ares_query_dnsrec(
            channel.0,
            c"initial.onion".as_ptr(),
            sys::ARES_CLASS_IN,
            sys::ARES_REC_TYPE_A,
            Some(callbacks::dns_trampoline::<DnsCallback>),
            Rc::into_raw(Rc::clone(&slot)).cast_mut().cast(),
            std::ptr::null_mut(),
        );
    }
    assert_eq!(calls.get(), 2);
    assert!(slot.is_completed());
    assert!(!state.is_poisoned());
    assert_eq!(state.depth(), 0);
    Ok(())
}

#[test]
fn server_notifications_copy_strings_and_quarantine_user_panics() {
    use cares::callbacks::ServerStateEvent;
    type Callback = Box<dyn FnMut(ServerStateEvent)>;
    let state = Rc::new(CallbackState::new());
    let output = Rc::new(RefCell::new(None));
    let capture = Rc::clone(&output);
    let callback: Callback = Box::new(move |event| {
        if !event.success {
            panic!("server callback panic");
        }
        *capture.borrow_mut() = Some(event);
    });
    let slot = NotificationSlot::new(Rc::clone(&state), callback);
    let server = std::ffi::CString::new("192.0.2.1:53").expect("server endpoint");
    // SAFETY: slot and server are live for the entire notification; the raw
    // pointer borrows the exact persistent slot type and transfers no ownership.
    unsafe {
        callbacks::server_state_trampoline::<Callback>(
            server.as_ptr(),
            sys::ARES_TRUE,
            0x4001,
            Rc::as_ptr(&slot).cast_mut().cast(),
        );
    }
    drop(server);
    let saved = output.borrow_mut().take().expect("server notification");
    assert_eq!(saved.server.as_deref(), Some("192.0.2.1:53"));
    assert_eq!(saved.flags.bits(), 0x4001);
    // SAFETY: the slot remains live; a null server pointer is permitted by the
    // trampoline and the failing notification exercises its unwind boundary.
    unsafe {
        callbacks::server_state_trampoline::<Callback>(
            std::ptr::null(),
            sys::ARES_FALSE,
            0,
            Rc::as_ptr(&slot).cast_mut().cast(),
        );
    }
    assert!(state.is_poisoned());
    assert!(state.take_panic().is_some());
    assert_eq!(state.depth(), 0);
}
