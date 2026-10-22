use std::{ffi::CStr, ptr};

use cares_sys::*;

#[path = "support/abi_values.rs"]
mod abi_values;

unsafe extern "C" {
    fn cares_sys_abi_probe(index: usize) -> usize;
}

#[test]
fn layouts_and_constants_match_selected_c_headers() {
    let expected = abi_values::expected();
    // SAFETY: The C probe has no pointer arguments and accepts every index.
    assert_eq!(unsafe { cares_sys_abi_probe(usize::MAX) }, expected.len());
    for (index, (label, value)) in expected.into_iter().enumerate() {
        // SAFETY: Every index is within the C probe's static values array.
        assert_eq!(unsafe { cares_sys_abi_probe(index) }, value, "{label}");
    }
}

#[test]
fn static_library_has_no_thread_support() {
    // SAFETY: The capability query takes no arguments or library state.
    assert_eq!(unsafe { ares_threadsafety() }, ARES_FALSE);
}

struct Record(*mut ares_dns_record_t);

impl Drop for Record {
    fn drop(&mut self) {
        // SAFETY: Each Record exclusively owns one live c-ares DNS record.
        unsafe { ares_dns_record_destroy(self.0) };
    }
}

struct Wire(*mut u8, usize);

impl Drop for Wire {
    fn drop(&mut self) {
        // SAFETY: The buffer was allocated by ares_dns_write and is freed once.
        unsafe { ares_free_string(self.0.cast()) };
    }
}

#[test]
fn dns_record_survives_write_parse_and_duplicate() {
    // SAFETY: Output slots are writable; all inputs remain live for each call.
    // Returned RR pointers are used before any further addition to their section.
    // Record and Wire guards release each allocation with its matching C allocator.
    unsafe {
        let mut raw = ptr::null_mut();
        let flags = (ARES_FLAG_QR.0 | ARES_FLAG_RD.0 | ARES_FLAG_RA.0) as u16;
        assert_eq!(
            ares_dns_record_create(
                &mut raw,
                0x4a21,
                flags,
                ARES_OPCODE_QUERY,
                ARES_RCODE_NOERROR
            ),
            ARES_SUCCESS
        );
        assert!(!raw.is_null());
        let original = Record(raw);
        assert_eq!(
            ares_dns_record_query_add(
                original.0,
                c"example.test".as_ptr(),
                ARES_REC_TYPE_A,
                ARES_CLASS_IN
            ),
            ARES_SUCCESS
        );
        let mut rr = ptr::null_mut();
        assert_eq!(
            ares_dns_record_rr_add(
                &mut rr,
                original.0,
                ARES_SECTION_ANSWER,
                c"example.test".as_ptr(),
                ARES_REC_TYPE_A,
                ARES_CLASS_IN,
                300
            ),
            ARES_SUCCESS
        );
        let address = libc::in_addr {
            s_addr: u32::from_ne_bytes([192, 0, 2, 42]),
        };
        assert_eq!(
            ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &address),
            ARES_SUCCESS
        );

        // OPT stores its wire class as the dedicated UDP payload size field.
        assert_eq!(
            ares_dns_record_rr_add(
                &mut rr,
                original.0,
                ARES_SECTION_ADDITIONAL,
                c"".as_ptr(),
                ARES_REC_TYPE_OPT,
                ARES_CLASS_IN,
                0
            ),
            ARES_SUCCESS
        );
        assert_eq!(
            ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, 4096),
            ARES_SUCCESS
        );
        let mut bytes = ptr::null_mut();
        let mut len = 0;
        assert_eq!(
            ares_dns_write(original.0, &mut bytes, &mut len),
            ARES_SUCCESS
        );
        assert!(!bytes.is_null());
        let wire = Wire(bytes, len);
        assert!(wire.1 >= 12);
        assert_eq!(std::slice::from_raw_parts(wire.0, 2), &[0x4a, 0x21]);

        let mut parsed = ptr::null_mut();
        assert_eq!(ares_dns_parse(wire.0, wire.1, 0, &mut parsed), ARES_SUCCESS);
        assert!(!parsed.is_null());
        let parsed = Record(parsed);
        let copied = ares_dns_record_duplicate(parsed.0);
        assert!(!copied.is_null());
        let copied = Record(copied);
        drop(parsed);
        drop(original);

        assert_eq!(ares_dns_record_get_id(copied.0), 0x4a21);
        assert_eq!(ares_dns_record_get_flags(copied.0), flags);
        assert_eq!(ares_dns_record_get_opcode(copied.0), ARES_OPCODE_QUERY);
        assert_eq!(ares_dns_record_get_rcode(copied.0), ARES_RCODE_NOERROR);
        assert_eq!(ares_dns_record_query_cnt(copied.0), 1);
        let mut name = ptr::null();
        let mut kind = ARES_REC_TYPE_ANY;
        let mut class = ARES_CLASS_ANY;
        assert_eq!(
            ares_dns_record_query_get(copied.0, 0, &mut name, &mut kind, &mut class),
            ARES_SUCCESS
        );
        assert_eq!(CStr::from_ptr(name), c"example.test");
        assert_eq!(kind, ARES_REC_TYPE_A);
        assert_eq!(class, ARES_CLASS_IN);
        assert_eq!(ares_dns_record_rr_cnt(copied.0, ARES_SECTION_ANSWER), 1);
        let answer = ares_dns_record_rr_get_const(copied.0, ARES_SECTION_ANSWER, 0);
        assert!(!answer.is_null());
        assert_eq!(
            CStr::from_ptr(ares_dns_rr_get_name(answer)),
            c"example.test"
        );
        assert_eq!(ares_dns_rr_get_type(answer), ARES_REC_TYPE_A);
        assert_eq!(ares_dns_rr_get_class(answer), ARES_CLASS_IN);
        assert_eq!(ares_dns_rr_get_ttl(answer), 300);
        let decoded = ares_dns_rr_get_addr(answer, ARES_RR_A_ADDR);
        assert!(!decoded.is_null());
        assert_eq!((*decoded).s_addr.to_ne_bytes(), [192, 0, 2, 42]);
        let opt = ares_dns_record_rr_get_const(copied.0, ARES_SECTION_ADDITIONAL, 0);
        assert!(!opt.is_null());
        assert_eq!(ares_dns_rr_get_u16(opt, ARES_RR_OPT_UDP_SIZE), 4096);
    }
}

#[test]
fn required_symbols_link_to_static_library() {
    let symbols = [
        ("ares_library_init", ares_library_init as *const ()),
        ("ares_library_cleanup", ares_library_cleanup as *const ()),
        ("ares_threadsafety", ares_threadsafety as *const ()),
        ("ares_init_options", ares_init_options as *const ()),
        ("ares_destroy", ares_destroy as *const ()),
        ("ares_reinit", ares_reinit as *const ()),
        ("ares_dup", ares_dup as *const ()),
        ("ares_cancel", ares_cancel as *const ()),
        ("ares_set_servers_csv", ares_set_servers_csv as *const ()),
        (
            "ares_set_servers_ports_csv",
            ares_set_servers_ports_csv as *const (),
        ),
        ("ares_get_servers_csv", ares_get_servers_csv as *const ()),
        ("ares_set_local_ip4", ares_set_local_ip4 as *const ()),
        ("ares_set_local_ip6", ares_set_local_ip6 as *const ()),
        ("ares_set_local_dev", ares_set_local_dev as *const ()),
        (
            "ares_set_socket_functions_ex",
            ares_set_socket_functions_ex as *const (),
        ),
        (
            "ares_set_server_state_callback",
            ares_set_server_state_callback as *const (),
        ),
        ("ares_process_fds", ares_process_fds as *const ()),
        ("ares_process_fd", ares_process_fd as *const ()),
        ("ares_timeout", ares_timeout as *const ()),
        ("ares_fds", ares_fds as *const ()),
        ("ares_strerror", ares_strerror as *const ()),
        ("ares_version", ares_version as *const ()),
        ("ares_free_data", ares_free_data as *const ()),
        ("ares_free_string", ares_free_string as *const ()),
        ("ares_free_hostent", ares_free_hostent as *const ()),
        ("ares_query_dnsrec", ares_query_dnsrec as *const ()),
        ("ares_send_dnsrec", ares_send_dnsrec as *const ()),
        (
            "ares_dns_record_create",
            ares_dns_record_create as *const (),
        ),
        (
            "ares_dns_record_destroy",
            ares_dns_record_destroy as *const (),
        ),
        (
            "ares_dns_record_duplicate",
            ares_dns_record_duplicate as *const (),
        ),
        (
            "ares_dns_record_get_id",
            ares_dns_record_get_id as *const (),
        ),
        (
            "ares_dns_record_get_flags",
            ares_dns_record_get_flags as *const (),
        ),
        (
            "ares_dns_record_get_opcode",
            ares_dns_record_get_opcode as *const (),
        ),
        (
            "ares_dns_record_get_rcode",
            ares_dns_record_get_rcode as *const (),
        ),
        (
            "ares_dns_record_query_add",
            ares_dns_record_query_add as *const (),
        ),
        (
            "ares_dns_record_query_cnt",
            ares_dns_record_query_cnt as *const (),
        ),
        (
            "ares_dns_record_query_get",
            ares_dns_record_query_get as *const (),
        ),
        (
            "ares_dns_record_rr_add",
            ares_dns_record_rr_add as *const (),
        ),
        (
            "ares_dns_record_rr_cnt",
            ares_dns_record_rr_cnt as *const (),
        ),
        (
            "ares_dns_record_rr_get",
            ares_dns_record_rr_get as *const (),
        ),
        (
            "ares_dns_record_rr_get_const",
            ares_dns_record_rr_get_const as *const (),
        ),
        ("ares_dns_rr_get_name", ares_dns_rr_get_name as *const ()),
        ("ares_dns_rr_get_type", ares_dns_rr_get_type as *const ()),
        ("ares_dns_rr_get_class", ares_dns_rr_get_class as *const ()),
        ("ares_dns_rr_get_ttl", ares_dns_rr_get_ttl as *const ()),
        ("ares_dns_rr_get_addr", ares_dns_rr_get_addr as *const ()),
        ("ares_dns_rr_get_addr6", ares_dns_rr_get_addr6 as *const ()),
        ("ares_dns_rr_get_str", ares_dns_rr_get_str as *const ()),
        ("ares_dns_rr_get_u8", ares_dns_rr_get_u8 as *const ()),
        ("ares_dns_rr_get_u16", ares_dns_rr_get_u16 as *const ()),
        ("ares_dns_rr_get_u32", ares_dns_rr_get_u32 as *const ()),
        ("ares_dns_rr_get_bin", ares_dns_rr_get_bin as *const ()),
        (
            "ares_dns_rr_get_abin_cnt",
            ares_dns_rr_get_abin_cnt as *const (),
        ),
        ("ares_dns_rr_get_abin", ares_dns_rr_get_abin as *const ()),
        (
            "ares_dns_rr_get_opt_cnt",
            ares_dns_rr_get_opt_cnt as *const (),
        ),
        ("ares_dns_rr_get_opt", ares_dns_rr_get_opt as *const ()),
        (
            "ares_dns_rr_get_opt_byid",
            ares_dns_rr_get_opt_byid as *const (),
        ),
        ("ares_dns_rr_set_addr", ares_dns_rr_set_addr as *const ()),
        ("ares_dns_rr_set_addr6", ares_dns_rr_set_addr6 as *const ()),
        ("ares_dns_rr_set_str", ares_dns_rr_set_str as *const ()),
        ("ares_dns_rr_set_u8", ares_dns_rr_set_u8 as *const ()),
        ("ares_dns_rr_set_u16", ares_dns_rr_set_u16 as *const ()),
        ("ares_dns_rr_set_u32", ares_dns_rr_set_u32 as *const ()),
        ("ares_dns_rr_set_bin", ares_dns_rr_set_bin as *const ()),
        ("ares_dns_rr_add_abin", ares_dns_rr_add_abin as *const ()),
        ("ares_dns_rr_set_opt", ares_dns_rr_set_opt as *const ()),
        ("ares_dns_parse", ares_dns_parse as *const ()),
        ("ares_dns_write", ares_dns_write as *const ()),
        ("ares_gethostbyname", ares_gethostbyname as *const ()),
        ("ares_gethostbyaddr", ares_gethostbyaddr as *const ()),
        ("ares_getnameinfo", ares_getnameinfo as *const ()),
    ];
    for (name, address) in symbols {
        assert!(!std::hint::black_box(address).is_null(), "{name}");
    }
}

#[test]
fn unknown_wire_class_remains_representable() {
    // SAFETY: All inputs and writable output slots live for each call; Record
    // and Wire own returned allocations, and RR borrows stay within the record.
    unsafe {
        let mut raw = ptr::null_mut();
        assert_eq!(
            ares_dns_record_create(
                &mut raw,
                1,
                ARES_FLAG_QR.0 as u16,
                ARES_OPCODE_QUERY,
                ARES_RCODE_NOERROR
            ),
            ARES_SUCCESS
        );
        let record = Record(raw);
        assert_eq!(
            ares_dns_record_query_add(
                record.0,
                c"example.test".as_ptr(),
                ARES_REC_TYPE_A,
                ARES_CLASS_IN
            ),
            ARES_SUCCESS
        );
        let mut rr = ptr::null_mut();
        assert_eq!(
            ares_dns_record_rr_add(
                &mut rr,
                record.0,
                ARES_SECTION_ANSWER,
                c"example.test".as_ptr(),
                ARES_REC_TYPE_RAW_RR,
                ares_dns_class_t(65000),
                60
            ),
            ARES_SUCCESS
        );
        assert_eq!(
            ares_dns_rr_set_u16(rr, ARES_RR_RAW_RR_TYPE, 65001),
            ARES_SUCCESS
        );
        let data = [1, 2, 3];
        assert_eq!(
            ares_dns_rr_set_bin(rr, ARES_RR_RAW_RR_DATA, data.as_ptr(), data.len()),
            ARES_SUCCESS
        );
        let mut bytes = ptr::null_mut();
        let mut len = 0;
        assert_eq!(ares_dns_write(record.0, &mut bytes, &mut len), ARES_SUCCESS);
        let wire = Wire(bytes, len);
        let mut parsed = ptr::null_mut();
        assert_eq!(ares_dns_parse(wire.0, wire.1, 0, &mut parsed), ARES_SUCCESS);
        let parsed = Record(parsed);
        let rr = ares_dns_record_rr_get_const(parsed.0, ARES_SECTION_ANSWER, 0);
        assert!(!rr.is_null());
        assert_eq!(ares_dns_rr_get_class(rr).0, 65000);
        assert_eq!(ares_dns_rr_get_type(rr), ARES_REC_TYPE_RAW_RR);
        assert_eq!(ares_dns_rr_get_u16(rr, ARES_RR_RAW_RR_TYPE), 65001);
    }
}
