//! Modern strongly typed DNS record creation, parsing and mutation APIs.

use libc::{c_char, c_uint, c_void};

use crate::*;

unsafe extern "C" {
    pub fn ares_dns_rec_type_tostr(r#type: ares_dns_rec_type_t) -> *const c_char;
    pub fn ares_dns_class_tostr(qclass: ares_dns_class_t) -> *const c_char;
    pub fn ares_dns_opcode_tostr(opcode: ares_dns_opcode_t) -> *const c_char;
    pub fn ares_dns_rr_key_tostr(key: ares_dns_rr_key_t) -> *const c_char;
    pub fn ares_dns_section_tostr(section: ares_dns_section_t) -> *const c_char;
    pub fn ares_dns_class_fromstr(
        qclass: *mut ares_dns_class_t,
        r#str: *const c_char,
    ) -> ares_bool_t;
    pub fn ares_dns_rec_type_fromstr(
        qtype: *mut ares_dns_rec_type_t,
        r#str: *const c_char,
    ) -> ares_bool_t;
    pub fn ares_dns_rcode_tostr(rcode: ares_dns_rcode_t) -> *const c_char;
    pub fn ares_dns_pton(
        ipaddr: *const c_char,
        addr: *mut ares_addr,
        out_len: *mut usize,
    ) -> *const c_void;
    pub fn ares_dns_addr_to_ptr(addr: *const ares_addr) -> *mut c_char;
    pub fn ares_dns_opt_get_datatype(key: ares_dns_rr_key_t, opt: u16) -> ares_dns_opt_datatype_t;
    pub fn ares_dns_opt_get_name(key: ares_dns_rr_key_t, opt: u16) -> *const c_char;
    pub fn ares_dns_rr_get_keys(
        r#type: ares_dns_rec_type_t,
        cnt: *mut usize,
    ) -> *const ares_dns_rr_key_t;
    pub fn ares_dns_rr_key_datatype(key: ares_dns_rr_key_t) -> ares_dns_datatype_t;
    pub fn ares_dns_rr_key_to_rec_type(key: ares_dns_rr_key_t) -> ares_dns_rec_type_t;
    pub fn ares_dns_record_create(
        dnsrec: *mut *mut ares_dns_record_t,
        id: u16,
        flags: u16,
        opcode: ares_dns_opcode_t,
        rcode: ares_dns_rcode_t,
    ) -> ares_status_t;
    pub fn ares_dns_record_destroy(dnsrec: *mut ares_dns_record_t);
    pub fn ares_dns_record_get_id(dnsrec: *const ares_dns_record_t) -> u16;
    pub fn ares_dns_record_set_id(dnsrec: *mut ares_dns_record_t, id: u16) -> ares_bool_t;
    pub fn ares_dns_record_get_flags(dnsrec: *const ares_dns_record_t) -> u16;
    pub fn ares_dns_record_get_opcode(dnsrec: *const ares_dns_record_t) -> ares_dns_opcode_t;
    pub fn ares_dns_record_get_rcode(dnsrec: *const ares_dns_record_t) -> ares_dns_rcode_t;
    pub fn ares_dns_record_query_add(
        dnsrec: *mut ares_dns_record_t,
        name: *const c_char,
        qtype: ares_dns_rec_type_t,
        qclass: ares_dns_class_t,
    ) -> ares_status_t;
    pub fn ares_dns_record_query_set_name(
        dnsrec: *mut ares_dns_record_t,
        idx: usize,
        name: *const c_char,
    ) -> ares_status_t;
    pub fn ares_dns_record_query_set_type(
        dnsrec: *mut ares_dns_record_t,
        idx: usize,
        qtype: ares_dns_rec_type_t,
    ) -> ares_status_t;
    pub fn ares_dns_record_query_cnt(dnsrec: *const ares_dns_record_t) -> usize;
    pub fn ares_dns_record_query_get(
        dnsrec: *const ares_dns_record_t,
        idx: usize,
        name: *mut *const c_char,
        qtype: *mut ares_dns_rec_type_t,
        qclass: *mut ares_dns_class_t,
    ) -> ares_status_t;
    pub fn ares_dns_record_rr_cnt(
        dnsrec: *const ares_dns_record_t,
        sect: ares_dns_section_t,
    ) -> usize;
    pub fn ares_dns_record_rr_add(
        rr_out: *mut *mut ares_dns_rr_t,
        dnsrec: *mut ares_dns_record_t,
        sect: ares_dns_section_t,
        name: *const c_char,
        r#type: ares_dns_rec_type_t,
        rclass: ares_dns_class_t,
        ttl: c_uint,
    ) -> ares_status_t;
    pub fn ares_dns_record_rr_get(
        dnsrec: *mut ares_dns_record_t,
        sect: ares_dns_section_t,
        idx: usize,
    ) -> *mut ares_dns_rr_t;
    pub fn ares_dns_record_rr_get_const(
        dnsrec: *const ares_dns_record_t,
        sect: ares_dns_section_t,
        idx: usize,
    ) -> *const ares_dns_rr_t;
    pub fn ares_dns_record_rr_del(
        dnsrec: *mut ares_dns_record_t,
        sect: ares_dns_section_t,
        idx: usize,
    ) -> ares_status_t;
    pub fn ares_dns_rr_get_name(rr: *const ares_dns_rr_t) -> *const c_char;
    pub fn ares_dns_rr_get_type(rr: *const ares_dns_rr_t) -> ares_dns_rec_type_t;
    pub fn ares_dns_rr_get_class(rr: *const ares_dns_rr_t) -> ares_dns_class_t;
    pub fn ares_dns_rr_get_ttl(rr: *const ares_dns_rr_t) -> c_uint;
    pub fn ares_dns_rr_set_addr(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        addr: *const libc::in_addr,
    ) -> ares_status_t;
    pub fn ares_dns_rr_set_addr6(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        addr: *const ares_in6_addr,
    ) -> ares_status_t;
    pub fn ares_dns_rr_set_str(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: *const c_char,
    ) -> ares_status_t;
    pub fn ares_dns_rr_set_u8(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: u8,
    ) -> ares_status_t;
    pub fn ares_dns_rr_set_u16(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: u16,
    ) -> ares_status_t;
    pub fn ares_dns_rr_set_u32(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: c_uint,
    ) -> ares_status_t;
    pub fn ares_dns_rr_set_bin(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: *const u8,
        len: usize,
    ) -> ares_status_t;
    pub fn ares_dns_rr_add_abin(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: *const u8,
        len: usize,
    ) -> ares_status_t;
    pub fn ares_dns_rr_del_abin(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        idx: usize,
    ) -> ares_status_t;
    pub fn ares_dns_rr_set_opt(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        opt: u16,
        val: *const u8,
        val_len: usize,
    ) -> ares_status_t;
    pub fn ares_dns_rr_del_opt_byid(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        opt: u16,
    ) -> ares_status_t;
    pub fn ares_dns_rr_get_addr(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
    ) -> *const libc::in_addr;
    pub fn ares_dns_rr_get_addr6(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
    ) -> *const ares_in6_addr;
    pub fn ares_dns_rr_get_str(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
    ) -> *const c_char;
    pub fn ares_dns_rr_get_u8(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> u8;
    pub fn ares_dns_rr_get_u16(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> u16;
    pub fn ares_dns_rr_get_u32(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> c_uint;
    pub fn ares_dns_rr_get_bin(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        len: *mut usize,
    ) -> *const u8;
    pub fn ares_dns_rr_get_abin_cnt(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> usize;
    pub fn ares_dns_rr_get_abin(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        idx: usize,
        len: *mut usize,
    ) -> *const u8;
    pub fn ares_dns_rr_get_opt_cnt(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> usize;
    pub fn ares_dns_rr_get_opt(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        idx: usize,
        val: *mut *const u8,
        val_len: *mut usize,
    ) -> u16;
    pub fn ares_dns_rr_get_opt_byid(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        opt: u16,
        val: *mut *const u8,
        val_len: *mut usize,
    ) -> ares_bool_t;
    pub fn ares_dns_parse(
        buf: *const u8,
        buf_len: usize,
        flags: c_uint,
        dnsrec: *mut *mut ares_dns_record_t,
    ) -> ares_status_t;
    pub fn ares_dns_write(
        dnsrec: *const ares_dns_record_t,
        buf: *mut *mut u8,
        buf_len: *mut usize,
    ) -> ares_status_t;
    pub fn ares_dns_record_duplicate(dnsrec: *const ares_dns_record_t) -> *mut ares_dns_record_t;
}
