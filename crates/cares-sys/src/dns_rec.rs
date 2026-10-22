//! Modern strongly typed DNS record creation, parsing and mutation APIs.

use libc::{c_char, c_uint, c_void};

use crate::*;

unsafe extern "C" {
    /// # Safety
    /// Any non-null returned name is static read-only storage and must not be freed or modified.
    pub fn ares_dns_rec_type_tostr(r#type: ares_dns_rec_type_t) -> *const c_char;
    /// # Safety
    /// Any non-null returned name is static read-only storage and must not be freed or modified.
    pub fn ares_dns_class_tostr(qclass: ares_dns_class_t) -> *const c_char;
    /// # Safety
    /// Any non-null returned name is static read-only storage and must not be freed or modified.
    pub fn ares_dns_opcode_tostr(opcode: ares_dns_opcode_t) -> *const c_char;
    /// # Safety
    /// Any non-null returned name is static read-only storage and must not be freed or modified.
    pub fn ares_dns_rr_key_tostr(key: ares_dns_rr_key_t) -> *const c_char;
    /// # Safety
    /// Any non-null returned name is static read-only storage and must not be freed or modified.
    pub fn ares_dns_section_tostr(section: ares_dns_section_t) -> *const c_char;
    /// # Safety
    /// qclass must be writable and str must be a readable NUL-terminated class name.
    pub fn ares_dns_class_fromstr(
        qclass: *mut ares_dns_class_t,
        r#str: *const c_char,
    ) -> ares_bool_t;
    /// # Safety
    /// qtype must be writable and str must be a readable NUL-terminated record type name.
    pub fn ares_dns_rec_type_fromstr(
        qtype: *mut ares_dns_rec_type_t,
        r#str: *const c_char,
    ) -> ares_bool_t;
    /// # Safety
    /// Any non-null returned name is static read-only storage and must not be freed or modified.
    pub fn ares_dns_rcode_tostr(rcode: ares_dns_rcode_t) -> *const c_char;
    /// # Safety
    /// ipaddr must be NUL-terminated and addr initialized with a valid family. addr and out_len
    /// must be writable. Any result borrows address storage inside addr.
    pub fn ares_dns_pton(
        ipaddr: *const c_char,
        addr: *mut ares_addr,
        out_len: *mut usize,
    ) -> *const c_void;
    /// # Safety
    /// addr must be readable and initialized for its family. A non-null returned string is owned
    /// and must be released once with ares_free_string.
    pub fn ares_dns_addr_to_ptr(addr: *const ares_addr) -> *mut c_char;
    /// # Safety
    /// Only integer value inputs are used; no pointer or ownership prerequisites apply.
    pub fn ares_dns_opt_get_datatype(key: ares_dns_rr_key_t, opt: u16) -> ares_dns_opt_datatype_t;
    /// # Safety
    /// Any non-null returned name is static read-only storage and must not be freed or modified.
    pub fn ares_dns_opt_get_name(key: ares_dns_rr_key_t, opt: u16) -> *const c_char;
    /// # Safety
    /// cnt must be writable. The returned key array is static storage; read only its reported
    /// length and never free or modify it.
    pub fn ares_dns_rr_get_keys(
        r#type: ares_dns_rec_type_t,
        cnt: *mut usize,
    ) -> *const ares_dns_rr_key_t;
    /// # Safety
    /// Only integer value inputs are used; no pointer or ownership prerequisites apply.
    pub fn ares_dns_rr_key_datatype(key: ares_dns_rr_key_t) -> ares_dns_datatype_t;
    /// # Safety
    /// Only integer value inputs are used; no pointer or ownership prerequisites apply.
    pub fn ares_dns_rr_key_to_rec_type(key: ares_dns_rr_key_t) -> ares_dns_rec_type_t;
    /// # Safety
    /// dnsrec must be writable. On success the returned record is exclusively owned and must be
    /// destroyed once with ares_dns_record_destroy.
    pub fn ares_dns_record_create(
        dnsrec: *mut *mut ares_dns_record_t,
        id: u16,
        flags: u16,
        opcode: ares_dns_opcode_t,
        rcode: ares_dns_rcode_t,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be null or a live exclusively owned record. Invalidate every borrowed question,
    /// RR, string, and binary slice before destroying it.
    pub fn ares_dns_record_destroy(dnsrec: *mut ares_dns_record_t);
    /// # Safety
    /// dnsrec must be a readable live record; do not race access with mutation or destruction.
    pub fn ares_dns_record_get_id(dnsrec: *const ares_dns_record_t) -> u16;
    /// # Safety
    /// dnsrec must be a live record with exclusive access during mutation.
    pub fn ares_dns_record_set_id(dnsrec: *mut ares_dns_record_t, id: u16) -> ares_bool_t;
    /// # Safety
    /// dnsrec must be a readable live record; do not race access with mutation or destruction.
    pub fn ares_dns_record_get_flags(dnsrec: *const ares_dns_record_t) -> u16;
    /// # Safety
    /// dnsrec must be a readable live record; do not race access with mutation or destruction.
    pub fn ares_dns_record_get_opcode(dnsrec: *const ares_dns_record_t) -> ares_dns_opcode_t;
    /// # Safety
    /// dnsrec must be a readable live record; do not race access with mutation or destruction.
    pub fn ares_dns_record_get_rcode(dnsrec: *const ares_dns_record_t) -> ares_dns_rcode_t;
    /// # Safety
    /// dnsrec must be live and exclusively accessible; name must be NUL-terminated. Mutation may
    /// invalidate borrowed question data.
    pub fn ares_dns_record_query_add(
        dnsrec: *mut ares_dns_record_t,
        name: *const c_char,
        qtype: ares_dns_rec_type_t,
        qclass: ares_dns_class_t,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be live and exclusively accessible; name must be NUL-terminated. Do not retain
    /// a previous borrowed question name across this mutation.
    pub fn ares_dns_record_query_set_name(
        dnsrec: *mut ares_dns_record_t,
        idx: usize,
        name: *const c_char,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be live and exclusively accessible. Existing question borrows must not overlap
    /// this mutation.
    pub fn ares_dns_record_query_set_type(
        dnsrec: *mut ares_dns_record_t,
        idx: usize,
        qtype: ares_dns_rec_type_t,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be a readable live record; do not race access with mutation or destruction.
    pub fn ares_dns_record_query_cnt(dnsrec: *const ares_dns_record_t) -> usize;
    /// # Safety
    /// dnsrec must be live. Each non-null output slot must be writable; a returned name borrows
    /// the record and must not outlive its next relevant mutation or destruction.
    pub fn ares_dns_record_query_get(
        dnsrec: *const ares_dns_record_t,
        idx: usize,
        name: *mut *const c_char,
        qtype: *mut ares_dns_rec_type_t,
        qclass: *mut ares_dns_class_t,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be a readable live record; do not race access with mutation or destruction.
    pub fn ares_dns_record_rr_cnt(
        dnsrec: *const ares_dns_record_t,
        sect: ares_dns_section_t,
    ) -> usize;
    /// # Safety
    /// dnsrec must be live and exclusively accessible; rr_out must be writable and name NUL-
    /// terminated. The returned RR borrows its parent section and is invalidated by section
    /// addition/deletion or parent destruction.
    pub fn ares_dns_record_rr_add(
        rr_out: *mut *mut ares_dns_rr_t,
        dnsrec: *mut ares_dns_record_t,
        sect: ares_dns_section_t,
        name: *const c_char,
        r#type: ares_dns_rec_type_t,
        rclass: ares_dns_class_t,
        ttl: c_uint,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be live. The returned RR borrows the parent section; do not overlap mutable
    /// access or retain it across section addition/deletion or parent destruction.
    pub fn ares_dns_record_rr_get(
        dnsrec: *mut ares_dns_record_t,
        sect: ares_dns_section_t,
        idx: usize,
    ) -> *mut ares_dns_rr_t;
    /// # Safety
    /// dnsrec must be live. The returned RR borrows the parent section; do not retain it across
    /// section addition/deletion or parent destruction.
    pub fn ares_dns_record_rr_get_const(
        dnsrec: *const ares_dns_record_t,
        sect: ares_dns_section_t,
        idx: usize,
    ) -> *const ares_dns_rr_t;
    /// # Safety
    /// dnsrec must be live and exclusively accessible. All RR pointers borrowed from the affected
    /// section are invalidated.
    pub fn ares_dns_record_rr_del(
        dnsrec: *mut ares_dns_record_t,
        sect: ares_dns_section_t,
        idx: usize,
    ) -> ares_status_t;
    /// # Safety
    /// The RR and its parent must remain live. A non-null result borrows the RR and must not be
    /// modified, freed, or retained across relevant mutation or parent destruction.
    pub fn ares_dns_rr_get_name(rr: *const ares_dns_rr_t) -> *const c_char;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_type(rr: *const ares_dns_rr_t) -> ares_dns_rec_type_t;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_class(rr: *const ares_dns_rr_t) -> ares_dns_class_t;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_ttl(rr: *const ares_dns_rr_t) -> c_uint;
    /// # Safety
    /// dns_rr must be live with exclusive access and key must select an IPv4 field. addr must hold
    /// a readable in_addr; do not retain previous borrows of changed data.
    pub fn ares_dns_rr_set_addr(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        addr: *const libc::in_addr,
    ) -> ares_status_t;
    /// # Safety
    /// dns_rr must be live with exclusive access and key must select an IPv6 field. addr must hold
    /// a readable ares_in6_addr; release previous borrows of changed data.
    pub fn ares_dns_rr_set_addr6(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        addr: *const ares_in6_addr,
    ) -> ares_status_t;
    /// # Safety
    /// dns_rr must be live with exclusive access and key must select a string/name field. val must
    /// be NUL-terminated; mutation invalidates prior borrows of that field.
    pub fn ares_dns_rr_set_str(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: *const c_char,
    ) -> ares_status_t;
    /// # Safety
    /// The RR and its parent must remain live with exclusive access. Use a key matching the field
    /// datatype; mutation may invalidate existing field borrows.
    pub fn ares_dns_rr_set_u8(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: u8,
    ) -> ares_status_t;
    /// # Safety
    /// The RR and its parent must remain live with exclusive access. Use a key matching the field
    /// datatype; mutation may invalidate existing field borrows.
    pub fn ares_dns_rr_set_u16(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: u16,
    ) -> ares_status_t;
    /// # Safety
    /// The RR and its parent must remain live with exclusive access. Use a key matching the field
    /// datatype; mutation may invalidate existing field borrows.
    pub fn ares_dns_rr_set_u32(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: c_uint,
    ) -> ares_status_t;
    /// # Safety
    /// dns_rr must be live with exclusive access and key must select a binary field. val must
    /// cover len readable bytes, unless len is zero and val is null. Mutation invalidates prior
    /// field borrows.
    pub fn ares_dns_rr_set_bin(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: *const u8,
        len: usize,
    ) -> ares_status_t;
    /// # Safety
    /// dns_rr must be live with exclusive access and key must select a binary-array field. val
    /// must cover len readable bytes, unless len is zero and val is null; array borrows may be
    /// invalidated.
    pub fn ares_dns_rr_add_abin(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        val: *const u8,
        len: usize,
    ) -> ares_status_t;
    /// # Safety
    /// The RR and its parent must remain live with exclusive access. Use a key matching the field
    /// datatype; mutation may invalidate existing field borrows.
    pub fn ares_dns_rr_del_abin(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        idx: usize,
    ) -> ares_status_t;
    /// # Safety
    /// dns_rr must be live with exclusive access and key must select options. val must cover
    /// val_len readable bytes, unless the length is zero and val is null. Mutation may invalidate
    /// borrowed option data.
    pub fn ares_dns_rr_set_opt(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        opt: u16,
        val: *const u8,
        val_len: usize,
    ) -> ares_status_t;
    /// # Safety
    /// The RR and its parent must remain live with exclusive access. Use a key matching the field
    /// datatype; mutation may invalidate existing field borrows.
    pub fn ares_dns_rr_del_opt_byid(
        dns_rr: *mut ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        opt: u16,
    ) -> ares_status_t;
    /// # Safety
    /// The RR and its parent must remain live. A non-null result borrows the RR and must not be
    /// modified, freed, or retained across relevant mutation or parent destruction.
    pub fn ares_dns_rr_get_addr(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
    ) -> *const libc::in_addr;
    /// # Safety
    /// The RR and its parent must remain live. A non-null result borrows the RR and must not be
    /// modified, freed, or retained across relevant mutation or parent destruction.
    pub fn ares_dns_rr_get_addr6(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
    ) -> *const ares_in6_addr;
    /// # Safety
    /// The RR and its parent must remain live. A non-null result borrows the RR and must not be
    /// modified, freed, or retained across relevant mutation or parent destruction.
    pub fn ares_dns_rr_get_str(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
    ) -> *const c_char;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_u8(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> u8;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_u16(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> u16;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_u32(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> c_uint;
    /// # Safety
    /// dns_rr must be live, key must select binary data, and len must be writable. A non-null
    /// result borrows the RR for the reported length until relevant mutation or destruction.
    pub fn ares_dns_rr_get_bin(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        len: *mut usize,
    ) -> *const u8;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_abin_cnt(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> usize;
    /// # Safety
    /// dns_rr must be live, key must select a binary array, and len must be writable. A non-null
    /// result borrows the RR for the reported length until array mutation or destruction.
    pub fn ares_dns_rr_get_abin(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        idx: usize,
        len: *mut usize,
    ) -> *const u8;
    /// # Safety
    /// The RR and its parent must remain live and readable; do not overlap access with mutation or
    /// destruction.
    pub fn ares_dns_rr_get_opt_cnt(dns_rr: *const ares_dns_rr_t, key: ares_dns_rr_key_t) -> usize;
    /// # Safety
    /// dns_rr must be live and key must select options. Non-null val and val_len output slots must
    /// be writable; a returned value borrows the RR until relevant mutation or destruction.
    pub fn ares_dns_rr_get_opt(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        idx: usize,
        val: *mut *const u8,
        val_len: *mut usize,
    ) -> u16;
    /// # Safety
    /// dns_rr must be live and key must select options. Non-null val and val_len output slots must
    /// be writable; a returned value borrows the RR until relevant mutation or destruction.
    pub fn ares_dns_rr_get_opt_byid(
        dns_rr: *const ares_dns_rr_t,
        key: ares_dns_rr_key_t,
        opt: u16,
        val: *mut *const u8,
        val_len: *mut usize,
    ) -> ares_bool_t;
    /// # Safety
    /// buf must cover buf_len readable bytes and dnsrec must be writable. A successfully returned
    /// record is owned and must be destroyed once with ares_dns_record_destroy.
    pub fn ares_dns_parse(
        buf: *const u8,
        buf_len: usize,
        flags: c_uint,
        dnsrec: *mut *mut ares_dns_record_t,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be live; buf and buf_len must be writable output slots. A successfully returned
    /// wire buffer is owned and must be freed once with ares_free_string.
    pub fn ares_dns_write(
        dnsrec: *const ares_dns_record_t,
        buf: *mut *mut u8,
        buf_len: *mut usize,
    ) -> ares_status_t;
    /// # Safety
    /// dnsrec must be null or a readable live record. Any non-null result is independently owned
    /// and must be destroyed once with ares_dns_record_destroy.
    pub fn ares_dns_record_duplicate(dnsrec: *const ares_dns_record_t) -> *mut ares_dns_record_t;
}
