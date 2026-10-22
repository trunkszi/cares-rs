//! Owned DNS messages and callback-scoped views backed by c-ares.

use std::{
    ffi::{CStr, CString},
    marker::PhantomData,
    ptr::{self, NonNull},
    rc::Rc,
};

use cares_sys as sys;

use crate::{
    error::{AresError, Result},
    record_rr::{DnsRr, DnsRrMut, FromDnsRr, IntoDnsRr},
    types::{DnsClass, DnsFlags, DnsOpcode, DnsRcode, DnsRecordType, DnsSection},
};

/// A uniquely owned DNS message. Mutation requires exclusive access.
#[derive(Debug)]
pub struct DnsRecord {
    raw: NonNull<sys::ares_dns_record_t>,
    _thread_bound: PhantomData<Rc<()>>,
}

/// An immutable DNS message borrowed for at most the callback's lifetime.
#[derive(Clone, Copy, Debug)]
pub struct DnsRecordRef<'cb> {
    raw: NonNull<sys::ares_dns_record_t>,
    _borrow: PhantomData<&'cb DnsRecord>,
}

/// A question borrowed from its message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsQuestion<'a> {
    /// Name being queried.
    pub name: &'a str,
    /// Requested resource record type.
    pub record_type: DnsRecordType,
    /// Requested DNS class.
    pub class: DnsClass,
}

/// Decodes an owned Rust value while the input message remains borrowed.
pub trait FromDnsRecord: Sized {
    /// Decode a DNS message.
    ///
    /// # Errors
    /// Returns an error if the message lacks the required fields.
    ///
    /// # Panics
    /// Implementations may panic if their own validation or conversion code panics.
    fn from_dns_record(record: DnsRecordRef<'_>) -> Result<Self>;
}

/// Encodes an owned Rust value as an independent DNS message.
pub trait IntoDnsRecord {
    /// Create a DNS message.
    ///
    /// # Errors
    /// Returns an error for invalid fields or allocation failures.
    ///
    /// # Panics
    /// Implementations may panic if their own validation or conversion code panics.
    fn into_dns_record(self) -> Result<DnsRecord>;
}

pub(crate) fn c_string(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| AresError::invalid_input("string contains an interior NUL"))
}

pub(crate) unsafe fn text<'a>(raw: *const std::ffi::c_char) -> Result<&'a str> {
    if raw.is_null() {
        return Err(AresError::invalid_record("missing string field"));
    }
    // SAFETY: The caller guarantees a live, NUL-terminated C string for 'a.
    unsafe { CStr::from_ptr(raw) }
        .to_str()
        .map_err(|_| AresError::invalid_record("DNS string is not UTF-8"))
}

macro_rules! read_methods {
    () => {
        /// Borrow the underlying C message pointer.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn as_ptr(&self) -> *const sys::ares_dns_record_t {
            self.raw.as_ptr()
        }

        /// Read the DNS transaction identifier.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn id(&self) -> u16 {
            // SAFETY: self owns or borrows a live DNS message.
            unsafe { sys::ares_dns_record_get_id(self.as_ptr()) }
        }

        /// Read the compact c-ares DNS header flags.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn flags(&self) -> DnsFlags {
            // SAFETY: self owns or borrows a live DNS message.
            DnsFlags::from_bits_retain(unsafe { sys::ares_dns_record_get_flags(self.as_ptr()) })
        }

        /// Read the DNS opcode.
        ///
        /// # Errors
        /// Returns an error for an unsupported opcode.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn opcode(&self) -> Result<DnsOpcode> {
            // SAFETY: self owns or borrows a live DNS message.
            DnsOpcode::try_from(unsafe { sys::ares_dns_record_get_opcode(self.as_ptr()) }.0)
        }

        /// Read the DNS response code.
        ///
        /// # Errors
        /// Returns an error for an unsupported response code.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn rcode(&self) -> Result<DnsRcode> {
            // SAFETY: self owns or borrows a live DNS message.
            DnsRcode::try_from(unsafe { sys::ares_dns_record_get_rcode(self.as_ptr()) }.0)
        }

        /// Count the questions in this message.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn query_count(&self) -> usize {
            // SAFETY: self owns or borrows a live DNS message.
            unsafe { sys::ares_dns_record_query_cnt(self.as_ptr()) }
        }

        /// Borrow a question by index.
        ///
        /// # Errors
        /// Returns an error for an invalid index or unsupported field value.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn question(&self, index: usize) -> Result<DnsQuestion<'_>> {
            let mut name = ptr::null();
            let mut record_type = sys::ares_dns_rec_type_t::default();
            let mut class = sys::ares_dns_class_t::default();
            AresError::check(
                // SAFETY: self is live; all output pointers reference initialized local storage.
                unsafe {
                    sys::ares_dns_record_query_get(
                        self.as_ptr(),
                        index,
                        &mut name,
                        &mut record_type,
                        &mut class,
                    )
                }
                .0 as i32,
            )?;
            Ok(DnsQuestion {
                // SAFETY: c-ares retains this NUL-terminated name until exclusive mutation or drop.
                name: unsafe { text(name) }?,
                record_type: DnsRecordType::try_from(record_type.0)?,
                class: DnsClass::try_from(class.0)?,
            })
        }

        /// Count resource records in a section.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn rr_count(&self, section: DnsSection) -> usize {
            // SAFETY: self is live and the section is a valid c-ares discriminant.
            unsafe { sys::ares_dns_record_rr_cnt(self.as_ptr(), section.as_raw().into()) }
        }

        /// Borrow a resource record by section and index.
        ///
        /// # Errors
        /// Returns an error when the index is outside the section.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn rr(&self, section: DnsSection, index: usize) -> Result<DnsRr<'_>> {
            // SAFETY: immutable access keeps the message and its RR storage live and unmoved.
            let raw = unsafe {
                sys::ares_dns_record_rr_get_const(self.as_ptr(), section.as_raw().into(), index)
            };
            // SAFETY: the resulting view is tied to this immutable borrow of the owner.
            unsafe { DnsRr::from_raw(raw) }
        }

        /// Decode every record of the requested type in a section.
        ///
        /// # Errors
        /// Returns an error if any matching record has invalid fields.
        ///
        /// # Panics
        /// Panics from the caller-provided decoder propagate.
        pub fn records<T: FromDnsRr>(&self, section: DnsSection) -> Result<Vec<T>> {
            let mut records = Vec::new();
            for index in 0..self.rr_count(section) {
                let rr = self.rr(section, index)?;
                if rr.record_type()? == T::RECORD_TYPE {
                    records.push(T::from_dns_rr(rr)?);
                }
            }
            Ok(records)
        }

        fn validate_wire_header(&self) -> Result<()> {
            // SAFETY: self owns or borrows a live immutable DNS message.
            let rcode = unsafe { sys::ares_dns_record_get_rcode(self.as_ptr()) }.0;
            if rcode <= 15 {
                return Ok(());
            }
            for index in 0..self.rr_count(DnsSection::Additional) {
                let rr = self.rr(DnsSection::Additional, index)?;
                // SAFETY: rr borrows live immutable storage owned by this message.
                if unsafe { sys::ares_dns_rr_get_type(rr.as_ptr()) } == sys::ARES_REC_TYPE_OPT {
                    return Ok(());
                }
            }
            // c-ares substitutes SERVFAIL when an extended response code lacks OPT.
            Err(AresError::invalid_record(
                "extended DNS response code requires an Additional OPT record",
            ))
        }

        /// Serialize the complete DNS message into an owned wire buffer.
        ///
        /// # Errors
        /// Returns an error if the record is incomplete or allocation fails.
        /// Returns [`AresError::InvalidRecord`] if an extended response code
        /// has no OPT record in the Additional section.
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn write_wire(&self) -> Result<Vec<u8>> {
            self.validate_wire_header()?;
            let mut raw = ptr::null_mut();
            let mut len = 0;
            AresError::check(
                // SAFETY: self is live and both output pointers refer to writable local storage.
                unsafe { sys::ares_dns_write(self.as_ptr(), &mut raw, &mut len) }.0 as i32,
            )?;
            struct WireBuffer(*mut u8);
            impl Drop for WireBuffer {
                fn drop(&mut self) {
                    // SAFETY: successful ares_dns_write transfers its allocation to this guard.
                    unsafe { sys::ares_free_string(self.0.cast()) };
                }
            }
            let buffer = WireBuffer(raw);
            if len == 0 {
                return Ok(Vec::new());
            }
            if buffer.0.is_null() || len > isize::MAX as usize {
                return Err(AresError::invalid_record("invalid serialized DNS buffer"));
            }
            // SAFETY: c-ares returned len initialized bytes, held alive by buffer until copied.
            Ok(unsafe { std::slice::from_raw_parts(buffer.0, len) }.to_vec())
        }

        /// Serialize the DNS message.
        ///
        /// # Errors
        /// Returns the same errors as [`Self::write_wire`].
        ///
        /// # Panics
        /// This function has no explicit panic path.
        pub fn write(&self) -> Result<Vec<u8>> {
            self.write_wire()
        }
    };
}

impl DnsRecord {
    /// Create an empty DNS message with the given header.
    ///
    /// # Errors
    /// Returns an error for invalid header values or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn new(id: u16, flags: DnsFlags, opcode: DnsOpcode, rcode: DnsRcode) -> Result<Self> {
        let mut raw = ptr::null_mut();
        AresError::check(
            // SAFETY: raw is a valid writable output; typed header values use c-ares
            // discriminants.
            unsafe {
                sys::ares_dns_record_create(
                    &mut raw,
                    id,
                    flags.bits(),
                    opcode.as_raw().into(),
                    rcode.as_raw().into(),
                )
            }
            .0 as i32,
        )?;
        // SAFETY: on success, c-ares transfers the freshly allocated record to the caller.
        unsafe { Self::from_raw(raw) }
    }

    /// Adopt an exclusively owned c-ares DNS message.
    ///
    /// # Safety
    /// A non-null pointer must denote a live allocation from c-ares whose ownership is
    /// transferred to this value. No other owner may destroy or mutate it afterwards.
    ///
    /// # Errors
    /// Returns [`AresError::AllocationFailed`] for a null pointer.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub unsafe fn from_raw(raw: *mut sys::ares_dns_record_t) -> Result<Self> {
        Ok(Self {
            raw: NonNull::new(raw).ok_or(AresError::AllocationFailed)?,
            _thread_bound: PhantomData,
        })
    }

    /// Parse a complete DNS wire message with the default c-ares parsing policy.
    ///
    /// # Errors
    /// Returns an error for malformed DNS data or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn parse_wire(wire: &[u8]) -> Result<Self> {
        Self::parse_wire_with_flags(wire, 0)
    }

    /// Parse a complete DNS message with explicit c-ares parsing flags.
    ///
    /// # Errors
    /// Returns an error for invalid flags, malformed data or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn parse_wire_with_flags(wire: &[u8], flags: u32) -> Result<Self> {
        let mut raw = ptr::null_mut();
        AresError::check(
            // SAFETY: wire is readable for its length and raw is a writable output pointer.
            unsafe { sys::ares_dns_parse(wire.as_ptr(), wire.len(), flags, &mut raw) }.0 as i32,
        )?;
        // SAFETY: successful parsing transfers ownership of the new message to the caller.
        unsafe { Self::from_raw(raw) }
    }

    /// Parse a DNS wire message.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::parse_wire`].
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn parse(wire: &[u8]) -> Result<Self> {
        Self::parse_wire(wire)
    }

    /// Duplicate this message into independent c-ares storage.
    ///
    /// # Errors
    /// Returns [`AresError::InvalidRecord`] if an extended response code
    /// has no OPT record in the Additional section.
    /// Returns [`AresError::AllocationFailed`] if duplication fails, including
    /// invalid or incomplete messages rejected by c-ares during duplication.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn try_clone(&self) -> Result<Self> {
        self.as_ref().to_owned_record()
    }

    /// Borrow this message without transferring ownership.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn as_ref(&self) -> DnsRecordRef<'_> {
        DnsRecordRef {
            raw: self.raw,
            _borrow: PhantomData,
        }
    }

    /// Transfer this allocation to the caller without destroying it.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn into_raw(self) -> *mut sys::ares_dns_record_t {
        let raw = self.raw.as_ptr();
        std::mem::forget(self);
        raw
    }

    /// Borrow a mutable C pointer; mutation through it requires an unsafe caller.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn as_mut_ptr(&mut self) -> *mut sys::ares_dns_record_t {
        self.raw.as_ptr()
    }

    /// Set the transaction identifier.
    ///
    /// # Errors
    /// Returns an error if c-ares rejects the message.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn set_id(&mut self, id: u16) -> Result<()> {
        // SAFETY: exclusive access ensures no live views are invalidated by mutation.
        if unsafe { sys::ares_dns_record_set_id(self.raw.as_ptr(), id) }.0 == 0 {
            return Err(AresError::invalid_record(
                "cannot set DNS transaction identifier",
            ));
        }
        Ok(())
    }

    /// Append a question.
    ///
    /// # Errors
    /// Returns an error for invalid names, unsupported fields or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn query_add(
        &mut self,
        name: &str,
        record_type: DnsRecordType,
        class: DnsClass,
    ) -> Result<()> {
        let name = c_string(name)?;
        AresError::check(
            // SAFETY: exclusive message access and a live NUL-terminated name satisfy c-ares.
            unsafe {
                sys::ares_dns_record_query_add(
                    self.raw.as_ptr(),
                    name.as_ptr(),
                    record_type.as_raw().into(),
                    class.as_raw().into(),
                )
            }
            .0 as i32,
        )
    }

    /// Replace a question's domain name.
    ///
    /// # Errors
    /// Returns an error for an invalid index, interior NUL or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn query_set_name(&mut self, index: usize, name: &str) -> Result<()> {
        let name = c_string(name)?;
        // SAFETY: exclusive access protects any relocated name storage; input is NUL-terminated.
        AresError::check(unsafe {
            sys::ares_dns_record_query_set_name(self.raw.as_ptr(), index, name.as_ptr())
        })
    }

    /// Replace a question's requested record type.
    ///
    /// # Errors
    /// Returns an error for an invalid index or unsupported question type.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn query_set_type(&mut self, index: usize, record_type: DnsRecordType) -> Result<()> {
        // SAFETY: exclusive access protects question storage and the type uses a valid
        // discriminant.
        AresError::check(unsafe {
            sys::ares_dns_record_query_set_type(
                self.raw.as_ptr(),
                index,
                record_type.as_raw().into(),
            )
        })
    }

    /// Borrow an existing resource record for exclusive mutation.
    ///
    /// # Errors
    /// Returns an error for an index outside the requested section.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn rr_mut(&mut self, section: DnsSection, index: usize) -> Result<DnsRrMut<'_>> {
        // SAFETY: the mutable record borrow prevents relocation or destruction of RR storage.
        let raw = unsafe {
            sys::ares_dns_record_rr_get(self.raw.as_ptr(), section.as_raw().into(), index)
        };
        // SAFETY: the returned pointer remains valid throughout the exclusive owner borrow.
        unsafe { DnsRrMut::from_raw(raw) }
    }

    /// Remove a resource record from a section.
    ///
    /// # Errors
    /// Returns an error for an index outside the requested section.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn rr_del(&mut self, section: DnsSection, index: usize) -> Result<()> {
        // SAFETY: exclusive access prevents live views from observing relocated or freed RR
        // storage.
        AresError::check(unsafe {
            sys::ares_dns_record_rr_del(self.raw.as_ptr(), section.as_raw().into(), index)
        })
    }

    /// Append a resource record and borrow it for initialization.
    ///
    /// # Errors
    /// Returns an error for invalid fields or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn rr_add(
        &mut self,
        section: DnsSection,
        name: &str,
        record_type: DnsRecordType,
        class: DnsClass,
        ttl: u32,
    ) -> Result<DnsRrMut<'_>> {
        let name = c_string(name)?;
        let mut raw = ptr::null_mut();
        AresError::check(
            // SAFETY: self is exclusively borrowed and all input/output storage is live.
            unsafe {
                sys::ares_dns_record_rr_add(
                    &mut raw,
                    self.raw.as_ptr(),
                    section.as_raw().into(),
                    name.as_ptr(),
                    record_type.as_raw().into(),
                    class.as_raw().into(),
                    ttl,
                )
            }
            .0 as i32,
        )?;
        // SAFETY: the RR is owned by this exclusively borrowed message and cannot move until
        // release.
        unsafe { DnsRrMut::from_raw(raw) }
    }

    /// Append a typed resource record, removing it again if field encoding fails.
    ///
    /// # Errors
    /// Returns an error for invalid fields or allocation failure.
    ///
    /// # Panics
    /// Panics from the caller-provided encoder propagate; the appended RR remains in the message.
    pub fn add_record<T: IntoDnsRr>(
        &mut self,
        section: DnsSection,
        name: &str,
        class: DnsClass,
        ttl: u32,
        value: &T,
    ) -> Result<()> {
        let index = self.rr_count(section);
        let result =
            value.write_dns_rr(&mut self.rr_add(section, name, T::RECORD_TYPE, class, ttl)?);
        if result.is_err() {
            AresError::check(
                // SAFETY: the new RR is still at index; its exclusive view was released above.
                unsafe {
                    sys::ares_dns_record_rr_del(self.raw.as_ptr(), section.as_raw().into(), index)
                }
                .0 as i32,
            )?;
        }
        result
    }

    /// Start constructing a standard recursive query message.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn builder() -> DnsRecordBuilder {
        DnsRecordBuilder::default()
    }

    read_methods!();
}

impl Drop for DnsRecord {
    fn drop(&mut self) {
        // SAFETY: self uniquely owns this c-ares allocation and all borrowed views have expired.
        unsafe { sys::ares_dns_record_destroy(self.raw.as_ptr()) };
    }
}

impl<'cb> DnsRecordRef<'cb> {
    /// Borrow a c-ares message without acquiring ownership.
    ///
    /// # Safety
    /// The message must remain live and immutable for all of 'cb. For a completion
    /// callback, 'cb must end before the C trampoline returns to c-ares.
    ///
    /// # Errors
    /// Returns an error for a null pointer.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub unsafe fn from_raw(raw: *const sys::ares_dns_record_t) -> Result<Self> {
        Ok(Self {
            raw: NonNull::new(raw.cast_mut())
                .ok_or_else(|| AresError::invalid_record("null borrowed DNS message"))?,
            _borrow: PhantomData,
        })
    }

    /// Duplicate the borrowed message into independent owned storage.
    ///
    /// # Errors
    /// Returns [`AresError::InvalidRecord`] if an extended response code
    /// has no OPT record in the Additional section.
    /// Returns [`AresError::AllocationFailed`] if duplication fails, including
    /// invalid or incomplete messages rejected by c-ares during duplication.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn to_owned_record(&self) -> Result<DnsRecord> {
        self.validate_wire_header()?;
        // SAFETY: self borrows a live immutable message for the duration of duplication.
        let raw = unsafe { sys::ares_dns_record_duplicate(self.as_ptr()) };
        // SAFETY: duplication returns a newly allocated record with ownership transferred to us.
        unsafe { DnsRecord::from_raw(raw) }
    }

    read_methods!();
}

/// A DNS header and question builder.
#[derive(Debug)]
pub struct DnsRecordBuilder {
    id: u16,
    flags: DnsFlags,
    opcode: DnsOpcode,
    rcode: DnsRcode,
    questions: Vec<(String, DnsRecordType, DnsClass)>,
}

impl Default for DnsRecordBuilder {
    fn default() -> Self {
        Self {
            id: 0,
            flags: DnsFlags::RD,
            opcode: DnsOpcode::Query,
            rcode: DnsRcode::NoError,
            questions: Vec::new(),
        }
    }
}

impl DnsRecordBuilder {
    /// Set the transaction identifier.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }
    /// Set the compact c-ares header flags.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn flags(mut self, flags: DnsFlags) -> Self {
        self.flags = flags;
        self
    }
    /// Set the DNS opcode.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn opcode(mut self, opcode: DnsOpcode) -> Self {
        self.opcode = opcode;
        self
    }
    /// Set the DNS response code.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn rcode(mut self, rcode: DnsRcode) -> Self {
        self.rcode = rcode;
        self
    }
    /// Append a question to be validated at build time.
    ///
    /// # Panics
    /// Panics from the supplied name conversion propagate.
    pub fn question(
        mut self,
        name: impl Into<String>,
        record_type: DnsRecordType,
        class: DnsClass,
    ) -> Self {
        self.questions.push((name.into(), record_type, class));
        self
    }
    /// Allocate the message and append all configured questions.
    ///
    /// # Errors
    /// Returns an error for invalid fields or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn build(self) -> Result<DnsRecord> {
        let mut record = DnsRecord::new(self.id, self.flags, self.opcode, self.rcode)?;
        for (name, record_type, class) in self.questions {
            record.query_add(&name, record_type, class)?;
        }
        Ok(record)
    }
}
