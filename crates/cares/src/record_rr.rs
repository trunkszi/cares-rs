//! Borrowed DNS resource records and lossless owned models for common RR types.

use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    ptr::{self, NonNull},
};

use cares_sys as sys;

use crate::{
    error::{AresError, Result},
    record::{DnsRecord, c_string, text},
    types::{DnsClass, DnsRecordType},
};

type Key = sys::ares_dns_rr_key_t;

/// Borrowed immutable resource record, invalidated only after this borrow ends.
#[derive(Clone, Copy, Debug)]
pub struct DnsRr<'a> {
    raw: NonNull<sys::ares_dns_rr_t>,
    _owner: PhantomData<&'a DnsRecord>,
}

/// Exclusive resource-record view used while constructing a message.
#[derive(Debug)]
pub struct DnsRrMut<'a> {
    raw: NonNull<sys::ares_dns_rr_t>,
    _owner: PhantomData<&'a mut DnsRecord>,
}

/// Decodes a specific resource-record type into an owned Rust value.
pub trait FromDnsRr: Sized {
    /// Expected resource-record type.
    const RECORD_TYPE: DnsRecordType;
    /// Decode a matching resource record.
    ///
    /// # Errors
    /// Returns an error if the type differs or a field cannot be decoded.
    ///
    /// # Panics
    /// Implementations may panic if their own validation or conversion code panics.
    fn from_dns_rr(rr: DnsRr<'_>) -> Result<Self>;
}

/// Encodes the fields of a specific resource-record type.
pub trait IntoDnsRr {
    /// Resource-record type created by this model.
    const RECORD_TYPE: DnsRecordType;
    /// Populate a matching resource record.
    ///
    /// # Errors
    /// Returns an error for invalid data, a mismatched type or allocation failure.
    ///
    /// # Panics
    /// Implementations may panic if their own validation or conversion code panics.
    fn write_dns_rr(&self, rr: &mut DnsRrMut<'_>) -> Result<()>;
}

impl<'a> DnsRr<'a> {
    pub(crate) unsafe fn from_raw(raw: *const sys::ares_dns_rr_t) -> Result<Self> {
        Ok(Self {
            raw: NonNull::new(raw.cast_mut()).ok_or_else(|| {
                AresError::invalid_record("resource record index is out of bounds")
            })?,
            _owner: PhantomData,
        })
    }
    /// Borrow the underlying C resource-record pointer.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn as_ptr(&self) -> *const sys::ares_dns_rr_t {
        self.raw.as_ptr()
    }
    /// Read the owner name.
    ///
    /// # Errors
    /// Returns an error if the name is absent or is not UTF-8.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn name(&self) -> Result<&str> {
        // SAFETY: the RR and its NUL-terminated name remain alive for this immutable borrow.
        unsafe { text(sys::ares_dns_rr_get_name(self.as_ptr())) }
    }
    /// Read the DNS resource-record type.
    ///
    /// # Errors
    /// Returns an error for an unsupported type value.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn record_type(&self) -> Result<DnsRecordType> {
        // SAFETY: self borrows a live resource record.
        DnsRecordType::try_from(unsafe { sys::ares_dns_rr_get_type(self.as_ptr()) }.0)
    }
    /// Read the resource-record class. Parsed OPT records report [`DnsClass::IN`];
    /// read their EDNS0 UDP payload size through [`Self::as_opt`].
    ///
    /// # Errors
    /// Returns an error if the class cannot be represented.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn class(&self) -> Result<DnsClass> {
        // SAFETY: self borrows a live resource record.
        DnsClass::try_from(unsafe { sys::ares_dns_rr_get_class(self.as_ptr()) }.0)
    }
    /// Read the resource-record time to live, in seconds.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn ttl(&self) -> u32 {
        // SAFETY: self borrows a live resource record.
        unsafe { sys::ares_dns_rr_get_ttl(self.as_ptr()) }
    }
    /// Decode this resource record into a strongly typed owned value.
    ///
    /// # Errors
    /// Returns an error if the type differs or a field is invalid.
    ///
    /// # Panics
    /// Panics from the caller-provided decoder propagate.
    pub fn extract<T: FromDnsRr>(&self) -> Result<T> {
        T::from_dns_rr(*self)
    }

    fn require_type(&self, expected: DnsRecordType) -> Result<()> {
        if self.record_type()? != expected {
            return Err(AresError::invalid_record("resource record type mismatch"));
        }
        Ok(())
    }
}

impl<'a> DnsRrMut<'a> {
    pub(crate) unsafe fn from_raw(raw: *mut sys::ares_dns_rr_t) -> Result<Self> {
        Ok(Self {
            raw: NonNull::new(raw)
                .ok_or_else(|| AresError::invalid_record("null mutable resource record"))?,
            _owner: PhantomData,
        })
    }
    /// Borrow an immutable resource-record view.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn as_ref(&self) -> DnsRr<'_> {
        DnsRr {
            raw: self.raw,
            _owner: PhantomData,
        }
    }
    /// Populate this resource record from a typed model.
    ///
    /// # Errors
    /// Returns an error for a mismatched type, invalid fields or allocation failure.
    ///
    /// # Panics
    /// Panics from the caller-provided encoder propagate; fields may already be modified.
    pub fn set<T: IntoDnsRr>(&mut self, value: &T) -> Result<()> {
        value.write_dns_rr(self)
    }
    /// Set a domain name or textual field selected by a c-ares RR key.
    ///
    /// # Errors
    /// Returns an error for an incompatible key, an interior NUL or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn set_string(&mut self, key: Key, value: &str) -> Result<()> {
        String::write(self, key, &value.to_owned())
    }
    /// Set an unsigned 8-bit field selected by a c-ares RR key.
    ///
    /// # Errors
    /// Returns an error for an incompatible key.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn set_u8(&mut self, key: Key, value: u8) -> Result<()> {
        u8::write(self, key, &value)
    }
    /// Set an unsigned 16-bit field selected by a c-ares RR key.
    ///
    /// # Errors
    /// Returns an error for an incompatible key.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn set_u16(&mut self, key: Key, value: u16) -> Result<()> {
        u16::write(self, key, &value)
    }
    /// Set an unsigned 32-bit field selected by a c-ares RR key.
    ///
    /// # Errors
    /// Returns an error for an incompatible key.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn set_u32(&mut self, key: Key, value: u32) -> Result<()> {
        u32::write(self, key, &value)
    }
    /// Set a binary field selected by a c-ares RR key.
    ///
    /// # Errors
    /// Returns an error for an incompatible key or allocation failure.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn set_binary(&mut self, key: Key, value: &[u8]) -> Result<()> {
        AresError::check(
            // SAFETY: exclusive RR access; c-ares copies the readable value before returning.
            unsafe { sys::ares_dns_rr_set_bin(self.raw.as_ptr(), key, value.as_ptr(), value.len()) }
                .0 as i32,
        )
    }
}

trait Field: Sized {
    fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self>;
    fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()>;
}

macro_rules! integer_field {
    ($ty:ty, $get:ident, $set:ident) => {
        impl Field for $ty {
            fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self> {
                // SAFETY: the typed model passes a matching integer field key for this live RR.
                Ok(unsafe { sys::$get(rr.as_ptr(), key) })
            }
            fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()> {
                // SAFETY: c-ares validates the key and exclusive access protects RR mutation.
                AresError::check(unsafe { sys::$set(rr.raw.as_ptr(), key, *value) }.0 as i32)
            }
        }
    };
}
integer_field!(u8, ares_dns_rr_get_u8, ares_dns_rr_set_u8);
integer_field!(u16, ares_dns_rr_get_u16, ares_dns_rr_set_u16);
integer_field!(u32, ares_dns_rr_get_u32, ares_dns_rr_set_u32);

impl Field for String {
    fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self> {
        // SAFETY: the returned NUL-terminated field is owned by the live immutable RR.
        Ok(unsafe { text(sys::ares_dns_rr_get_str(rr.as_ptr(), key)) }?.to_owned())
    }
    fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()> {
        let value = c_string(value)?;
        AresError::check(
            // SAFETY: c-ares validates the key and copies the live NUL-terminated string.
            unsafe { sys::ares_dns_rr_set_str(rr.raw.as_ptr(), key, value.as_ptr()) }.0 as i32,
        )
    }
}

fn copy_binary(raw: *const u8, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if raw.is_null() || len > isize::MAX as usize {
        return Err(AresError::invalid_record("invalid binary field"));
    }
    // SAFETY: callers pass c-ares field pointers with their lengths, protected by immutable RR
    // borrows.
    Ok(unsafe { std::slice::from_raw_parts(raw, len) }.to_vec())
}

impl Field for Vec<u8> {
    fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self> {
        let mut len = 0;
        // SAFETY: rr is live and len is a writable output containing the field's byte length.
        let raw = unsafe { sys::ares_dns_rr_get_bin(rr.as_ptr(), key, &mut len) };
        if len == 0 {
            return Err(AresError::invalid_record("missing required binary RR data"));
        }
        copy_binary(raw, len)
    }
    fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()> {
        if value.is_empty() {
            return Err(AresError::invalid_input("binary RR data must not be empty"));
        }
        rr.set_binary(key, value)
    }
}

impl Field for Vec<Vec<u8>> {
    fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self> {
        // SAFETY: the typed model supplies the TXT array field key for a live RR.
        let count = unsafe { sys::ares_dns_rr_get_abin_cnt(rr.as_ptr(), key) };
        if count == 0 {
            return Err(AresError::invalid_record(
                "TXT requires at least one character string",
            ));
        }
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            let mut len = 0;
            // SAFETY: index is in range and rr remains immutably borrowed while copying.
            let raw = unsafe { sys::ares_dns_rr_get_abin(rr.as_ptr(), key, index, &mut len) };
            if len > 255 {
                return Err(AresError::invalid_record(
                    "TXT character string exceeds 255 bytes",
                ));
            }
            values.push(copy_binary(raw, len)?);
        }
        Ok(values)
    }
    fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()> {
        if value.is_empty() || value.iter().any(|chunk| chunk.len() > 255) {
            return Err(AresError::invalid_input(
                "TXT needs at least one string, each at most 255 bytes",
            ));
        }
        // SAFETY: c-ares validates the array key on this live RR.
        let count = unsafe { sys::ares_dns_rr_get_abin_cnt(rr.raw.as_ptr(), key) };
        for index in (0..count).rev() {
            AresError::check(
                // SAFETY: reverse deletion keeps every remaining index valid with exclusive
                // access.
                unsafe { sys::ares_dns_rr_del_abin(rr.raw.as_ptr(), key, index) }.0 as i32,
            )?;
        }
        for bytes in value {
            AresError::check(
                // SAFETY: c-ares copies the readable bytes before returning; rr is exclusive.
                unsafe {
                    sys::ares_dns_rr_add_abin(rr.raw.as_ptr(), key, bytes.as_ptr(), bytes.len())
                }
                .0 as i32,
            )?;
        }
        Ok(())
    }
}

/// Ordered service-binding parameters or EDNS0 options, preserving unknown keys.
/// HTTPS and SVCB parameters must have strictly increasing identifiers.
pub type DnsOptions = Vec<(u16, Vec<u8>)>;
fn ordered_service_params(key: Key, values: &DnsOptions) -> bool {
    (key != sys::ARES_RR_SVCB_PARAMS && key != sys::ARES_RR_HTTPS_PARAMS)
        || values.windows(2).all(|pair| pair[0].0 < pair[1].0)
}
impl Field for DnsOptions {
    fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self> {
        // SAFETY: the typed model supplies a valid options field key for this live RR.
        let count = unsafe { sys::ares_dns_rr_get_opt_cnt(rr.as_ptr(), key) };
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            let mut raw = ptr::null();
            let mut len = 0;
            // SAFETY: index is in range and both output pointers reference writable locals.
            let id =
                unsafe { sys::ares_dns_rr_get_opt(rr.as_ptr(), key, index, &mut raw, &mut len) };
            values.push((id, copy_binary(raw, len)?));
        }
        if !ordered_service_params(key, &values) {
            return Err(AresError::invalid_record(
                "service parameters are not strictly increasing",
            ));
        }
        Ok(values)
    }
    fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        if !ordered_service_params(key, value) || value.iter().any(|(id, _)| !seen.insert(*id)) {
            return Err(AresError::invalid_input(
                "DNS option identifiers must be unique and service parameters ordered",
            ));
        }
        let existing = DnsOptions::read(&rr.as_ref(), key)?;
        for (id, _) in existing {
            AresError::check(
                // SAFETY: existing identifiers came from this exclusively held RR.
                unsafe { sys::ares_dns_rr_del_opt_byid(rr.raw.as_ptr(), key, id) }.0 as i32,
            )?;
        }
        for (id, bytes) in value {
            AresError::check(
                // SAFETY: c-ares validates the key and copies all bytes during this exclusive
                // call.
                unsafe {
                    sys::ares_dns_rr_set_opt(rr.raw.as_ptr(), key, *id, bytes.as_ptr(), bytes.len())
                }
                .0 as i32,
            )?;
        }
        Ok(())
    }
}

impl Field for Ipv4Addr {
    fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self> {
        // SAFETY: c-ares checks the supplied address key for the live immutable RR.
        let raw = unsafe { sys::ares_dns_rr_get_addr(rr.as_ptr(), key) };
        let raw = NonNull::new(raw.cast_mut())
            .ok_or_else(|| AresError::invalid_record("missing IPv4 address"))?;
        // SAFETY: c-ares returned a properly aligned in_addr held live by rr.
        Ok(Ipv4Addr::from(unsafe { raw.as_ref() }.s_addr.to_ne_bytes()))
    }
    fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()> {
        let addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(value.octets()),
        };
        // SAFETY: c-ares copies a live network-order in_addr into this exclusive RR.
        AresError::check(unsafe { sys::ares_dns_rr_set_addr(rr.raw.as_ptr(), key, &addr) }.0 as i32)
    }
}

impl Field for Ipv6Addr {
    fn read(rr: &DnsRr<'_>, key: Key) -> Result<Self> {
        // SAFETY: c-ares checks the supplied IPv6 address key on the live RR.
        let raw = unsafe { sys::ares_dns_rr_get_addr6(rr.as_ptr(), key) };
        if raw.is_null() {
            return Err(AresError::invalid_record("missing IPv6 address"));
        }
        let mut bytes = [0u8; 16];
        // SAFETY: ares_in6_addr contains exactly 16 network-order bytes; source and destination do
        // not overlap.
        unsafe { ptr::copy_nonoverlapping(raw.cast::<u8>(), bytes.as_mut_ptr(), bytes.len()) };
        Ok(Ipv6Addr::from(bytes))
    }
    fn write(rr: &mut DnsRrMut<'_>, key: Key, value: &Self) -> Result<()> {
        // SAFETY: all-zero is a valid representation of the plain C address structure/union.
        let mut addr: sys::ares_in6_addr = unsafe { std::mem::zeroed() };
        let bytes = value.octets();
        // SAFETY: ares_in6_addr is 16 bytes of address data; the local buffers are disjoint.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (&mut addr as *mut sys::ares_in6_addr).cast::<u8>(),
                bytes.len(),
            )
        };
        AresError::check(
            // SAFETY: c-ares copies the live local IPv6 address during this exclusive call.
            unsafe { sys::ares_dns_rr_set_addr6(rr.raw.as_ptr(), key, &addr) }.0 as i32,
        )
    }
}

macro_rules! model {
    ($(#[$meta:meta])* $name:ident, $variant:ident, $extractor:ident { $($(#[$field_meta:meta])* $field:ident : $ty:ty = $key:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name { $($(#[$field_meta])* pub $field: $ty,)+ }
        impl FromDnsRr for $name {
            const RECORD_TYPE: DnsRecordType = DnsRecordType::$variant;
            fn from_dns_rr(rr: DnsRr<'_>) -> Result<Self> {
                rr.require_type(<Self as FromDnsRr>::RECORD_TYPE)?;
                Ok(Self { $($field: <$ty as Field>::read(&rr, sys::$key)?,)+ })
            }
        }
        impl IntoDnsRr for $name {
            const RECORD_TYPE: DnsRecordType = DnsRecordType::$variant;
            fn write_dns_rr(&self, rr: &mut DnsRrMut<'_>) -> Result<()> {
                rr.as_ref().require_type(<Self as IntoDnsRr>::RECORD_TYPE)?;
                $(<$ty as Field>::write(rr, sys::$key, &self.$field)?;)+
                Ok(())
            }
        }
        impl DnsRr<'_> {
            /// Decode this RR into its strongly typed owned model.
            ///
            /// # Errors
            /// Returns an error if the RR type differs or a field is invalid.
            ///
            /// # Panics
            /// This function has no explicit panic path.
            pub fn $extractor(&self) -> Result<$name> { self.extract::<$name>() }
        }
        impl TryFrom<DnsRr<'_>> for $name {
            type Error = AresError;
            fn try_from(rr: DnsRr<'_>) -> Result<Self> { Self::from_dns_rr(rr) }
        }
    };
}

model!(
    /// An IPv4 address record.
    ARecord,
    A,
    as_a {
        /// IPv4 address.
        address: Ipv4Addr = ARES_RR_A_ADDR
    }
);
model!(
    /// An IPv6 address record.
    AaaaRecord,
    AAAA,
    as_aaaa {
        /// IPv6 address.
        address: Ipv6Addr = ARES_RR_AAAA_ADDR
    }
);
model!(
    /// A canonical-name alias record.
    CnameRecord,
    CNAME,
    as_cname {
        /// Canonical target name.
        cname: String = ARES_RR_CNAME_CNAME
    }
);
model!(
    /// An authoritative-name-server record.
    NsRecord,
    NS,
    as_ns {
        /// Authoritative name server.
        nsdname: String = ARES_RR_NS_NSDNAME
    }
);
model!(
    /// A reverse-lookup pointer record.
    PtrRecord,
    PTR,
    as_ptr_record {
        /// Target domain name.
        dname: String = ARES_RR_PTR_DNAME
    }
);
model!(
    /// A mail-exchanger record.
    MxRecord,
    MX,
    as_mx {
        /// Preference, lower values first.
        preference: u16 = ARES_RR_MX_PREFERENCE,
        /// Exchange host name.
        exchange: String = ARES_RR_MX_EXCHANGE
    }
);
model!(/// A TXT record preserving one or more binary strings of at most 255 bytes.
    TxtRecord, TXT, as_txt { /// Ordered character-string segments, including embedded NUL bytes.
    chunks: Vec<Vec<u8>> = ARES_RR_TXT_DATA });
model!(
    /// A service-location record.
    SrvRecord,
    SRV,
    as_srv {
        /// Selection priority.
        priority: u16 = ARES_RR_SRV_PRIORITY,
        /// Selection weight.
        weight: u16 = ARES_RR_SRV_WEIGHT,
        /// Service port.
        port: u16 = ARES_RR_SRV_PORT,
        /// Target host name.
        target: String = ARES_RR_SRV_TARGET
    }
);
model!(
    /// A zone start-of-authority record.
    SoaRecord,
    SOA,
    as_soa {
        /// Primary name server.
        mname: String = ARES_RR_SOA_MNAME,
        /// Responsible mailbox name.
        rname: String = ARES_RR_SOA_RNAME,
        /// Zone serial number.
        serial: u32 = ARES_RR_SOA_SERIAL,
        /// Refresh interval in seconds.
        refresh: u32 = ARES_RR_SOA_REFRESH,
        /// Retry interval in seconds.
        retry: u32 = ARES_RR_SOA_RETRY,
        /// Expiry interval in seconds.
        expire: u32 = ARES_RR_SOA_EXPIRE,
        /// Negative-cache TTL in seconds.
        minimum: u32 = ARES_RR_SOA_MINIMUM
    }
);
model!(
    /// A naming-authority pointer record.
    NaptrRecord,
    NAPTR,
    as_naptr {
        /// Rule ordering.
        order: u16 = ARES_RR_NAPTR_ORDER,
        /// Rule preference.
        preference: u16 = ARES_RR_NAPTR_PREFERENCE,
        /// Application flags.
        flags: String = ARES_RR_NAPTR_FLAGS,
        /// Supported services.
        services: String = ARES_RR_NAPTR_SERVICES,
        /// Substitution expression.
        regexp: String = ARES_RR_NAPTR_REGEXP,
        /// Replacement domain.
        replacement: String = ARES_RR_NAPTR_REPLACEMENT
    }
);
model!(
    /// A URI resource record.
    UriRecord,
    URI,
    as_uri {
        /// Selection priority.
        priority: u16 = ARES_RR_URI_PRIORITY,
        /// Selection weight.
        weight: u16 = ARES_RR_URI_WEIGHT,
        /// URI target.
        target: String = ARES_RR_URI_TARGET
    }
);
model!(/// A certification-authority authorization record.
    CaaRecord, CAA, as_caa { /// Critical flag octet.
    critical: u8 = ARES_RR_CAA_CRITICAL, /// Property tag.
    tag: String = ARES_RR_CAA_TAG, /// Opaque property value.
    value: Vec<u8> = ARES_RR_CAA_VALUE });
model!(/// A TLS certificate association record.
    TlsaRecord, TLSA, as_tlsa { /// Certificate usage octet.
    cert_usage: u8 = ARES_RR_TLSA_CERT_USAGE, /// Certificate selector octet.
    selector: u8 = ARES_RR_TLSA_SELECTOR, /// Matching algorithm octet.
    matching_type: u8 = ARES_RR_TLSA_MATCH, /// Certificate association data.
    data: Vec<u8> = ARES_RR_TLSA_DATA });
model!(
    /// An HTTPS service-binding record preserving unknown parameters.
    HttpsRecord,
    HTTPS,
    as_https {
        /// Service priority; zero selects alias mode.
        priority: u16 = ARES_RR_HTTPS_PRIORITY,
        /// Target domain name.
        target: String = ARES_RR_HTTPS_TARGET,
        /// Opaque service parameters keyed by identifier.
        params: DnsOptions = ARES_RR_HTTPS_PARAMS
    }
);
model!(
    /// A generic service-binding record preserving unknown parameters.
    SvcbRecord,
    SVCB,
    as_svcb {
        /// Service priority; zero selects alias mode.
        priority: u16 = ARES_RR_SVCB_PRIORITY,
        /// Target domain name.
        target: String = ARES_RR_SVCB_TARGET,
        /// Opaque service parameters keyed by identifier.
        params: DnsOptions = ARES_RR_SVCB_PARAMS
    }
);
model!(
    /// An EDNS0 pseudo-record.
    OptRecord,
    OPT,
    as_opt {
        /// Advertised UDP payload capacity.
        udp_size: u16 = ARES_RR_OPT_UDP_SIZE,
        /// EDNS version.
        version: u8 = ARES_RR_OPT_VERSION,
        /// EDNS flag word.
        flags: u16 = ARES_RR_OPT_FLAGS,
        /// Opaque EDNS options keyed by identifier.
        options: DnsOptions = ARES_RR_OPT_OPTIONS
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DnsClass, DnsRecordType, DnsSection};

    #[test]
    fn binary_pointer_validation_precedes_slice_construction() -> Result<()> {
        assert!(copy_binary(ptr::null(), 0)?.is_empty());
        assert!(copy_binary(ptr::null(), 1).is_err());
        assert!(copy_binary(NonNull::<u8>::dangling().as_ptr(), isize::MAX as usize + 1).is_err());
        Ok(())
    }

    #[test]
    fn empty_parameters_are_valid_and_missing_binary_data_is_rejected() -> Result<()> {
        let mut record = DnsRecord::builder()
            .question("empty.test", DnsRecordType::HTTPS, DnsClass::IN)
            .build()?;
        let https = HttpsRecord {
            priority: 1,
            target: "svc.test".into(),
            params: vec![],
        };
        let svcb = SvcbRecord {
            priority: 1,
            target: "svc.test".into(),
            params: vec![],
        };
        record.add_record(DnsSection::Answer, "empty.test", DnsClass::IN, 0, &https)?;
        record.add_record(DnsSection::Answer, "empty.test", DnsClass::IN, 0, &svcb)?;
        let tls = record.rr_add(
            DnsSection::Additional,
            "empty.test",
            DnsRecordType::TLSA,
            DnsClass::IN,
            0,
        )?;
        assert!(tls.as_ref().as_tlsa().is_err());
        record.rr_del(DnsSection::Additional, 0)?;
        let empty_tls = TlsaRecord {
            cert_usage: 3,
            selector: 1,
            matching_type: 1,
            data: vec![],
        };
        assert!(
            record
                .add_record(
                    DnsSection::Additional,
                    "empty.test",
                    DnsClass::IN,
                    0,
                    &empty_tls
                )
                .is_err()
        );
        assert_eq!(record.rr_count(DnsSection::Additional), 0);
        let parsed = DnsRecord::parse_wire(&record.write_wire()?)?;
        assert_eq!(parsed.rr(DnsSection::Answer, 0)?.as_https()?, https);
        assert_eq!(parsed.rr(DnsSection::Answer, 1)?.as_svcb()?, svcb);
        Ok(())
    }

    #[test]
    fn unordered_service_parameters_are_rejected_on_write_and_read() -> Result<()> {
        let mut record = DnsRecord::builder()
            .question("order.test", DnsRecordType::HTTPS, DnsClass::IN)
            .build()?;
        let bad = SvcbRecord {
            priority: 1,
            target: "svc.test".into(),
            params: vec![(65401, vec![1]), (65400, vec![2])],
        };
        assert!(
            record
                .add_record(DnsSection::Answer, "order.test", DnsClass::IN, 0, &bad)
                .is_err()
        );
        assert_eq!(record.rr_count(DnsSection::Answer), 0);
        let mut rr = record.rr_add(
            DnsSection::Answer,
            "order.test",
            DnsRecordType::HTTPS,
            DnsClass::IN,
            0,
        )?;
        rr.set_u16(sys::ARES_RR_HTTPS_PRIORITY, 1)?;
        rr.set_string(sys::ARES_RR_HTTPS_TARGET, "svc.test")?;
        for id in [65401, 65400] {
            // SAFETY: the RR is exclusively borrowed, the key matches HTTPS,
            // and c-ares copies this one-byte value during the call. Ordering
            // is deliberately malformed to exercise typed extraction rejection.
            AresError::check(unsafe {
                sys::ares_dns_rr_set_opt(
                    rr.raw.as_ptr(),
                    sys::ARES_RR_HTTPS_PARAMS,
                    id,
                    b"v".as_ptr(),
                    1,
                )
            })?;
        }
        assert!(rr.as_ref().as_https().is_err());
        let parsed = DnsRecord::parse_wire(&record.write_wire()?)?;
        assert!(parsed.records::<HttpsRecord>(DnsSection::Answer).is_err());
        Ok(())
    }
}
