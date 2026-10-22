//! Typed DNS constants and network endpoint values.

use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::error::{AresError, Result};

/// An owned host lookup result copied before the C callback returns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEntry {
    /// Canonical host name.
    pub name: String,
    /// Alternate host names.
    pub aliases: Vec<String>,
    /// IPv4 and IPv6 host addresses.
    pub addresses: Vec<IpAddr>,
}

/// An owned reverse-name lookup result copied before the C callback returns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameInfo {
    /// Resolved host name, when requested and available.
    pub node: Option<String>,
    /// Resolved service, when requested and available.
    pub service: Option<String>,
}

macro_rules! dns_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$item:meta])* $variant:ident = $value:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(u32)]
        pub enum $name { $($(#[$item])* $variant = $value,)+ }

        impl $name {
            /// Returns the numeric value accepted by the c-ares DNS API.
            ///
            /// # Panics
            /// This function does not panic.
            pub const fn as_raw(self) -> u32 { self as u32 }

            /// Converts a supported numeric DNS value into its typed form.
            ///
            /// # Errors
            /// Returns an input error for an unsupported value.
            ///
            /// # Panics
            /// This function has no explicit panic path.
            pub fn from_raw(value: u32) -> Result<Self> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(AresError::invalid_input(format!(
                        "unsupported {} value {value}", stringify!($name)
                    ))),
                }
            }
        }

        impl TryFrom<u32> for $name {
            type Error = AresError;
            fn try_from(value: u32) -> Result<Self> { Self::from_raw(value) }
        }

        impl TryFrom<u16> for $name {
            type Error = AresError;
            fn try_from(value: u16) -> Result<Self> { Self::from_raw(u32::from(value)) }
        }

        impl From<$name> for u32 {
            fn from(value: $name) -> Self { value.as_raw() }
        }
    };
}

/// DNS question or record class, retaining every 16-bit wire value.
///
/// An EDNS OPT record stores its advertised UDP payload size in this field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct DnsClass(u16);

impl DnsClass {
    /// Internet class.
    pub const IN: Self = Self(1);
    /// CHAOS class.
    pub const CHAOS: Self = Self(3);
    /// Hesiod class.
    pub const HESIOD: Self = Self(4);
    /// No class, used by dynamic updates.
    pub const NONE: Self = Self(254);
    /// Any class.
    pub const ANY: Self = Self(255);

    /// Creates a class or OPT payload size from its exact wire value.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric value accepted by the c-ares DNS API.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn as_raw(self) -> u32 {
        self.0 as u32
    }

    /// Creates a class or OPT payload size from a c-ares integer.
    ///
    /// # Errors
    /// Returns an input error if the value does not fit a 16-bit wire field.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn from_raw(value: u32) -> Result<Self> {
        u16::try_from(value).map(Self).map_err(|_| {
            AresError::invalid_input(format!("DNS class exceeds its 16-bit wire field: {value}"))
        })
    }
}

impl From<u16> for DnsClass {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl TryFrom<u32> for DnsClass {
    type Error = AresError;
    fn try_from(value: u32) -> Result<Self> {
        Self::from_raw(value)
    }
}

impl From<DnsClass> for u32 {
    fn from(value: DnsClass) -> Self {
        value.as_raw()
    }
}

dns_enum! {
    /// Record types supported by the c-ares DNS record API.
    DnsRecordType {
        /// IPv4 address.
        A = 1,
        /// Authoritative name server.
        NS = 2,
        /// Canonical name.
        CNAME = 5,
        /// Start of authority.
        SOA = 6,
        /// Reverse-lookup pointer.
        PTR = 12,
        /// Host information.
        HINFO = 13,
        /// Mail exchange.
        MX = 15,
        /// Text strings.
        TXT = 16,
        /// Legacy signature record.
        SIG = 24,
        /// IPv6 address.
        AAAA = 28,
        /// Service location.
        SRV = 33,
        /// Naming authority pointer.
        NAPTR = 35,
        /// EDNS pseudo-record.
        OPT = 41,
        /// TLS certificate association.
        TLSA = 52,
        /// Service binding.
        SVCB = 64,
        /// HTTPS service binding.
        HTTPS = 65,
        /// Any record type in a question.
        ANY = 255,
        /// Uniform resource identifier.
        URI = 256,
        /// Certification authority authorization.
        CAA = 257,
        /// c-ares' generic representation for an unknown wire record type.
        RawRr = 65536,
    }
}

dns_enum! {
    /// Resource-record sections of a DNS message.
    DnsSection {
        /// Answer records.
        Answer = 1,
        /// Authority records.
        Authority = 2,
        /// Additional records.
        Additional = 3,
    }
}

dns_enum! {
    /// DNS header operation code.
    DnsOpcode {
        /// Standard query.
        Query = 0,
        /// Obsolete inverse query.
        Iquery = 1,
        /// Name-server status query.
        Status = 2,
        /// Zone change notification.
        Notify = 4,
        /// Dynamic zone update.
        Update = 5,
    }
}

dns_enum! {
    /// DNS response code, including EDNS extended response codes.
    DnsRcode {
        /// Successful response.
        NoError = 0,
        /// Query format error.
        FormErr = 1,
        /// Name-server failure.
        ServFail = 2,
        /// The requested name does not exist.
        NxDomain = 3,
        /// The operation is not implemented.
        NotImp = 4,
        /// The operation was refused.
        Refused = 5,
        /// A required-absent name exists.
        YxDomain = 6,
        /// A required-absent record set exists.
        YxRrset = 7,
        /// A required-present record set does not exist.
        NxRrset = 8,
        /// The server is not authoritative for the zone.
        NotAuth = 9,
        /// An update name is outside the zone.
        NotZone = 10,
        /// The DSO type is not implemented.
        DsoTypeNotImplemented = 11,
        /// Invalid TSIG signature, or unsupported EDNS version for an OPT record.
        BadSig = 16,
        /// The TSIG key is unknown.
        BadKey = 17,
        /// The TSIG signature is outside its time window.
        BadTime = 18,
        /// Invalid TKEY mode.
        BadMode = 19,
        /// Duplicate key name.
        BadName = 20,
        /// Unsupported algorithm.
        BadAlg = 21,
        /// Invalid truncation.
        BadTrunc = 22,
        /// Missing or invalid DNS server cookie.
        BadCookie = 23,
    }
}

impl DnsRcode {
    /// EDNS calls response code 16 `BADVERS`; TSIG calls it `BADSIG`.
    pub const BADVERS: Self = Self::BadSig;
}

macro_rules! ffi_conversions {
    ($($safe:ident => $raw:ident;)+) => {$(
        impl TryFrom<cares_sys::$raw> for $safe {
            type Error = AresError;
            fn try_from(value: cares_sys::$raw) -> Result<Self> {
                Self::from_raw(value.0)
            }
        }

        impl From<$safe> for cares_sys::$raw {
            fn from(value: $safe) -> Self {
                Self(value.as_raw())
            }
        }
    )+};
}

ffi_conversions! {
    DnsClass => ares_dns_class_t;
    DnsRecordType => ares_dns_rec_type_t;
    DnsSection => ares_dns_section_t;
    DnsOpcode => ares_dns_opcode_t;
    DnsRcode => ares_dns_rcode_t;
}

bitflags::bitflags! {
    /// DNS header flags in c-ares' compact representation.
    ///
    /// These are the `ares_dns_flags_t` masks, not the bit positions of a
    /// serialized DNS header and not channel configuration flags.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct DnsFlags: u16 {
        /// This message is a response.
        const QR = 1;
        /// The answer is authoritative.
        const AA = 2;
        /// The response was truncated.
        const TC = 4;
        /// Recursion is desired.
        const RD = 8;
        /// Recursion is available.
        const RA = 16;
        /// The server authenticated the answer.
        const AD = 32;
        /// DNSSEC validation is disabled for this query.
        const CD = 64;
    }

    /// Transport used by a server-state notification.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct ServerStateFlags: i32 {
        /// Query used UDP.
        const UDP = 1;
        /// Query used TCP.
        const TCP = 2;
    }
}

/// An IPv4 or IPv6 endpoint, preserving the IPv6 scope and flow information.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SocketAddress(pub SocketAddr);

impl SocketAddress {
    /// Constructs an IP endpoint with the given port.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self(SocketAddr::new(ip, port))
    }

    /// Returns the endpoint's IP address.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn ip(self) -> IpAddr {
        self.0.ip()
    }

    /// Returns the endpoint's port in host byte order.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn port(self) -> u16 {
        self.0.port()
    }

    /// Borrows the standard-library endpoint.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn as_std(&self) -> &SocketAddr {
        &self.0
    }

    /// Converts to the standard-library endpoint without changing any fields.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn into_std(self) -> SocketAddr {
        self.0
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(value: SocketAddr) -> Self {
        Self(value)
    }
}

impl From<SocketAddrV4> for SocketAddress {
    fn from(value: SocketAddrV4) -> Self {
        Self(SocketAddr::V4(value))
    }
}

impl From<SocketAddrV6> for SocketAddress {
    fn from(value: SocketAddrV6) -> Self {
        Self(SocketAddr::V6(value))
    }
}

impl From<SocketAddress> for SocketAddr {
    fn from(value: SocketAddress) -> Self {
        value.0
    }
}

impl FromStr for SocketAddress {
    type Err = AresError;

    /// Parses a numeric endpoint such as `192.0.2.1:53` or `[2001:db8::1]:53`.
    ///
    /// # Errors
    /// Returns an input error if an address or port is malformed or absent.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    fn from_str(value: &str) -> Result<Self> {
        value.parse().map(Self).map_err(|error| {
            AresError::invalid_input(format!("invalid DNS server endpoint {value:?}: {error}"))
        })
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
