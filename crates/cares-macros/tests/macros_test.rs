//! Macro integration against a controlled in-memory cares API; no native DNS calls.
extern crate self as cares;
mod api {
    pub mod cares {
        pub mod error {
            #[derive(Debug, PartialEq, Eq)]
            pub struct AresError(pub &'static str);
            pub type Result<T> = std::result::Result<T, AresError>;
            impl AresError {
                pub fn invalid_record(message: &'static str) -> Self {
                    Self(message)
                }
            }
        }
        pub mod types {
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            #[repr(u16)]
            pub enum DnsRecordType {
                A = 1,
                AAAA = 28,
                CNAME = 5,
                NS = 2,
                PTR = 12,
                MX = 15,
                TXT = 16,
                SRV = 33,
                SOA = 6,
                NAPTR = 35,
                URI = 256,
                CAA = 257,
                TLSA = 52,
                HTTPS = 65,
                SVCB = 64,
                OPT = 41,
            }
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum DnsClass {
                IN,
                CH,
            }
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum DnsSection {
                Answer,
                Authority,
                Additional,
            }
            pub struct DnsFlags;
            impl DnsFlags {
                pub const QR: Self = Self;
            }
            pub enum DnsOpcode {
                Query,
            }
            pub enum DnsRcode {
                NoError,
            }
        }
        pub mod record_rr {
            use std::net::{Ipv4Addr, Ipv6Addr};

            use super::{
                error::{AresError, Result},
                types::{DnsClass, DnsRecordType},
            };
            pub trait FromDnsRr: Sized {
                const RECORD_TYPE: DnsRecordType;
                /// # Errors
                /// Rejects malformed or mismatched resource records.
                fn from_dns_rr(rr: DnsRr<'_>) -> Result<Self>;
            }
            pub trait IntoDnsRr {
                const RECORD_TYPE: DnsRecordType;
                /// # Errors
                /// Rejects a resource record of another type.
                fn write_dns_rr(&self, rr: &mut DnsRrMut<'_>) -> Result<()>;
            }
            #[derive(Debug)]
            pub struct StoredRr {
                pub name: String,
                pub class: DnsClass,
                pub ttl: u32,
                pub record_type: DnsRecordType,
                pub malformed: bool,
                pub data: Option<Data>,
            }
            #[derive(Debug, Clone)]
            pub enum Data {
                A(ARecord),
                AAAA(AaaaRecord),
                CNAME(CnameRecord),
                NS(NsRecord),
                PTR(PtrRecord),
                MX(MxRecord),
                TXT(TxtRecord),
                SRV(SrvRecord),
                SOA(SoaRecord),
                NAPTR(NaptrRecord),
                URI(UriRecord),
                CAA(CaaRecord),
                TLSA(TlsaRecord),
                HTTPS(HttpsRecord),
                SVCB(SvcbRecord),
                OPT(OptRecord),
            }
            #[derive(Clone, Copy)]
            pub struct DnsRr<'a>(pub &'a StoredRr);
            pub struct DnsRrMut<'a>(pub &'a mut StoredRr);
            impl DnsRr<'_> {
                /// # Errors
                /// Rejects a malformed owner name.
                pub fn name(&self) -> Result<&str> {
                    Ok(&self.0.name)
                }
                /// # Errors
                /// Rejects an unsupported class.
                pub fn class(&self) -> Result<DnsClass> {
                    Ok(self.0.class)
                }
                pub fn ttl(&self) -> u32 {
                    self.0.ttl
                }
            }
            macro_rules! model {
            ($name:ident, $variant:ident, $accessor:ident { $($field:ident: $ty:ty),+ }) => {
                #[derive(Debug, Clone, PartialEq, Eq)]
                pub struct $name { $(pub $field: $ty,)+ }
                impl FromDnsRr for $name {
                    const RECORD_TYPE: DnsRecordType = DnsRecordType::$variant;
                    fn from_dns_rr(rr: DnsRr<'_>) -> Result<Self> {
                        if rr.0.malformed { return Err(AresError::invalid_record("malformed payload")); }
                        match &rr.0.data {
                            Some(Data::$variant(value)) if rr.0.record_type == <Self as FromDnsRr>::RECORD_TYPE => Ok(value.clone()),
                            _ => Err(AresError::invalid_record("record type mismatch")),
                        }
                    }
                }
                impl IntoDnsRr for $name {
                    const RECORD_TYPE: DnsRecordType = DnsRecordType::$variant;
                    fn write_dns_rr(&self, rr: &mut DnsRrMut<'_>) -> Result<()> {
                        if rr.0.record_type != <Self as IntoDnsRr>::RECORD_TYPE {
                            return Err(AresError::invalid_record("record type mismatch"));
                        }
                        rr.0.data = Some(Data::$variant(self.clone()));
                        Ok(())
                    }
                }
                impl DnsRr<'_> {
                    /// # Errors
                    /// Rejects malformed fields or another RR type.
                    pub fn $accessor(&self) -> Result<$name> { $name::from_dns_rr(*self) }
                }
            };
        }
            model!(ARecord, A, as_a { address: Ipv4Addr });
            model!(AaaaRecord, AAAA, as_aaaa { address: Ipv6Addr });
            model!(CnameRecord, CNAME, as_cname { cname: String });
            model!(NsRecord, NS, as_ns { nsdname: String });
            model!(PtrRecord, PTR, as_ptr_record { dname: String });
            model!(
                MxRecord,
                MX,
                as_mx {
                    preference: u16,
                    exchange: String
                }
            );
            model!(TxtRecord, TXT, as_txt { chunks: Vec<Vec<u8>> });
            model!(
                SrvRecord,
                SRV,
                as_srv {
                    priority: u16,
                    weight: u16,
                    port: u16,
                    target: String
                }
            );
            model!(
                SoaRecord,
                SOA,
                as_soa {
                    mname: String,
                    rname: String,
                    serial: u32,
                    refresh: u32,
                    retry: u32,
                    expire: u32,
                    minimum: u32
                }
            );
            model!(
                NaptrRecord,
                NAPTR,
                as_naptr {
                    order: u16,
                    preference: u16,
                    flags: String,
                    services: String,
                    regexp: String,
                    replacement: String
                }
            );
            model!(
                UriRecord,
                URI,
                as_uri {
                    priority: u16,
                    weight: u16,
                    target: String
                }
            );
            model!(CaaRecord, CAA, as_caa { critical: u8, tag: String, value: Vec<u8> });
            model!(TlsaRecord, TLSA, as_tlsa { cert_usage: u8, selector: u8, matching_type: u8, data: Vec<u8> });
            model!(HttpsRecord, HTTPS, as_https { priority: u16, target: String, params: Vec<(u16, Vec<u8>)> });
            model!(SvcbRecord, SVCB, as_svcb { priority: u16, target: String, params: Vec<(u16, Vec<u8>)> });
            model!(OptRecord, OPT, as_opt { udp_size: u16, version: u8, flags: u16, options: Vec<(u16, Vec<u8>)> });
        }
        pub mod record {
            use super::{
                error::{AresError, Result},
                record_rr::{DnsRr, DnsRrMut, FromDnsRr, IntoDnsRr, StoredRr},
                types::{DnsClass, DnsFlags, DnsOpcode, DnsRcode, DnsRecordType, DnsSection},
            };
            pub trait FromDnsRecord: Sized {
                /// # Errors
                /// Rejects a message with invalid matching resource records.
                fn from_dns_record(record: DnsRecordRef<'_>) -> Result<Self>;
            }
            pub trait IntoDnsRecord {
                /// # Errors
                /// Rejects an invalid record.
                fn into_dns_record(self) -> Result<DnsRecord>;
            }
            #[derive(Debug)]
            pub struct DnsRecord {
                pub questions: Vec<(String, DnsRecordType, DnsClass)>,
                pub records: Vec<(DnsSection, StoredRr)>,
            }
            #[derive(Clone, Copy)]
            pub struct DnsRecordRef<'a>(pub &'a DnsRecord);
            impl DnsRecord {
                /// # Errors
                /// Rejects unsupported header values.
                pub fn new(
                    _id: u16,
                    _flags: DnsFlags,
                    _opcode: DnsOpcode,
                    _rcode: DnsRcode,
                ) -> Result<Self> {
                    Ok(Self {
                        questions: Vec::new(),
                        records: Vec::new(),
                    })
                }
                pub fn as_ref(&self) -> DnsRecordRef<'_> {
                    DnsRecordRef(self)
                }
                /// # Errors
                /// Rejects invalid question fields.
                pub fn query_add(
                    &mut self,
                    owner: &str,
                    record_type: DnsRecordType,
                    class: DnsClass,
                ) -> Result<()> {
                    self.questions.push((owner.into(), record_type, class));
                    Ok(())
                }
                /// # Errors
                /// Rejects writes before a question exists or failed payload encoding.
                pub fn add_record<T: IntoDnsRr>(
                    &mut self,
                    section: DnsSection,
                    name: &str,
                    class: DnsClass,
                    ttl: u32,
                    value: &T,
                ) -> Result<()> {
                    if self.questions.is_empty() {
                        return Err(AresError::invalid_record("question must precede records"));
                    }
                    let mut rr = StoredRr {
                        name: name.into(),
                        class,
                        ttl,
                        record_type: T::RECORD_TYPE,
                        malformed: false,
                        data: None,
                    };
                    value.write_dns_rr(&mut DnsRrMut(&mut rr))?;
                    self.records.push((section, rr));
                    Ok(())
                }
            }
            impl DnsRecordRef<'_> {
                /// # Errors
                /// Propagates invalid matching payloads.
                pub fn records<T: FromDnsRr>(&self, section: DnsSection) -> Result<Vec<T>> {
                    self.0
                        .records
                        .iter()
                        .filter(|(found, rr)| *found == section && rr.record_type == T::RECORD_TYPE)
                        .map(|(_, rr)| T::from_dns_rr(DnsRr(rr)))
                        .collect()
                }
            }
        }
    }
}
use std::net::{Ipv4Addr, Ipv6Addr};

pub use api::cares::{error, record, record_rr, types};
use cares_macros::{DnsRecordExtract, cares_query_table};
use record::{FromDnsRecord, IntoDnsRecord};
use record_rr::{DnsRr, DnsRrMut, FromDnsRr, IntoDnsRr};
use types::{DnsClass, DnsSection};

#[path = "support/allocation.rs"]
mod allocation;

#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "A", section = "Answer")]
pub struct DerivedARecord {
    pub address: Ipv4Addr,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "AAAA", section = "Authority")]
pub struct DerivedAaaaRecord {
    pub address: Ipv6Addr,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "CNAME", section = "Additional")]
pub struct DerivedCnameRecord {
    pub cname: String,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "NS", section = "Answer")]
pub struct DerivedNsRecord {
    pub nsdname: String,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "PTR", section = "Authority")]
pub struct DerivedPtrRecord {
    pub dname: String,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "MX", section = "Additional")]
pub struct DerivedMxRecord {
    pub preference: u16,
    pub exchange: String,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "TXT", section = "Answer")]
pub struct DerivedTxtRecord {
    pub chunks: Vec<Vec<u8>>,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "SRV", section = "Authority")]
pub struct DerivedSrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "SOA", section = "Additional")]
pub struct DerivedSoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "NAPTR", section = "Answer")]
pub struct DerivedNaptrRecord {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub services: String,
    pub regexp: String,
    pub replacement: String,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "URI", section = "Authority")]
pub struct DerivedUriRecord {
    pub priority: u16,
    pub weight: u16,
    pub target: String,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "CAA", section = "Additional")]
pub struct DerivedCaaRecord {
    pub critical: u8,
    pub tag: String,
    pub value: Vec<u8>,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "TLSA", section = "Answer")]
pub struct DerivedTlsaRecord {
    pub cert_usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub data: Vec<u8>,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "HTTPS", section = "Authority")]
pub struct DerivedHttpsRecord {
    pub priority: u16,
    pub target: String,
    pub params: Vec<(u16, Vec<u8>)>,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "SVCB", section = "Additional")]
pub struct DerivedSvcbRecord {
    pub priority: u16,
    pub target: String,
    pub params: Vec<(u16, Vec<u8>)>,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}
#[derive(Clone, Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "OPT", section = "Answer")]
pub struct DerivedOptRecord {
    pub udp_size: u16,
    pub version: u8,
    pub flags: u16,
    pub options: Vec<(u16, Vec<u8>)>,
    pub owner: String,
    pub ttl: u32,
    pub dns_class: DnsClass,
}

macro_rules! record_case {
    ($test:ident, $name:ident, $rr:literal, $section:literal, $variant:ident, { $($field:ident: $ty:ty = $value:expr),+ $(,)? }) => {
        #[test]
        fn $test() -> error::Result<()> {
            let value = $name { $($field: $value,)+ owner: "record.example".into(), ttl: 0xfedc_ba98, dns_class: DnsClass::CH };
            let record = value.clone().into_dns_record()?;
            assert_eq!(record.questions, vec![("record.example".into(), < $name as FromDnsRr >::RECORD_TYPE, DnsClass::CH)]);
            assert_eq!(record.records[0].0, DnsSection::$variant);
            assert_eq!($name::from_dns_record(record.as_ref())?, value);
            assert_eq!($name::extract_from_record(record.as_ref())?, vec![value.clone()]);
            assert_eq!($name::from_dns_rr(DnsRr(&record.records[0].1))?, value);
            let mut other = value.clone().into_dns_record()?;
            value.write_dns_rr(&mut DnsRrMut(&mut other.records[0].1))?;
            assert_eq!($name::from_dns_record(other.as_ref())?, value);
            assert_eq!($name::RR_TYPE_CODE, < $name as FromDnsRr >::RECORD_TYPE as u16);
            Ok(())
        }
    };
}
record_case!(integration_a_all_conversion_traits, DerivedARecord, "A", "Answer", Answer, {
    address: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 17),
});
record_case!(integration_aaaa_all_conversion_traits, DerivedAaaaRecord, "AAAA", "Authority", Authority, {
    address: Ipv6Addr = Ipv6Addr::LOCALHOST,
});
record_case!(integration_cname_all_conversion_traits, DerivedCnameRecord, "CNAME", "Additional", Additional, {
    cname: String = "target.example".into(),
});
record_case!(integration_ns_all_conversion_traits, DerivedNsRecord, "NS", "Answer", Answer, {
    nsdname: String = "ns.example".into(),
});
record_case!(integration_ptr_all_conversion_traits, DerivedPtrRecord, "PTR", "Authority", Authority, {
    dname: String = "ptr.example".into(),
});
record_case!(integration_mx_all_conversion_traits, DerivedMxRecord, "MX", "Additional", Additional, {
    preference: u16 = 17,
    exchange: String = "mail.example".into(),
});
record_case!(integration_txt_all_conversion_traits, DerivedTxtRecord, "TXT", "Answer", Answer, {
    chunks: Vec<Vec<u8>> = vec![vec![0, 255, 17], vec![]],
});
record_case!(integration_srv_all_conversion_traits, DerivedSrvRecord, "SRV", "Authority", Authority, {
    priority: u16 = 19,
    weight: u16 = 23,
    port: u16 = 443,
    target: String = "service.example".into(),
});
record_case!(integration_soa_all_conversion_traits, DerivedSoaRecord, "SOA", "Additional", Additional, {
    mname: String = "ns.example".into(),
    rname: String = "admin.example".into(),
    serial: u32 = 0xfedc_ba98,
    refresh: u32 = 600,
    retry: u32 = 61,
    expire: u32 = 86400,
    minimum: u32 = 37,
});
record_case!(integration_naptr_all_conversion_traits, DerivedNaptrRecord, "NAPTR", "Answer", Answer, {
    order: u16 = 5,
    preference: u16 = 7,
    flags: String = "s".into(),
    services: String = "SIP+D2U".into(),
    regexp: String = "!^.*$!sip:info@example!".into(),
    replacement: String = "_sip._udp.example".into(),
});
record_case!(integration_uri_all_conversion_traits, DerivedUriRecord, "URI", "Authority", Authority, {
    priority: u16 = 11,
    weight: u16 = 13,
    target: String = "https://example.test/path".into(),
});
record_case!(integration_caa_all_conversion_traits, DerivedCaaRecord, "CAA", "Additional", Additional, {
    critical: u8 = 128,
    tag: String = "issue".into(),
    value: Vec<u8> = vec![0, 128, 255],
});
record_case!(integration_tlsa_all_conversion_traits, DerivedTlsaRecord, "TLSA", "Answer", Answer, {
    cert_usage: u8 = 3,
    selector: u8 = 1,
    matching_type: u8 = 2,
    data: Vec<u8> = vec![0, 42, 255],
});
record_case!(integration_https_all_conversion_traits, DerivedHttpsRecord, "HTTPS", "Authority", Authority, {
    priority: u16 = 1,
    target: String = "https.example".into(),
    params: Vec<(u16, Vec<u8>)> = vec![(1, vec![2, 104, 50]), (65001, vec![0, 255])],
});
record_case!(integration_svcb_all_conversion_traits, DerivedSvcbRecord, "SVCB", "Additional", Additional, {
    priority: u16 = 2,
    target: String = "svc.example".into(),
    params: Vec<(u16, Vec<u8>)> = vec![(3, vec![1, 187])],
});
record_case!(integration_opt_all_conversion_traits, DerivedOptRecord, "OPT", "Answer", Answer, {
    udp_size: u16 = 1232,
    version: u8 = 0,
    flags: u16 = 0x8000,
    options: Vec<(u16, Vec<u8>)> = vec![(12, vec![0, 0]), (65000, vec![255])],
});

#[derive(Debug, PartialEq, Eq, DnsRecordExtract)]
#[dns(rr_type = "A", section = "Answer")]
pub struct AddressOnly {
    address: Ipv4Addr,
}

#[test]
fn integration_default_metadata_and_single_match_rule() -> error::Result<()> {
    let value = AddressOnly {
        address: Ipv4Addr::LOCALHOST,
    };
    let mut message = value.into_dns_record()?;
    assert_eq!(message.questions[0].0, ".");
    assert_eq!(message.records[0].1.name, ".");
    assert_eq!(message.records[0].1.ttl, 0);
    assert_eq!(message.records[0].1.class, DnsClass::IN);
    message.records.clear();
    assert!(AddressOnly::extract_from_record(message.as_ref())?.is_empty());
    assert!(AddressOnly::from_dns_record(message.as_ref()).is_err());
    let first = AddressOnly {
        address: Ipv4Addr::new(192, 0, 2, 1),
    };
    let second = AddressOnly {
        address: Ipv4Addr::new(192, 0, 2, 2),
    };
    message.add_record(
        DnsSection::Answer,
        "first.example",
        DnsClass::IN,
        60,
        &first,
    )?;
    message.add_record(
        DnsSection::Answer,
        "second.example",
        DnsClass::IN,
        70,
        &second,
    )?;
    assert_eq!(
        AddressOnly::extract_from_record(message.as_ref())?,
        vec![first, second]
    );
    assert!(AddressOnly::from_dns_record(message.as_ref()).is_err());
    Ok(())
}

#[test]
fn integration_section_type_filtering_and_decode_errors() -> error::Result<()> {
    let mut message = AddressOnly {
        address: Ipv4Addr::LOCALHOST,
    }
    .into_dns_record()?;
    let original = AddressOnly::from_dns_record(message.as_ref())?;
    message.add_record(
        DnsSection::Authority,
        "authority.example",
        DnsClass::IN,
        1,
        &AddressOnly {
            address: Ipv4Addr::UNSPECIFIED,
        },
    )?;
    message.add_record(
        DnsSection::Additional,
        "additional.example",
        DnsClass::IN,
        1,
        &AddressOnly {
            address: Ipv4Addr::BROADCAST,
        },
    )?;
    message.add_record(
        DnsSection::Answer,
        "v6.example",
        DnsClass::IN,
        2,
        &record_rr::AaaaRecord {
            address: Ipv6Addr::LOCALHOST,
        },
    )?;
    assert_eq!(AddressOnly::from_dns_record(message.as_ref())?, original);
    assert_eq!(AddressOnly::extract_from_record(message.as_ref())?.len(), 1);
    assert!(AddressOnly::from_dns_rr(DnsRr(&message.records[3].1)).is_err());
    assert!(
        original
            .write_dns_rr(&mut DnsRrMut(&mut message.records[3].1))
            .is_err()
    );
    message.records[0].1.malformed = true;
    assert!(AddressOnly::from_dns_rr(DnsRr(&message.records[0].1)).is_err());
    assert!(AddressOnly::from_dns_record(message.as_ref()).is_err());
    assert!(AddressOnly::extract_from_record(message.as_ref()).is_err());
    Ok(())
}

cares_query_table! {
    pub enum Queries {
        web_a { name: "example.com", rr_type: A, class: IN },
        web_v6 { name: "example.com", rr_type: AAAA, class: IN },
        chaos_txt { name: "version.bind.", rr_type: TXT, class: CHAOS },
        root_ns { name: ".", rr_type: NS, class: IN },
        escaped { name: "a\\.b.example", rr_type: HTTPS, class: ANY },
    }
}

#[test]
fn integration_query_encoding_dispatch_and_roundtrips() -> Result<(), &'static str> {
    assert_eq!(Queries::SLOT_COUNT, 5);
    assert_eq!(Queries::DISPATCH[0].name, "web_a");
    assert_eq!(Queries::WebA.slot_name(), "web_a");
    assert_eq!(Queries::WebA.qname(), "example.com");
    assert_eq!(Queries::WebA.rr_type(), 1);
    assert_eq!(Queries::ChaosTxt.dns_class(), 3);
    for route in [
        Queries::WebA,
        Queries::WebV6,
        Queries::ChaosTxt,
        Queries::RootNs,
        Queries::Escaped,
    ] {
        let mut packet = [0_u8; 512];
        let len = route.encode(0x1234, &mut packet)?;
        assert_eq!(&packet[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Queries::decode(&packet[..len])?, route);
        packet[2] |= 0x80;
        assert_eq!(Queries::decode(&packet[..len])?, route);
        let mut too_short = vec![0xa5; len - 1];
        assert!(route.encode(0, &mut too_short).is_err());
    }
    let mut packet = [0_u8; 64];
    let len = Queries::WebA.encode(0, &mut packet)?;
    assert_eq!(len, 29);
    assert_eq!(&packet[12..len], b"\x07example\x03com\0\0\x01\0\x01");
    for byte in &mut packet[13..20] {
        byte.make_ascii_uppercase();
    }
    assert_eq!(Queries::decode(&packet[..len])?, Queries::WebA);
    Ok(())
}

#[test]
fn integration_query_compression_and_malformed_packets() -> Result<(), &'static str> {
    let mut packet = [0_u8; 64];
    let len = Queries::WebA.encode(1, &mut packet)?;
    for truncated in 0..len {
        assert!(Queries::decode(&packet[..truncated]).is_err());
    }
    let mut compressed = [0_u8; 64];
    compressed[..12].copy_from_slice(&packet[..12]);
    compressed[12..18].copy_from_slice(&[0xc0, 18, 0, 1, 0, 1]);
    compressed[18..31].copy_from_slice(&packet[12..25]);
    assert_eq!(Queries::decode(&compressed[..31])?, Queries::WebA);
    compressed[13] = 12;
    assert!(Queries::decode(&compressed[..31]).is_err());
    compressed[13] = 63;
    assert!(Queries::decode(&compressed[..31]).is_err());
    packet[12] = 0x40;
    assert!(Queries::decode(&packet[..len]).is_err());
    let len = Queries::WebA.encode(1, &mut packet)?;
    packet[5] = 0;
    assert!(Queries::decode(&packet[..len]).is_err());
    packet[5] = 1;
    packet[2] = 0x08;
    assert!(Queries::decode(&packet[..len]).is_err());
    packet[2] = 1;
    packet[len - 1] = 255;
    assert!(Queries::decode(&packet[..len]).is_err());
    packet[len - 1] = 1;
    packet[len - 3] = 255;
    assert!(Queries::decode(&packet[..len]).is_err());
    Ok(())
}

#[test]
fn integration_query_encode_decode_allocate_nothing() -> Result<(), &'static str> {
    let mut packet = [0_u8; 64];
    allocation::start();
    let encoded = Queries::WebA.encode(4, &mut packet);
    let decoded = match encoded {
        Ok(len) => Queries::decode(&packet[..len]),
        Err(err) => Err(err),
    };
    let count = allocation::finish();
    assert_eq!(count, 0);
    assert_eq!(decoded?, Queries::WebA);
    Ok(())
}

mod imported_result_hygiene {
    use super::{Queries, cares_query_table};
    use crate::error::Result;
    cares_query_table! {
        enum ImportedResult {
            web { name: "example.com", rr_type: A, class: IN },
        }
    }
    #[test]
    fn integration_generated_query_ignores_result_alias() -> Result<()> {
        let mut packet = [0; 64];
        let Ok(len) = ImportedResult::Web.encode(2, &mut packet) else {
            panic!("encoding failed");
        };
        assert_eq!(Queries::decode(&packet[..len]), Ok(Queries::WebA));
        assert_eq!(
            ImportedResult::decode(&packet[..len]),
            Ok(ImportedResult::Web)
        );
        Ok(())
    }
}
