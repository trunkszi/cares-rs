//! In-memory DNS record model used by macro expansion integration tests.
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
