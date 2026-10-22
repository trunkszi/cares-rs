//! Compile-time DNS record mapping and zero-allocation query tables.
//!
//! [`DnsRecordExtract`](derive@DnsRecordExtract) emits `cares` trait impls for a
//! struct whose fields match one built-in resource-record model. [`cares_query_table`]
//! checks query slots while compiling and emits a routing enum that encodes and
//! decodes standard questions without allocating.

#![forbid(unsafe_code)]

mod extract;
mod query_table;

use proc_macro::TokenStream;

/// Map a named-field struct onto one c-ares resource-record model.
///
/// Place `#[dns(rr_type = "...", section = "...")]` on the struct. `rr_type`
/// is one of `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `PTR`, `SOA`, `NAPTR`,
/// `URI`, `CAA`, `TLSA`, `HTTPS`, `SVCB`, `NS`, or `OPT`. `section` is
/// `Answer`, `Authority`, or `Additional`.
///
/// The derive implements `cares::record_rr::FromDnsRr`, `cares::record_rr::IntoDnsRr`,
/// `cares::record::FromDnsRecord`, and `cares::record::IntoDnsRecord`. It also
/// adds `extract_from_record`, which returns every matching record in the
/// annotated section. `FromDnsRecord` succeeds only when that section contains
/// exactly one match. `IntoDnsRecord` builds a one-question message: `query_add`
/// runs before `add_record`, because `ares_dns_parse` accepts only that shape.
/// Field names and types are the ones published by `cares::record_rr`
/// (`address: Ipv4Addr`, `dname`, `chunks: Vec<Vec<u8>>`, `critical`,
/// `cert_usage`, and so on). Optional metadata fields are `owner: String`,
/// `ttl: u32`, and `dns_class: cares::types::DnsClass`.
///
/// # Examples
///
/// ```ignore
/// use cares_macros::DnsRecordExtract;
///
/// #[derive(DnsRecordExtract)]
/// #[dns(rr_type = "A", section = "Answer")]
/// struct Host {
///     address: std::net::Ipv4Addr,
/// }
/// ```
///
/// ```compile_fail
/// use cares_macros::DnsRecordExtract;
///
/// #[derive(DnsRecordExtract)]
/// #[dns(rr_type = "NOT_A_TYPE", section = "Answer")]
/// struct Host {
///     address: std::net::Ipv4Addr,
/// }
/// ```
///
/// ```compile_fail
/// use cares_macros::DnsRecordExtract;
///
/// #[derive(DnsRecordExtract)]
/// #[dns(rr_type = "A", section = "Question")]
/// struct Host {
///     address: std::net::Ipv4Addr,
/// }
/// ```
///
/// ```compile_fail
/// use cares_macros::DnsRecordExtract;
///
/// #[derive(DnsRecordExtract)]
/// struct Host {
///     address: std::net::Ipv4Addr,
/// }
/// ```
#[proc_macro_derive(DnsRecordExtract, attributes(dns))]
pub fn derive_dns_record_extract(input: TokenStream) -> TokenStream {
    match extract::expand(input.into()) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Declare a zero-allocation DNS query routing table.
///
/// Each slot names a presentation-format domain, a resource-record type, and a
/// class. Slot identifiers become `PascalCase` enum variants (`web_a` becomes
/// `WebA`). `encode` writes one standard query (RD set, QDCOUNT 1) into a
/// caller buffer. `decode` routes the first question of a query or a response
/// without allocating.
///
/// Legal classes are `IN`, `CS`, `CH`, `CHAOS`, `HS`, `HESIOD`, `NONE`, and
/// `ANY`. Legal types are the c-ares record types except the `RawRr` sentinel.
///
/// # Examples
///
/// ```
/// cares_macros::cares_query_table! {
///     enum Queries {
///         web { name: "example.com", rr_type: A, class: IN },
///     }
/// }
///
/// let mut buf = [0u8; 64];
/// let written = match Queries::Web.encode(0x0010, &mut buf) {
///     Ok(value) => value,
///     Err(_) => panic!("encode failed"),
/// };
/// assert_eq!(written, 29);
/// assert_eq!(
///     &buf[..12],
///     &[
///         0x00, 0x10, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
///     ]
/// );
/// let decoded = match Queries::decode(&buf[..written]) {
///     Ok(value) => value,
///     Err(_) => panic!("decode failed"),
/// };
/// assert_eq!(decoded, Queries::Web);
/// assert_eq!(Queries::Web.slot_name(), "web");
/// assert_eq!(Queries::Web.qname(), "example.com");
/// assert_eq!(Queries::Web.rr_type(), 1);
/// assert_eq!(Queries::Web.dns_class(), 1);
/// assert_eq!(Queries::SLOT_COUNT, 1);
/// assert_eq!(Queries::DISPATCH[0].name, "web");
/// ```
#[proc_macro]
pub fn cares_query_table(input: TokenStream) -> TokenStream {
    match query_table::expand(input.into()) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
