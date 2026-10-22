//! `#[derive(DnsRecordExtract)]` expansion.
//!
//! Generated impls call the public `cares` record models. The question is added
//! before the resource record so a later wire parse sees exactly one question.

use proc_macro2::TokenStream;
use quote::{ToTokens, format_ident, quote};
use syn::{Data, DeriveInput, Fields, FieldsNamed, Ident, LitStr, Type, spanned::Spanned};

pub(crate) fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            input.generics,
            "DnsRecordExtract does not support generic structs",
        ));
    }
    let fields = named_fields(&input)?;
    let (rr_type, section) = dns_attr(&input)?;
    let section = section_ident(&section)?;
    let model = model_for(&rr_type)?;
    let bound = bind_fields(fields, model)?;
    Ok(emit(&input.ident, &input.vis, model, &section, &bound))
}

fn named_fields(input: &DeriveInput) -> syn::Result<&FieldsNamed> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(fields),
            _ => Err(syn::Error::new_spanned(
                input,
                "DnsRecordExtract requires a struct with named fields",
            )),
        },
        _ => Err(syn::Error::new_spanned(
            input,
            "DnsRecordExtract requires a struct with named fields",
        )),
    }
}

fn dns_attr(input: &DeriveInput) -> syn::Result<(LitStr, LitStr)> {
    let mut rr_type = None;
    let mut section = None;
    let mut seen = false;
    for attr in &input.attrs {
        if !attr.path().is_ident("dns") {
            continue;
        }
        if seen {
            return Err(syn::Error::new_spanned(attr, "duplicate #[dns] attribute"));
        }
        seen = true;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rr_type") {
                let lit: LitStr = meta.value()?.parse()?;
                if rr_type.is_some() {
                    return Err(meta.error("duplicate rr_type"));
                }
                rr_type = Some(lit);
                Ok(())
            } else if meta.path.is_ident("section") {
                let lit: LitStr = meta.value()?.parse()?;
                if section.is_some() {
                    return Err(meta.error("duplicate section"));
                }
                section = Some(lit);
                Ok(())
            } else {
                Err(meta.error("unsupported dns key; expected rr_type or section"))
            }
        })?;
    }
    let rr_type = rr_type.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            "missing #[dns(rr_type = \"...\", section = \"...\")]",
        )
    })?;
    let section = section.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            "missing #[dns(rr_type = \"...\", section = \"...\")]",
        )
    })?;
    Ok((rr_type, section))
}

struct Model {
    rr: &'static str,
    code: u16,
    variant: &'static str,
    model: &'static str,
    extract: &'static str,
    fields: &'static [SpecField],
}

struct SpecField {
    name: &'static str,
    ty: FieldTy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldTy {
    Ipv4,
    Ipv6,
    U8,
    U16,
    U32,
    String,
    Bytes,
    Chunks,
    Params,
}

impl FieldTy {
    const fn is_copy(self) -> bool {
        matches!(
            self,
            Self::Ipv4 | Self::Ipv6 | Self::U8 | Self::U16 | Self::U32
        )
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "Ipv4Addr",
            Self::Ipv6 => "Ipv6Addr",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::String => "String",
            Self::Bytes => "Vec<u8>",
            Self::Chunks => "Vec<Vec<u8>>",
            Self::Params => "Vec<(u16, Vec<u8>)>",
        }
    }

    fn matches(self, canonical: &str) -> bool {
        let ok = self.label().replace(' ', "");
        canonical == ok || (self == Self::Params && (canonical == "DnsOptions" || canonical == ok))
    }
}

const A_FIELDS: &[SpecField] = &[SpecField {
    name: "address",
    ty: FieldTy::Ipv4,
}];
const AAAA_FIELDS: &[SpecField] = &[SpecField {
    name: "address",
    ty: FieldTy::Ipv6,
}];
const CNAME_FIELDS: &[SpecField] = &[SpecField {
    name: "cname",
    ty: FieldTy::String,
}];
const NS_FIELDS: &[SpecField] = &[SpecField {
    name: "nsdname",
    ty: FieldTy::String,
}];
const PTR_FIELDS: &[SpecField] = &[SpecField {
    name: "dname",
    ty: FieldTy::String,
}];
const MX_FIELDS: &[SpecField] = &[
    SpecField {
        name: "preference",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "exchange",
        ty: FieldTy::String,
    },
];
const TXT_FIELDS: &[SpecField] = &[SpecField {
    name: "chunks",
    ty: FieldTy::Chunks,
}];
const SRV_FIELDS: &[SpecField] = &[
    SpecField {
        name: "priority",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "weight",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "port",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "target",
        ty: FieldTy::String,
    },
];
const SOA_FIELDS: &[SpecField] = &[
    SpecField {
        name: "mname",
        ty: FieldTy::String,
    },
    SpecField {
        name: "rname",
        ty: FieldTy::String,
    },
    SpecField {
        name: "serial",
        ty: FieldTy::U32,
    },
    SpecField {
        name: "refresh",
        ty: FieldTy::U32,
    },
    SpecField {
        name: "retry",
        ty: FieldTy::U32,
    },
    SpecField {
        name: "expire",
        ty: FieldTy::U32,
    },
    SpecField {
        name: "minimum",
        ty: FieldTy::U32,
    },
];
const NAPTR_FIELDS: &[SpecField] = &[
    SpecField {
        name: "order",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "preference",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "flags",
        ty: FieldTy::String,
    },
    SpecField {
        name: "services",
        ty: FieldTy::String,
    },
    SpecField {
        name: "regexp",
        ty: FieldTy::String,
    },
    SpecField {
        name: "replacement",
        ty: FieldTy::String,
    },
];
const URI_FIELDS: &[SpecField] = &[
    SpecField {
        name: "priority",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "weight",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "target",
        ty: FieldTy::String,
    },
];
const CAA_FIELDS: &[SpecField] = &[
    SpecField {
        name: "critical",
        ty: FieldTy::U8,
    },
    SpecField {
        name: "tag",
        ty: FieldTy::String,
    },
    SpecField {
        name: "value",
        ty: FieldTy::Bytes,
    },
];
const TLSA_FIELDS: &[SpecField] = &[
    SpecField {
        name: "cert_usage",
        ty: FieldTy::U8,
    },
    SpecField {
        name: "selector",
        ty: FieldTy::U8,
    },
    SpecField {
        name: "matching_type",
        ty: FieldTy::U8,
    },
    SpecField {
        name: "data",
        ty: FieldTy::Bytes,
    },
];
const HTTPS_FIELDS: &[SpecField] = &[
    SpecField {
        name: "priority",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "target",
        ty: FieldTy::String,
    },
    SpecField {
        name: "params",
        ty: FieldTy::Params,
    },
];
const OPT_FIELDS: &[SpecField] = &[
    SpecField {
        name: "udp_size",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "version",
        ty: FieldTy::U8,
    },
    SpecField {
        name: "flags",
        ty: FieldTy::U16,
    },
    SpecField {
        name: "options",
        ty: FieldTy::Params,
    },
];

const MODELS: &[Model] = &[
    Model {
        rr: "A",
        code: 1,
        variant: "A",
        model: "ARecord",
        extract: "as_a",
        fields: A_FIELDS,
    },
    Model {
        rr: "AAAA",
        code: 28,
        variant: "AAAA",
        model: "AaaaRecord",
        extract: "as_aaaa",
        fields: AAAA_FIELDS,
    },
    Model {
        rr: "CNAME",
        code: 5,
        variant: "CNAME",
        model: "CnameRecord",
        extract: "as_cname",
        fields: CNAME_FIELDS,
    },
    Model {
        rr: "NS",
        code: 2,
        variant: "NS",
        model: "NsRecord",
        extract: "as_ns",
        fields: NS_FIELDS,
    },
    Model {
        rr: "PTR",
        code: 12,
        variant: "PTR",
        model: "PtrRecord",
        extract: "as_ptr_record",
        fields: PTR_FIELDS,
    },
    Model {
        rr: "MX",
        code: 15,
        variant: "MX",
        model: "MxRecord",
        extract: "as_mx",
        fields: MX_FIELDS,
    },
    Model {
        rr: "TXT",
        code: 16,
        variant: "TXT",
        model: "TxtRecord",
        extract: "as_txt",
        fields: TXT_FIELDS,
    },
    Model {
        rr: "SRV",
        code: 33,
        variant: "SRV",
        model: "SrvRecord",
        extract: "as_srv",
        fields: SRV_FIELDS,
    },
    Model {
        rr: "SOA",
        code: 6,
        variant: "SOA",
        model: "SoaRecord",
        extract: "as_soa",
        fields: SOA_FIELDS,
    },
    Model {
        rr: "NAPTR",
        code: 35,
        variant: "NAPTR",
        model: "NaptrRecord",
        extract: "as_naptr",
        fields: NAPTR_FIELDS,
    },
    Model {
        rr: "URI",
        code: 256,
        variant: "URI",
        model: "UriRecord",
        extract: "as_uri",
        fields: URI_FIELDS,
    },
    Model {
        rr: "CAA",
        code: 257,
        variant: "CAA",
        model: "CaaRecord",
        extract: "as_caa",
        fields: CAA_FIELDS,
    },
    Model {
        rr: "TLSA",
        code: 52,
        variant: "TLSA",
        model: "TlsaRecord",
        extract: "as_tlsa",
        fields: TLSA_FIELDS,
    },
    Model {
        rr: "HTTPS",
        code: 65,
        variant: "HTTPS",
        model: "HttpsRecord",
        extract: "as_https",
        fields: HTTPS_FIELDS,
    },
    Model {
        rr: "SVCB",
        code: 64,
        variant: "SVCB",
        model: "SvcbRecord",
        extract: "as_svcb",
        fields: HTTPS_FIELDS,
    },
    Model {
        rr: "OPT",
        code: 41,
        variant: "OPT",
        model: "OptRecord",
        extract: "as_opt",
        fields: OPT_FIELDS,
    },
];

fn model_for(rr_type: &LitStr) -> syn::Result<&'static Model> {
    let name = rr_type.value();
    for model in MODELS {
        if model.rr == name {
            return Ok(model);
        }
    }
    Err(syn::Error::new(
        rr_type.span(),
        format!(
            "unsupported rr_type \"{name}\"; expected one of A, AAAA, CNAME, NS, PTR, MX, TXT, \
             SRV, SOA, NAPTR, URI, CAA, TLSA, HTTPS, SVCB, OPT"
        ),
    ))
}

fn section_ident(section: &LitStr) -> syn::Result<Ident> {
    let name = section.value();
    let ident = match name.as_str() {
        "Answer" | "Authority" | "Additional" => format_ident!("{name}"),
        _ => {
            return Err(syn::Error::new(
                section.span(),
                "unsupported section; expected \"Answer\", \"Authority\", or \"Additional\"",
            ));
        }
    };
    Ok(ident)
}

struct BoundField {
    ident: Ident,
    ty: FieldTy,
}

struct Bound {
    fields: Vec<BoundField>,
    owner: Option<Ident>,
    ttl: Option<Ident>,
    dns_class: Option<Ident>,
}

fn bind_fields(fields: &FieldsNamed, model: &Model) -> syn::Result<Bound> {
    let mut chosen = Vec::new();
    let mut owner = None;
    let mut ttl = None;
    let mut dns_class = None;
    let mut seen = vec![false; model.fields.len()];
    for field in &fields.named {
        let Some(ident) = field.ident.clone() else {
            return Err(syn::Error::new_spanned(
                field,
                "DnsRecordExtract requires named fields",
            ));
        };
        let name = ident.to_string();
        if let Some(index) = model.fields.iter().position(|spec| spec.name == name) {
            if seen[index] {
                return Err(syn::Error::new_spanned(ident, "duplicate record field"));
            }
            let spec = &model.fields[index];
            let got = canonical_type(&field.ty);
            if !spec.ty.matches(&got) {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    format!("field `{name}` must have type {}", spec.ty.label()),
                ));
            }
            seen[index] = true;
            chosen.push(BoundField { ident, ty: spec.ty });
            continue;
        }
        match name.as_str() {
            "owner" if type_is(&field.ty, "String") => owner = Some(ident),
            "ttl" if type_is(&field.ty, "u32") => ttl = Some(ident),
            "dns_class" if type_is(&field.ty, "DnsClass") => dns_class = Some(ident),
            "owner" | "ttl" | "dns_class" => {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    format!("optional field `{name}` has the wrong type"),
                ));
            }
            _ => {
                return Err(syn::Error::new_spanned(
                    ident,
                    format!(
                        "field `{name}` is not part of the {} record model",
                        model.rr
                    ),
                ));
            }
        }
    }
    for (spec, present) in model.fields.iter().zip(seen) {
        if !present {
            return Err(syn::Error::new(
                fields.span(),
                format!(
                    "missing {} field `{}` of type {}",
                    model.rr,
                    spec.name,
                    spec.ty.label()
                ),
            ));
        }
    }
    Ok(Bound {
        fields: chosen,
        owner,
        ttl,
        dns_class,
    })
}

fn type_is(ty: &Type, expected: &str) -> bool {
    canonical_type(ty) == expected
}

fn canonical_type(ty: &Type) -> String {
    let mut text = ty.to_token_stream().to_string();
    text.retain(|ch| !ch.is_whitespace());
    loop {
        let next = text
            .replace("::std::", "std::")
            .replace("std::vec::", "")
            .replace("std::string::", "")
            .replace("std::net::", "")
            .replace("::cares::record_rr::", "")
            .replace("cares::record_rr::", "")
            .replace("::cares::types::", "")
            .replace("cares::types::", "");
        if next == text {
            return text;
        }
        text = next;
    }
}

fn emit(
    name: &Ident,
    vis: &syn::Visibility,
    model: &Model,
    section: &Ident,
    bound: &Bound,
) -> TokenStream {
    let variant = format_ident!("{}", model.variant);
    let model_ty = format_ident!("{}", model.model);
    let extract = format_ident!("{}", model.extract);
    let code = model.code;
    let read_fields = bound.fields.iter().map(|field| {
        let ident = &field.ident;
        quote! { #ident: parsed.#ident }
    });
    let owner_read = bound.owner.as_ref().map(|ident| {
        quote! { #ident: rr.name()?.to_owned(), }
    });
    let ttl_read = bound.ttl.as_ref().map(|ident| quote! { #ident: rr.ttl(), });
    let class_read = bound
        .dns_class
        .as_ref()
        .map(|ident| quote! { #ident: rr.class()?, });
    let write_fields = bound.fields.iter().map(|field| {
        let ident = &field.ident;
        if field.ty.is_copy() {
            quote! { #ident: self.#ident }
        } else {
            quote! { #ident: ::core::clone::Clone::clone(&self.#ident) }
        }
    });
    // Own the question name before `add_record` borrows `self`.
    let owner_string = if let Some(ident) = &bound.owner {
        quote! { ::core::clone::Clone::clone(&self.#ident) }
    } else {
        quote! { ::std::string::String::from(".") }
    };
    let ttl_expr = if let Some(ident) = &bound.ttl {
        quote! { self.#ident }
    } else {
        quote! { 0u32 }
    };
    let class_expr = if let Some(ident) = &bound.dns_class {
        quote! { self.#ident }
    } else {
        quote! { ::cares::types::DnsClass::IN }
    };
    let section_name = section.to_string();
    quote! {
        impl #name {
            /// Numeric DNS type code selected by `rr_type`.
            #vis const RR_TYPE_CODE: u16 = #code;

            /// Collect every matching resource record in the annotated section.
            ///
            /// # Errors
            /// Returns an error when a matching record cannot be decoded.
            ///
            /// # Panics
            /// This function does not panic.
            #vis fn extract_from_record(
                record: ::cares::record::DnsRecordRef<'_>,
            ) -> ::cares::error::Result<::std::vec::Vec<Self>> {
                record.records::<Self>(::cares::types::DnsSection::#section)
            }
        }

        impl ::cares::record_rr::FromDnsRr for #name {
            const RECORD_TYPE: ::cares::types::DnsRecordType = ::cares::types::DnsRecordType::#variant;

            fn from_dns_rr(
                rr: ::cares::record_rr::DnsRr<'_>,
            ) -> ::cares::error::Result<Self> {
                let parsed = rr.#extract()?;
                ::core::result::Result::Ok(Self {
                    #(#read_fields,)*
                    #owner_read
                    #ttl_read
                    #class_read
                })
            }
        }

        impl ::cares::record_rr::IntoDnsRr for #name {
            const RECORD_TYPE: ::cares::types::DnsRecordType = ::cares::types::DnsRecordType::#variant;

            fn write_dns_rr(
                &self,
                rr: &mut ::cares::record_rr::DnsRrMut<'_>,
            ) -> ::cares::error::Result<()> {
                let parsed = ::cares::record_rr::#model_ty { #(#write_fields,)* };
                ::cares::record_rr::IntoDnsRr::write_dns_rr(&parsed, rr)
            }
        }

        impl ::cares::record::FromDnsRecord for #name {
            fn from_dns_record(
                record: ::cares::record::DnsRecordRef<'_>,
            ) -> ::cares::error::Result<Self> {
                let found = record.records::<Self>(::cares::types::DnsSection::#section)?;
                let mut iter = found.into_iter();
                match (iter.next(), iter.next()) {
                    (
                        ::core::option::Option::Some(value),
                        ::core::option::Option::None,
                    ) => ::core::result::Result::Ok(value),
                    _ => ::core::result::Result::Err(::cares::error::AresError::invalid_record(
                        ::std::concat!(
                            "expected exactly one matching resource record in ",
                            #section_name
                        ),
                    )),
                }
            }
        }

        impl ::cares::record::IntoDnsRecord for #name {
            fn into_dns_record(self) -> ::cares::error::Result<::cares::record::DnsRecord> {
                let ttl = #ttl_expr;
                let dns_class = #class_expr;
                let owner_owned = #owner_string;
                let owner: &str = owner_owned.as_str();
                let mut record = ::cares::record::DnsRecord::new(
                    0u16,
                    ::cares::types::DnsFlags::QR,
                    ::cares::types::DnsOpcode::Query,
                    ::cares::types::DnsRcode::NoError,
                )?;
                record.query_add(
                    owner,
                    <Self as ::cares::record_rr::IntoDnsRr>::RECORD_TYPE,
                    dns_class,
                )?;
                record.add_record(
                    ::cares::types::DnsSection::#section,
                    owner,
                    dns_class,
                    ttl,
                    &self,
                )?;
                ::core::result::Result::Ok(record)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::expand;

    #[test]
    fn rejects_unknown_type() {
        let expanded = expand(quote! {
            #[dns(rr_type = "HINFO", section = "Answer")]
            struct Host { address: std::net::Ipv4Addr }
        });
        assert!(expanded.is_err());
    }

    #[test]
    fn rejects_bad_section_and_missing_attr() {
        let bad_section = expand(quote! {
            #[dns(rr_type = "A", section = "Question")]
            struct Host { address: std::net::Ipv4Addr }
        });
        let missing = expand(quote! {
            struct Host { address: std::net::Ipv4Addr }
        });
        assert!(bad_section.is_err());
        assert!(missing.is_err());
    }

    #[test]
    fn ptr_expansion_uses_public_accessor() {
        let expanded = expand(quote! {
            #[dns(rr_type = "PTR", section = "Answer")]
            struct PtrHost { dname: String }
        });
        let Ok(tokens) = expanded else {
            panic!("ptr expansion failed");
        };
        let text = tokens.to_string();
        assert!(text.contains("as_ptr_record"));
        assert!(text.contains("query_add"));
        assert!(text.contains("dname"));
        assert!(!text.contains(". as_ptr ("));
    }
}
