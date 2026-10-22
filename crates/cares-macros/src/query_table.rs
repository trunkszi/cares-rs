//! Compile-time query validation and fixed-buffer DNS question routing.

use std::collections::HashSet;

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Ident, LitByteStr, LitStr, Token, Visibility, braced,
    ext::IdentExt,
    parse::{Parse, ParseStream},
};

struct Table {
    visibility: Visibility,
    name: Ident,
    slots: Vec<Slot>,
}

struct Slot {
    name: Ident,
    domain: LitStr,
    rr_type: Ident,
    class: Ident,
}

impl Parse for Table {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let visibility = input.parse()?;
        input.parse::<Token![enum]>()?;
        let name = input.parse()?;
        let body;
        braced!(body in input);
        let mut slots = Vec::new();
        while !body.is_empty() {
            slots.push(body.parse()?);
            if !body.is_empty() {
                body.parse::<Token![,]>()?;
            }
        }
        if slots.is_empty() {
            return Err(syn::Error::new(
                body.span(),
                "query table must contain a slot",
            ));
        }
        Ok(Self {
            visibility,
            name,
            slots,
        })
    }
}

impl Parse for Slot {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name = input.parse()?;
        let body;
        braced!(body in input);
        let mut domain = None;
        let mut rr_type = None;
        let mut class = None;
        while !body.is_empty() {
            let key: Ident = body.parse()?;
            body.parse::<Token![:]>()?;
            match key.to_string().as_str() {
                "name" if domain.is_none() => domain = Some(body.parse()?),
                "rr_type" if rr_type.is_none() => rr_type = Some(body.parse()?),
                "class" if class.is_none() => class = Some(body.parse()?),
                "name" | "rr_type" | "class" => {
                    return Err(syn::Error::new(key.span(), "duplicate query slot field"));
                }
                _ => return Err(syn::Error::new(key.span(), "unknown query slot field")),
            }
            if !body.is_empty() {
                body.parse::<Token![,]>()?;
            }
        }
        Ok(Self {
            name,
            domain: domain.ok_or_else(|| body.error("missing query name"))?,
            rr_type: rr_type.ok_or_else(|| body.error("missing rr_type"))?,
            class: class.ok_or_else(|| body.error("missing class"))?,
        })
    }
}

struct CheckedSlot {
    variant: Ident,
    name: String,
    domain: LitStr,
    wire: LitByteStr,
    question: LitByteStr,
    rr_type: u16,
    class: u16,
}

pub(crate) fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let table: Table = syn::parse2(input)?;
    let mut names = HashSet::new();
    let mut variants = HashSet::new();
    let mut tuples = HashSet::new();
    let slots = table
        .slots
        .into_iter()
        .map(|slot| {
            let name = slot.name.unraw().to_string();
            if !names.insert(name.clone()) {
                return Err(syn::Error::new(
                    slot.name.span(),
                    "duplicate query slot name",
                ));
            }
            let variant = variant_name(&slot.name)?;
            if !variants.insert(variant.to_string()) {
                return Err(syn::Error::new(
                    slot.name.span(),
                    "query slot enum variant collision",
                ));
            }
            let wire = domain_wire(&slot.domain)?;
            let rr_type = rr_code(&slot.rr_type)?;
            let class = class_code(&slot.class)?;
            if !tuples.insert((wire.clone(), rr_type, class)) {
                return Err(syn::Error::new(
                    slot.domain.span(),
                    "duplicate canonical DNS question",
                ));
            }
            let mut question = wire.clone();
            question.extend_from_slice(&rr_type.to_be_bytes());
            question.extend_from_slice(&class.to_be_bytes());
            Ok(CheckedSlot {
                variant,
                name,
                domain: slot.domain,
                wire: LitByteStr::new(&wire, Span::call_site()),
                question: LitByteStr::new(&question, Span::call_site()),
                rr_type,
                class,
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(emit(table.visibility, table.name, &slots))
}

fn variant_name(name: &Ident) -> syn::Result<Ident> {
    let mut variant = String::new();
    for part in name
        .unraw()
        .to_string()
        .split('_')
        .filter(|part| !part.is_empty())
    {
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            variant.extend(first.to_uppercase());
        }
        variant.extend(characters);
    }
    if variant == "Self" {
        return Err(syn::Error::new(
            name.span(),
            "slot produces the reserved variant Self",
        ));
    }
    syn::parse_str::<Ident>(&variant)
        .map(|mut value| {
            value.set_span(name.span());
            value
        })
        .map_err(|_| syn::Error::new(name.span(), "slot does not produce a valid enum variant"))
}

fn domain_wire(domain: &LitStr) -> syn::Result<Vec<u8>> {
    let value = domain.value();
    let error = |message| syn::Error::new(domain.span(), message);
    if value == "." {
        return Ok(vec![0]);
    }
    if value.is_empty() || !value.is_ascii() {
        return Err(error("DNS name must be nonempty ASCII presentation text"));
    }
    let bytes = value.as_bytes();
    let mut wire = vec![0];
    let mut label = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let mut byte = bytes[cursor];
        cursor += 1;
        if byte == b'.' {
            let length = wire.len() - label - 1;
            if length == 0 {
                return Err(error("DNS name contains an empty label"));
            }
            wire[label] = length as u8;
            label = wire.len();
            wire.push(0);
            continue;
        }
        if byte == b'\\' {
            byte = *bytes
                .get(cursor)
                .ok_or_else(|| error("incomplete DNS escape"))?;
            cursor += 1;
            if byte.is_ascii_digit() {
                let second = *bytes
                    .get(cursor)
                    .ok_or_else(|| error("DNS decimal escape needs three digits"))?;
                let third = *bytes
                    .get(cursor + 1)
                    .ok_or_else(|| error("DNS decimal escape needs three digits"))?;
                if !second.is_ascii_digit() || !third.is_ascii_digit() {
                    return Err(error("DNS decimal escape needs three digits"));
                }
                let number = u16::from(byte - b'0') * 100
                    + u16::from(second - b'0') * 10
                    + u16::from(third - b'0');
                byte = u8::try_from(number).map_err(|_| error("DNS escape exceeds 255"))?;
                cursor += 2;
            }
        } else if !byte.is_ascii_graphic() {
            return Err(error("DNS labels require printable ASCII or escaped bytes"));
        }
        wire.push(byte.to_ascii_lowercase());
        if wire.len() - label - 1 > 63 {
            return Err(error("DNS label exceeds 63 bytes"));
        }
    }
    let length = wire.len() - label - 1;
    if length != 0 {
        wire[label] = length as u8;
        wire.push(0);
    }
    if wire.len() > 255 {
        return Err(error("DNS name exceeds 255 wire bytes"));
    }
    Ok(wire)
}

fn rr_code(value: &Ident) -> syn::Result<u16> {
    match value.to_string().as_str() {
        "A" => Ok(1),
        "NS" => Ok(2),
        "CNAME" => Ok(5),
        "SOA" => Ok(6),
        "PTR" => Ok(12),
        "HINFO" => Ok(13),
        "MX" => Ok(15),
        "TXT" => Ok(16),
        "SIG" => Ok(24),
        "AAAA" => Ok(28),
        "SRV" => Ok(33),
        "NAPTR" => Ok(35),
        "OPT" => Ok(41),
        "TLSA" => Ok(52),
        "SVCB" => Ok(64),
        "HTTPS" => Ok(65),
        "ANY" => Ok(255),
        "URI" => Ok(256),
        "CAA" => Ok(257),
        _ => Err(syn::Error::new(value.span(), "unsupported DNS record type")),
    }
}

fn class_code(value: &Ident) -> syn::Result<u16> {
    match value.to_string().as_str() {
        "IN" => Ok(1),
        "CS" => Ok(2),
        "CH" | "CHAOS" => Ok(3),
        "HS" | "HESIOD" => Ok(4),
        "NONE" => Ok(254),
        "ANY" => Ok(255),
        _ => Err(syn::Error::new(value.span(), "unsupported DNS class")),
    }
}

fn emit(visibility: Visibility, name: Ident, slots: &[CheckedSlot]) -> TokenStream {
    let dispatch = format_ident!("{}Dispatch", name.unraw());
    let variants = slots.iter().map(|slot| &slot.variant).collect::<Vec<_>>();
    let names = slots.iter().map(|slot| &slot.name).collect::<Vec<_>>();
    let domains = slots.iter().map(|slot| &slot.domain).collect::<Vec<_>>();
    let wires = slots.iter().map(|slot| &slot.wire).collect::<Vec<_>>();
    let questions = slots.iter().map(|slot| &slot.question).collect::<Vec<_>>();
    let types = slots.iter().map(|slot| slot.rr_type).collect::<Vec<_>>();
    let classes = slots.iter().map(|slot| slot.class).collect::<Vec<_>>();
    let count = slots.len();
    let dispatch_alias = (!slots.iter().any(|slot| slot.variant == "DISPATCH")).then(|| {
        quote! {
            /// Query slots in declaration order; also available through `Self::dispatch()`.
            pub const DISPATCH: [#dispatch; #count] = Self::__CARES_QUERY_TABLE_DISPATCH;
        }
    });
    quote! {
        /// A statically validated DNS question route.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #visibility enum #name {
            #(#[doc = #names] #variants,)*
        }

        /// Static metadata for one DNS question route.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #visibility struct #dispatch {
            /// Slot identifier from the query table.
            pub name: &'static ::core::primitive::str,
            /// Presentation-format question name.
            pub qname: &'static ::core::primitive::str,
            /// Numeric resource-record type.
            pub rr_type: ::core::primitive::u16,
            /// Numeric DNS class.
            pub dns_class: ::core::primitive::u16,
        }

        impl #name {
            /// Number of statically declared query slots.
            pub const SLOT_COUNT: ::core::primitive::usize = #count;
            const __CARES_QUERY_TABLE_DISPATCH: [#dispatch; #count] = [#(
                #dispatch { name: #names, qname: #domains, rr_type: #types, dns_class: #classes },
            )*];

            #dispatch_alias

            /// Returns query slots in declaration order.
            pub const fn dispatch() -> &'static [#dispatch; #count] {
                &Self::__CARES_QUERY_TABLE_DISPATCH
            }

            /// Returns the declared slot identifier.
            pub const fn slot_name(self) -> &'static ::core::primitive::str {
                match self { #(Self::#variants => #names,)* }
            }
            /// Returns the declared presentation-format domain name.
            pub const fn qname(self) -> &'static ::core::primitive::str {
                match self { #(Self::#variants => #domains,)* }
            }
            /// Returns the wire resource-record type.
            pub const fn rr_type(self) -> ::core::primitive::u16 {
                match self { #(Self::#variants => #types,)* }
            }
            /// Returns the wire DNS class.
            pub const fn dns_class(self) -> ::core::primitive::u16 {
                match self { #(Self::#variants => #classes,)* }
            }

            /// Encodes one recursion-desired question without allocating.
            ///
            /// # Errors
            /// Returns an error without changing the buffer if it is too short.
            pub fn encode(self, id: ::core::primitive::u16, buffer: &mut [::core::primitive::u8]) -> ::core::result::Result<::core::primitive::usize, &'static ::core::primitive::str> {
                let question: &[::core::primitive::u8] = match self { #(Self::#variants => #questions,)* };
                let length = 12 + question.len();
                if buffer.len() < length {
                    return ::core::result::Result::Err("DNS query buffer is too short");
                }
                buffer[..12].copy_from_slice(&[
                    (id >> 8) as ::core::primitive::u8, id as ::core::primitive::u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                ]);
                buffer[12..length].copy_from_slice(question);
                ::core::result::Result::Ok(length)
            }

            /// Routes the first question, accepting compressed and mixed-case names.
            ///
            /// The remaining questions and resource records are outside this routing boundary.
            ///
            /// # Errors
            /// Rejects truncated headers or questions, nonstandard opcodes, invalid label tags,
            /// compression loops, overlong names, and questions absent from this table.
            pub fn decode(packet: &[::core::primitive::u8]) -> ::core::result::Result<Self, &'static ::core::primitive::str> {
                if packet.len() < 12 {
                    return ::core::result::Result::Err("truncated DNS header");
                }
                if packet[2] & 0x78 != 0 || packet[3] & 0x40 != 0 {
                    return ::core::result::Result::Err("unsupported DNS header flags");
                }
                if packet[4] == 0 && packet[5] == 0 {
                    return ::core::result::Result::Err("DNS message has no question");
                }
                let (wire, length, rr_type, class) = Self::__decode_question(packet)?;
                #(
                    if rr_type == #types && class == #classes
                        && wire[..length].eq_ignore_ascii_case(#wires)
                    {
                        return ::core::result::Result::Ok(Self::#variants);
                    }
                )*
                ::core::result::Result::Err("DNS question is absent from the query table")
            }

            fn __decode_question(packet: &[::core::primitive::u8]) -> ::core::result::Result<([::core::primitive::u8; 255], ::core::primitive::usize, ::core::primitive::u16, ::core::primitive::u16), &'static ::core::primitive::str> {
                let mut wire = [0_u8; 255];
                let mut length = 0;
                let mut cursor = 12;
                let mut question_end = ::core::option::Option::None;
                let mut visited = [0_u8; 2048];
                loop {
                    let byte = *packet.get(cursor).ok_or("truncated DNS question name")?;
                    if byte & 0xc0 == 0xc0 {
                        let next = *packet.get(cursor + 1).ok_or("truncated DNS pointer")?;
                        if question_end.is_none() {
                            question_end = ::core::option::Option::Some(cursor + 2);
                        }
                        cursor = (::core::primitive::usize::from(byte & 0x3f) << 8) | ::core::primitive::usize::from(next);
                        if cursor < 12 || cursor >= packet.len() {
                            return ::core::result::Result::Err("invalid DNS compression target");
                        }
                        let mask = 1_u8 << (cursor % 8);
                        if visited[cursor / 8] & mask != 0 {
                            return ::core::result::Result::Err("DNS compression loop");
                        }
                        visited[cursor / 8] |= mask;
                        continue;
                    }
                    if byte & 0xc0 != 0 {
                        return ::core::result::Result::Err("unsupported DNS label tag");
                    }
                    let size = ::core::primitive::usize::from(byte);
                    if length + size + 1 > wire.len() {
                        return ::core::result::Result::Err("DNS question name exceeds 255 bytes");
                    }
                    wire[length] = byte;
                    length += 1;
                    cursor += 1;
                    if size == 0 {
                        let end = match question_end { ::core::option::Option::Some(end) => end, ::core::option::Option::None => cursor };
                        let fields = packet.get(end..end + 4).ok_or("truncated DNS question fields")?;
                        return ::core::result::Result::Ok((wire, length,
                            ::core::primitive::u16::from_be_bytes([fields[0], fields[1]]),
                            ::core::primitive::u16::from_be_bytes([fields[2], fields[3]])));
                    }
                    let label = packet.get(cursor..cursor + size).ok_or("truncated DNS label")?;
                    wire[length..length + size].copy_from_slice(label);
                    length += size;
                    cursor += size;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::expand;

    #[test]
    fn unit_scenario_rejects_invalid_query_declarations() {
        let invalid = [
            quote! { enum Empty {} },
            quote! { enum T { a { name: "", rr_type: A, class: IN } } },
            quote! { enum T { a { name: "a..b", rr_type: A, class: IN } } },
            quote! { enum T { a { name: "a", rr_type: RawRr, class: IN } } },
            quote! { enum T { a { name: "a", rr_type: A, class: BAD } } },
            quote! { enum T { a { name: "a", name: "b", rr_type: A, class: IN } } },
            quote! { enum T { a { name: "A.", rr_type: A, class: CH },
            b { name: "a", rr_type: A, class: CHAOS } } },
            quote! { enum T { web_a { name: "a", rr_type: A, class: IN },
            WebA { name: "b", rr_type: A, class: IN } } },
            quote! { enum T { a { name: "a", rr_type: A, class: IN },
            a { name: "b", rr_type: A, class: IN } } },
            quote! { enum T { self { name: "a", rr_type: A, class: IN } } },
        ];
        for input in invalid {
            assert!(expand(input).is_err());
        }
    }

    #[test]
    fn unit_scenario_validates_dns_wire_limits() {
        let label = "a".repeat(64);
        let domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        for name in [
            label,
            domain,
            String::from("example\\999.com"),
            String::from("example\\12.com"),
        ] {
            assert!(
                expand(quote! { enum T { a { name: #name, rr_type: A, class: IN } } }).is_err()
            );
        }
        let maximum = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(expand(quote! { enum T { a { name: #maximum, rr_type: A, class: IN } } }).is_ok());
        assert!(
            expand(
                quote! { enum T { root { name: ".", rr_type: NS, class: IN },
                service { name: "_dns._udp.Example.", rr_type: SRV, class: IN },
                escaped { name: "one\\.label.\\065", rr_type: TXT, class: IN } } }
            )
            .is_ok()
        );
    }
}
