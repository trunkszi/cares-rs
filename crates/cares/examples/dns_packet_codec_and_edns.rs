//! Build, serialize, parse, and decode a DNS response carrying an EDNS0 OPT record.
//!
//! Everything runs in memory: the message is written to a wire buffer and parsed
//! back without touching a socket.

use std::net::{Ipv4Addr, Ipv6Addr};

use cares::{
    DnsClass, DnsRecord, DnsRecordExtract, DnsRecordType, DnsSection,
    record_rr::{ARecord, AaaaRecord, OptRecord, SrvRecord, TxtRecord},
    types::DnsFlags,
};

/// Typed view of the IPv4 answers in the response.
#[derive(DnsRecordExtract)]
#[dns(rr_type = "A", section = "Answer")]
struct WebAddress {
    address: Ipv4Addr,
    owner: String,
    ttl: u32,
    dns_class: DnsClass,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut record = DnsRecord::builder()
        .id(0x1234)
        .flags(DnsFlags::QR | DnsFlags::RD | DnsFlags::RA)
        .question("www.example.test", DnsRecordType::A, DnsClass::IN)
        .build()?;

    record.add_record(
        DnsSection::Answer,
        "www.example.test",
        DnsClass::IN,
        60,
        &ARecord {
            address: Ipv4Addr::new(192, 0, 2, 10),
        },
    )?;
    record.add_record(
        DnsSection::Answer,
        "www.example.test",
        DnsClass::IN,
        60,
        &AaaaRecord {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
        },
    )?;
    record.add_record(
        DnsSection::Answer,
        "www.example.test",
        DnsClass::IN,
        60,
        &TxtRecord {
            chunks: vec![b"codec=edns0".to_vec()],
        },
    )?;
    record.add_record(
        DnsSection::Answer,
        "_https._tcp.example.test",
        DnsClass::IN,
        60,
        &SrvRecord {
            priority: 10,
            weight: 5,
            port: 8443,
            target: "svc.example.test".to_owned(),
        },
    )?;
    // c-ares validates the OPT class as a DNS class; the advertised payload
    // size is carried by OptRecord::udp_size instead.
    record.add_record(
        DnsSection::Additional,
        "",
        DnsClass::IN,
        0,
        &OptRecord {
            udp_size: 1232,
            version: 0,
            flags: 0,
            options: Vec::new(),
        },
    )?;

    let wire = record.write_wire()?;
    println!("wire length: {} bytes", wire.len());

    let parsed = DnsRecord::parse_wire(&wire)?;
    let question = parsed.question(0)?;
    println!(
        "question: {} type={:?} class={}",
        question.name,
        question.record_type,
        question.class.as_raw()
    );
    println!("answer count: {}", parsed.rr_count(DnsSection::Answer));
    println!(
        "additional count: {}",
        parsed.rr_count(DnsSection::Additional)
    );

    for index in 0..parsed.rr_count(DnsSection::Answer) {
        let rr = parsed.rr(DnsSection::Answer, index)?;
        match rr.record_type()? {
            DnsRecordType::A => println!(
                "answer {index}: A owner={} ttl={} address={}",
                rr.name()?,
                rr.ttl(),
                rr.as_a()?.address
            ),
            DnsRecordType::AAAA => println!(
                "answer {index}: AAAA owner={} ttl={} address={}",
                rr.name()?,
                rr.ttl(),
                rr.as_aaaa()?.address
            ),
            DnsRecordType::TXT => {
                let txt = rr.as_txt()?;
                let chunks: Vec<String> = txt
                    .chunks
                    .iter()
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect();
                println!(
                    "answer {index}: TXT owner={} ttl={} chunks={:?}",
                    rr.name()?,
                    rr.ttl(),
                    chunks
                );
            }
            DnsRecordType::SRV => {
                let srv = rr.as_srv()?;
                println!(
                    "answer {index}: SRV owner={} ttl={} priority={} weight={} port={} target={}",
                    rr.name()?,
                    rr.ttl(),
                    srv.priority,
                    srv.weight,
                    srv.port,
                    srv.target
                );
            }
            other => println!("answer {index}: {:?} owner={}", other, rr.name()?),
        }
    }

    let opt_rr = parsed.rr(DnsSection::Additional, 0)?;
    let opt = opt_rr.as_opt()?;
    println!("edns owner: {:?}", opt_rr.name()?);
    println!("edns payload size: {}", opt.udp_size);
    println!("edns version: {}", opt.version);
    println!("edns flags: 0x{:04x}", opt.flags);
    println!("edns option count: {}", opt.options.len());

    let web_addresses = WebAddress::extract_from_record(parsed.as_ref())?;
    println!("derived type code: {}", WebAddress::RR_TYPE_CODE);
    println!("extracted A records: {}", web_addresses.len());
    for address in &web_addresses {
        println!(
            "extracted: owner={} ttl={} class={} address={}",
            address.owner,
            address.ttl,
            address.dns_class.as_raw(),
            address.address
        );
    }

    Ok(())
}
