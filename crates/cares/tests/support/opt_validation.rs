//! OPT records have message-wide cardinality, owner, and section constraints.

use cares::{
    error::{AresError, Result},
    record::DnsRecord,
    record_rr::OptRecord,
    types::{DnsClass, DnsRcode, DnsRecordType, DnsSection},
};

fn message(rcode: DnsRcode, locations: &[(DnsSection, &str)]) -> Result<DnsRecord> {
    let mut record = DnsRecord::builder()
        .rcode(rcode)
        .question("example.test", DnsRecordType::A, DnsClass::IN)
        .build()?;
    let opt = OptRecord {
        udp_size: 1232,
        version: 0,
        flags: 0,
        options: Vec::new(),
    };
    for &(section, owner) in locations {
        record.add_record(section, owner, DnsClass::IN, 0, &opt)?;
    }
    Ok(record)
}

#[test]
fn invalid_opt_layouts_fail_every_export_and_copy() -> Result<()> {
    use DnsSection::{Additional, Answer, Authority};
    let layouts: &[&[(DnsSection, &str)]] = &[
        &[(Additional, ""), (Additional, ".")],
        &[(Additional, ""), (Answer, "")],
        &[(Authority, ""), (Additional, "")],
        &[(Answer, "")],
        &[(Authority, ".")],
        &[(Additional, "bad.test")],
    ];
    for rcode in [DnsRcode::NoError, DnsRcode::BadCookie] {
        for &layout in layouts {
            let record = message(rcode, layout)?;
            let borrowed = record.as_ref();
            for result in [
                record.write_wire(),
                record.write(),
                borrowed.write_wire(),
                borrowed.write(),
            ] {
                assert!(
                    matches!(result, Err(AresError::InvalidRecord(_))),
                    "wire export accepted {layout:?} with {rcode:?}: {result:?}"
                );
            }
            for result in [record.try_clone(), borrowed.to_owned_record()] {
                assert!(
                    matches!(result, Err(AresError::InvalidRecord(_))),
                    "copy accepted {layout:?} with {rcode:?}: {result:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn single_root_opt_with_empty_options_survives_every_export_and_copy() -> Result<()> {
    for rcode in [DnsRcode::NoError, DnsRcode::BadCookie] {
        for owner in ["", "."] {
            let record = message(rcode, &[(DnsSection::Additional, owner)])?;
            let borrowed = record.as_ref();
            for copy in [
                DnsRecord::parse_wire(&record.write_wire()?)?,
                DnsRecord::parse_wire(&borrowed.write_wire()?)?,
                record.try_clone()?,
                borrowed.to_owned_record()?,
            ] {
                assert_eq!(copy.rcode()?, rcode);
                assert_eq!(copy.rr_count(DnsSection::Additional), 1);
                let rr = copy.rr(DnsSection::Additional, 0)?;
                assert!(matches!(rr.name()?, "" | "."));
                let opt = rr.as_opt()?;
                assert_eq!(opt.udp_size, 1232);
                assert!(opt.options.is_empty());
            }
        }
    }
    Ok(())
}
