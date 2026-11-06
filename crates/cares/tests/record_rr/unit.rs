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
