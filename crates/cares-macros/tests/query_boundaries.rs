//! DNS routing preserves full-width wire fields and rejects length/tag boundaries.
use cares_macros::cares_query_table;

cares_query_table! {
    enum Routes { maximal { name: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", rr_type: CAA, class: ANY } }
}

#[test]
fn maximum_wire_name_and_identifier_round_trip_without_truncation() -> Result<(), &'static str> {
    let mut packet = [0; 272];
    for id in [0, 1, 0x8000, u16::MAX] {
        let len = Routes::Maximal.encode(id, &mut packet)?;
        assert_eq!(len, 271);
        assert_eq!(&packet[..2], &id.to_be_bytes());
        assert_eq!(Routes::decode(&packet[..len])?, Routes::Maximal);
        for prefix in 0..len {
            assert!(Routes::decode(&packet[..prefix]).is_err());
        }
        let mut short = [0xa5; 270];
        assert!(Routes::Maximal.encode(id, &mut short).is_err());
        assert!(short.iter().all(|&byte| byte == 0xa5));
    }
    let mut overlong = packet[..271].to_vec();
    overlong[204] = 62;
    overlong.insert(266, b'e');
    assert!(Routes::decode(&overlong).is_err());
    for tag in 64..=255 {
        packet[12] = tag;
        assert!(Routes::decode(&packet[..271]).is_err());
    }
    Ok(())
}

#[test]
fn header_flags_counts_and_question_fields_have_exact_validation() -> Result<(), &'static str> {
    let mut packet = [0; 271];
    Routes::Maximal.encode(u16::MAX, &mut packet)?;
    for high in 0..=u8::MAX {
        for low in 0..=u8::MAX {
            packet[2] = high;
            packet[3] = low;
            assert_eq!(
                Routes::decode(&packet).is_ok(),
                high & 0x78 == 0 && low & 0x40 == 0
            );
        }
    }
    packet[2] = 1;
    packet[3] = 0;
    for count in [0u16, 1, 256, u16::MAX] {
        packet[4..6].copy_from_slice(&count.to_be_bytes());
        assert_eq!(Routes::decode(&packet).is_ok(), count != 0);
    }
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());
    for value in [0u16, 1, 256, u16::MAX] {
        packet[267..269].copy_from_slice(&value.to_be_bytes());
        assert!(Routes::decode(&packet).is_err());
    }
    packet[267..269].copy_from_slice(&257u16.to_be_bytes());
    for value in [0u16, 1, 256, u16::MAX] {
        packet[269..271].copy_from_slice(&value.to_be_bytes());
        assert!(Routes::decode(&packet).is_err());
    }
    Ok(())
}
