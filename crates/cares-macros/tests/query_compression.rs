//! First-question routing rejects pointers outside previously decoded names.

use cares_macros::cares_query_table;

cares_query_table! {
    enum Routes {
        normal { name: "a.example", rr_type: A, class: IN },
        root { name: ".", rr_type: NS, class: IN },
        binary { name: "\\001a\\000.a", rr_type: A, class: IN },
    }
}

#[test]
fn first_question_rejects_compression_targets() -> Result<(), &'static str> {
    let mut normal = [0u8; 64];
    let length = Routes::Normal.encode(1, &mut normal)?;
    assert_eq!(Routes::decode(&normal[..length])?, Routes::Normal);
    let mut forward = normal[..12].to_vec();
    forward.extend_from_slice(&[0xc0, 18, 0, 1, 0, 1]);
    forward.extend_from_slice(&normal[12..length - 4]);
    let mut field = normal[..12].to_vec();
    field.extend_from_slice(&[0xc0, 14, 0, 2, 0, 1]);
    let mut payload = normal[..12].to_vec();
    payload.extend_from_slice(&[3, 1, b'a', 0, 0xc0, 13, 0, 1, 0, 1]);
    let mut boundary = normal[..12].to_vec();
    boundary.extend_from_slice(&[1, b'a', 0xc0, 12, 0, 1, 0, 1]);
    for packet in [forward, field, payload, boundary] {
        assert!(Routes::decode(&packet).is_err(), "accepted {packet:02x?}");
    }
    let root_length = Routes::Root.encode(2, &mut normal)?;
    assert_eq!(Routes::decode(&normal[..root_length])?, Routes::Root);
    let binary_length = Routes::Binary.encode(3, &mut normal)?;
    assert_eq!(Routes::decode(&normal[..binary_length])?, Routes::Binary);
    Ok(())
}
