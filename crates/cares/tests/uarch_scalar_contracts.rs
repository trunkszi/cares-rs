//! Scalar layout proofs preserve the public DNS and C ABI value domains.
use cares::{
    socket_bridge::SocketInterest,
    types::{DnsClass, DnsRecordType, DnsSection},
};
use cares_sys::{ares_dns_class_t, ares_fd_events_t, ares_status_t};
fn scalar<T: Copy + uarch::layout::NoPadding + uarch::layout::RegisterLeaf>() {}
#[test]
fn dns_and_c_scalar_descriptors_have_checked_register_layouts() {
    scalar::<DnsClass>();
    scalar::<cares::types::DnsFlags>();
    scalar::<cares::types::ServerStateFlags>();
    scalar::<DnsRecordType>();
    scalar::<DnsSection>();
    scalar::<ares_status_t>();
    scalar::<ares_dns_class_t>();
    fn no_padding<T: uarch::layout::NoPadding>() {}
    no_padding::<ares_fd_events_t>();
    assert_eq!(std::mem::size_of::<SocketInterest>(), 2);
    assert_eq!(DnsClass::new(u16::MAX).as_raw(), u16::MAX as u32);
    assert_eq!(u32::from(ares_status_t(u32::MAX)), u32::MAX);
}
