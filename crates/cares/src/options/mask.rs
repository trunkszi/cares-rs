//! Native option presence, distinct from resolver behavior and DNS wire flags.
use uarch::prelude::*;
bitword! {
    pub(super) struct OptionMask(u32) {
        [0] pub FLAGS,
        [1] pub TIMEOUT,
        [2] pub TRIES,
        [3] pub NDOTS,
        [4] pub UDP_PORT,
        [5] pub TCP_PORT,
        [6] pub SERVERS,
        [7] pub DOMAINS,
        [8] pub LOOKUPS,
        [9] pub SOCK_STATE_CB,
        [10] pub SORTLIST,
        [11] pub SOCK_SNDBUF,
        [12] pub SOCK_RCVBUF,
        [13] pub TIMEOUTMS,
        [14] pub ROTATE,
        [15] pub EDNSPSZ,
        [16] pub NOROTATE,
        [17] pub RESOLVCONF,
        [18] pub HOSTS_FILE,
        [19] pub UDP_MAX_QUERIES,
        [20] pub MAXTIMEOUTMS,
        [21] pub QUERY_CACHE,
        [22] pub EVENT_THREAD,
        [23] pub SERVER_FAILOVER,
    }
}
const _: () = {
    assert!(OptionMask::FLAGS.mask() == cares_sys::ARES_OPT_FLAGS as u64);
    assert!(OptionMask::TIMEOUT.mask() == cares_sys::ARES_OPT_TIMEOUT as u64);
    assert!(OptionMask::TRIES.mask() == cares_sys::ARES_OPT_TRIES as u64);
    assert!(OptionMask::NDOTS.mask() == cares_sys::ARES_OPT_NDOTS as u64);
    assert!(OptionMask::UDP_PORT.mask() == cares_sys::ARES_OPT_UDP_PORT as u64);
    assert!(OptionMask::TCP_PORT.mask() == cares_sys::ARES_OPT_TCP_PORT as u64);
    assert!(OptionMask::SERVERS.mask() == cares_sys::ARES_OPT_SERVERS as u64);
    assert!(OptionMask::DOMAINS.mask() == cares_sys::ARES_OPT_DOMAINS as u64);
    assert!(OptionMask::LOOKUPS.mask() == cares_sys::ARES_OPT_LOOKUPS as u64);
    assert!(OptionMask::SOCK_STATE_CB.mask() == cares_sys::ARES_OPT_SOCK_STATE_CB as u64);
    assert!(OptionMask::SORTLIST.mask() == cares_sys::ARES_OPT_SORTLIST as u64);
    assert!(OptionMask::SOCK_SNDBUF.mask() == cares_sys::ARES_OPT_SOCK_SNDBUF as u64);
    assert!(OptionMask::SOCK_RCVBUF.mask() == cares_sys::ARES_OPT_SOCK_RCVBUF as u64);
    assert!(OptionMask::TIMEOUTMS.mask() == cares_sys::ARES_OPT_TIMEOUTMS as u64);
    assert!(OptionMask::ROTATE.mask() == cares_sys::ARES_OPT_ROTATE as u64);
    assert!(OptionMask::EDNSPSZ.mask() == cares_sys::ARES_OPT_EDNSPSZ as u64);
    assert!(OptionMask::NOROTATE.mask() == cares_sys::ARES_OPT_NOROTATE as u64);
    assert!(OptionMask::RESOLVCONF.mask() == cares_sys::ARES_OPT_RESOLVCONF as u64);
    assert!(OptionMask::HOSTS_FILE.mask() == cares_sys::ARES_OPT_HOSTS_FILE as u64);
    assert!(OptionMask::UDP_MAX_QUERIES.mask() == cares_sys::ARES_OPT_UDP_MAX_QUERIES as u64);
    assert!(OptionMask::MAXTIMEOUTMS.mask() == cares_sys::ARES_OPT_MAXTIMEOUTMS as u64);
    assert!(OptionMask::QUERY_CACHE.mask() == cares_sys::ARES_OPT_QUERY_CACHE as u64);
    assert!(OptionMask::EVENT_THREAD.mask() == cares_sys::ARES_OPT_EVENT_THREAD as u64);
    assert!(OptionMask::SERVER_FAILOVER.mask() == cares_sys::ARES_OPT_SERVER_FAILOVER as u64);
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn option_presence_preserves_independent_bits() {
        let word = OptionMask::new(0).patch(patch!(OptionMask {
            FLAGS: true,
            SERVERS: true,
            TIMEOUTMS: true,
            QUERY_CACHE: true
        }));
        assert!(word.matches(
            pattern!(OptionMask { FLAGS & SERVERS & TIMEOUTMS & QUERY_CACHE & !EVENT_THREAD })
        ));
        let changed = word.patch(patch!(OptionMask {
            FLAGS: false,
            EVENT_THREAD: true
        }));
        assert!(!changed.test(OptionMask::FLAGS));
        assert!(changed.test(OptionMask::SERVERS));
        assert!(changed.test(OptionMask::EVENT_THREAD));
    }
}
