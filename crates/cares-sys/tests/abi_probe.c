/* Compiled against the selected upstream headers to check the Rust ABI. */
#include <stddef.h>
#include <ares.h>

size_t cares_sys_abi_probe(size_t index) {
  static const size_t values[] = {
    sizeof(struct ares_socket_functions_ex), /* ares_socket_functions_ex.size */
    _Alignof(struct ares_socket_functions_ex), /* ares_socket_functions_ex.align */
    offsetof(struct ares_socket_functions_ex, version), /* ares_socket_functions_ex.version */
    offsetof(struct ares_socket_functions_ex, flags), /* ares_socket_functions_ex.flags */
    offsetof(struct ares_socket_functions_ex, asocket), /* ares_socket_functions_ex.asocket */
    offsetof(struct ares_socket_functions_ex, aclose), /* ares_socket_functions_ex.aclose */
    offsetof(struct ares_socket_functions_ex, asetsockopt), /* ares_socket_functions_ex.asetsockopt */
    offsetof(struct ares_socket_functions_ex, aconnect), /* ares_socket_functions_ex.aconnect */
    offsetof(struct ares_socket_functions_ex, arecvfrom), /* ares_socket_functions_ex.arecvfrom */
    offsetof(struct ares_socket_functions_ex, asendto), /* ares_socket_functions_ex.asendto */
    offsetof(struct ares_socket_functions_ex, agetsockname), /* ares_socket_functions_ex.agetsockname */
    offsetof(struct ares_socket_functions_ex, abind), /* ares_socket_functions_ex.abind */
    offsetof(struct ares_socket_functions_ex, aif_nametoindex), /* ares_socket_functions_ex.aif_nametoindex */
    offsetof(struct ares_socket_functions_ex, aif_indextoname), /* ares_socket_functions_ex.aif_indextoname */
    sizeof(struct ares_server_failover_options), /* ares_server_failover_options.size */
    _Alignof(struct ares_server_failover_options), /* ares_server_failover_options.align */
    offsetof(struct ares_server_failover_options, retry_chance), /* ares_server_failover_options.retry_chance */
    offsetof(struct ares_server_failover_options, retry_delay), /* ares_server_failover_options.retry_delay */
    sizeof(struct ares_options), /* ares_options.size */
    _Alignof(struct ares_options), /* ares_options.align */
    offsetof(struct ares_options, flags), /* ares_options.flags */
    offsetof(struct ares_options, timeout), /* ares_options.timeout */
    offsetof(struct ares_options, tries), /* ares_options.tries */
    offsetof(struct ares_options, ndots), /* ares_options.ndots */
    offsetof(struct ares_options, udp_port), /* ares_options.udp_port */
    offsetof(struct ares_options, tcp_port), /* ares_options.tcp_port */
    offsetof(struct ares_options, socket_send_buffer_size), /* ares_options.socket_send_buffer_size */
    offsetof(struct ares_options, socket_receive_buffer_size), /* ares_options.socket_receive_buffer_size */
    offsetof(struct ares_options, servers), /* ares_options.servers */
    offsetof(struct ares_options, nservers), /* ares_options.nservers */
    offsetof(struct ares_options, domains), /* ares_options.domains */
    offsetof(struct ares_options, ndomains), /* ares_options.ndomains */
    offsetof(struct ares_options, lookups), /* ares_options.lookups */
    offsetof(struct ares_options, sock_state_cb), /* ares_options.sock_state_cb */
    offsetof(struct ares_options, sock_state_cb_data), /* ares_options.sock_state_cb_data */
    offsetof(struct ares_options, sortlist), /* ares_options.sortlist */
    offsetof(struct ares_options, nsort), /* ares_options.nsort */
    offsetof(struct ares_options, ednspsz), /* ares_options.ednspsz */
    offsetof(struct ares_options, resolvconf_path), /* ares_options.resolvconf_path */
    offsetof(struct ares_options, hosts_path), /* ares_options.hosts_path */
    offsetof(struct ares_options, udp_max_queries), /* ares_options.udp_max_queries */
    offsetof(struct ares_options, maxtimeout), /* ares_options.maxtimeout */
    offsetof(struct ares_options, qcache_max_ttl), /* ares_options.qcache_max_ttl */
    offsetof(struct ares_options, evsys), /* ares_options.evsys */
    offsetof(struct ares_options, server_failover_opts), /* ares_options.server_failover_opts */
    sizeof(struct ares_in6_addr), /* ares_in6_addr.size */
    _Alignof(struct ares_in6_addr), /* ares_in6_addr.align */
    offsetof(struct ares_in6_addr, _S6_un), /* ares_in6_addr._S6_un */
    sizeof(struct ares_addr), /* ares_addr.size */
    _Alignof(struct ares_addr), /* ares_addr.align */
    offsetof(struct ares_addr, family), /* ares_addr.family */
    offsetof(struct ares_addr, addr), /* ares_addr.addr */
    sizeof(ares_fd_events_t), /* ares_fd_events_t.size */
    _Alignof(ares_fd_events_t), /* ares_fd_events_t.align */
    offsetof(ares_fd_events_t, fd), /* ares_fd_events_t.fd */
    offsetof(ares_fd_events_t, events), /* ares_fd_events_t.events */
    sizeof(ares_status_t), /* ares_status_t.size */
    _Alignof(ares_status_t), /* ares_status_t.align */
    ARES_SUCCESS, /* ARES_SUCCESS */
    ARES_ENODATA, /* ARES_ENODATA */
    ARES_EFORMERR, /* ARES_EFORMERR */
    ARES_ESERVFAIL, /* ARES_ESERVFAIL */
    ARES_ENOTFOUND, /* ARES_ENOTFOUND */
    ARES_ENOTIMP, /* ARES_ENOTIMP */
    ARES_EREFUSED, /* ARES_EREFUSED */
    ARES_EBADQUERY, /* ARES_EBADQUERY */
    ARES_EBADNAME, /* ARES_EBADNAME */
    ARES_EBADFAMILY, /* ARES_EBADFAMILY */
    ARES_EBADRESP, /* ARES_EBADRESP */
    ARES_ECONNREFUSED, /* ARES_ECONNREFUSED */
    ARES_ETIMEOUT, /* ARES_ETIMEOUT */
    ARES_EOF, /* ARES_EOF */
    ARES_EFILE, /* ARES_EFILE */
    ARES_ENOMEM, /* ARES_ENOMEM */
    ARES_EDESTRUCTION, /* ARES_EDESTRUCTION */
    ARES_EBADSTR, /* ARES_EBADSTR */
    ARES_EBADFLAGS, /* ARES_EBADFLAGS */
    ARES_ENONAME, /* ARES_ENONAME */
    ARES_EBADHINTS, /* ARES_EBADHINTS */
    ARES_ENOTINITIALIZED, /* ARES_ENOTINITIALIZED */
    ARES_ELOADIPHLPAPI, /* ARES_ELOADIPHLPAPI */
    ARES_EADDRGETNETWORKPARAMS, /* ARES_EADDRGETNETWORKPARAMS */
    ARES_ECANCELLED, /* ARES_ECANCELLED */
    ARES_ESERVICE, /* ARES_ESERVICE */
    ARES_ENOSERVER, /* ARES_ENOSERVER */
    sizeof(ares_bool_t), /* ares_bool_t.size */
    _Alignof(ares_bool_t), /* ares_bool_t.align */
    ARES_FALSE, /* ARES_FALSE */
    ARES_TRUE, /* ARES_TRUE */
    sizeof(ares_evsys_t), /* ares_evsys_t.size */
    _Alignof(ares_evsys_t), /* ares_evsys_t.align */
    ARES_EVSYS_DEFAULT, /* ARES_EVSYS_DEFAULT */
    ARES_EVSYS_WIN32, /* ARES_EVSYS_WIN32 */
    ARES_EVSYS_EPOLL, /* ARES_EVSYS_EPOLL */
    ARES_EVSYS_KQUEUE, /* ARES_EVSYS_KQUEUE */
    ARES_EVSYS_POLL, /* ARES_EVSYS_POLL */
    ARES_EVSYS_SELECT, /* ARES_EVSYS_SELECT */
    sizeof(ares_sockfunc_flags_t), /* ares_sockfunc_flags_t.size */
    _Alignof(ares_sockfunc_flags_t), /* ares_sockfunc_flags_t.align */
    ARES_SOCKFUNC_FLAG_NONBLOCKING, /* ARES_SOCKFUNC_FLAG_NONBLOCKING */
    sizeof(ares_socket_opt_t), /* ares_socket_opt_t.size */
    _Alignof(ares_socket_opt_t), /* ares_socket_opt_t.align */
    ARES_SOCKET_OPT_SENDBUF_SIZE, /* ARES_SOCKET_OPT_SENDBUF_SIZE */
    ARES_SOCKET_OPT_RECVBUF_SIZE, /* ARES_SOCKET_OPT_RECVBUF_SIZE */
    ARES_SOCKET_OPT_BIND_DEVICE, /* ARES_SOCKET_OPT_BIND_DEVICE */
    ARES_SOCKET_OPT_TCP_FASTOPEN, /* ARES_SOCKET_OPT_TCP_FASTOPEN */
    sizeof(ares_socket_connect_flags_t), /* ares_socket_connect_flags_t.size */
    _Alignof(ares_socket_connect_flags_t), /* ares_socket_connect_flags_t.align */
    ARES_SOCKET_CONN_TCP_FASTOPEN, /* ARES_SOCKET_CONN_TCP_FASTOPEN */
    sizeof(ares_socket_bind_flags_t), /* ares_socket_bind_flags_t.size */
    _Alignof(ares_socket_bind_flags_t), /* ares_socket_bind_flags_t.align */
    ARES_SOCKET_BIND_TCP, /* ARES_SOCKET_BIND_TCP */
    ARES_SOCKET_BIND_CLIENT, /* ARES_SOCKET_BIND_CLIENT */
    sizeof(ares_fd_eventflag_t), /* ares_fd_eventflag_t.size */
    _Alignof(ares_fd_eventflag_t), /* ares_fd_eventflag_t.align */
    ARES_FD_EVENT_NONE, /* ARES_FD_EVENT_NONE */
    ARES_FD_EVENT_READ, /* ARES_FD_EVENT_READ */
    ARES_FD_EVENT_WRITE, /* ARES_FD_EVENT_WRITE */
    sizeof(ares_process_flag_t), /* ares_process_flag_t.size */
    _Alignof(ares_process_flag_t), /* ares_process_flag_t.align */
    ARES_PROCESS_FLAG_NONE, /* ARES_PROCESS_FLAG_NONE */
    ARES_PROCESS_FLAG_SKIP_NON_FD, /* ARES_PROCESS_FLAG_SKIP_NON_FD */
    sizeof(ares_dns_rec_type_t), /* ares_dns_rec_type_t.size */
    _Alignof(ares_dns_rec_type_t), /* ares_dns_rec_type_t.align */
    ARES_REC_TYPE_A, /* ARES_REC_TYPE_A */
    ARES_REC_TYPE_NS, /* ARES_REC_TYPE_NS */
    ARES_REC_TYPE_CNAME, /* ARES_REC_TYPE_CNAME */
    ARES_REC_TYPE_SOA, /* ARES_REC_TYPE_SOA */
    ARES_REC_TYPE_PTR, /* ARES_REC_TYPE_PTR */
    ARES_REC_TYPE_HINFO, /* ARES_REC_TYPE_HINFO */
    ARES_REC_TYPE_MX, /* ARES_REC_TYPE_MX */
    ARES_REC_TYPE_TXT, /* ARES_REC_TYPE_TXT */
    ARES_REC_TYPE_SIG, /* ARES_REC_TYPE_SIG */
    ARES_REC_TYPE_AAAA, /* ARES_REC_TYPE_AAAA */
    ARES_REC_TYPE_SRV, /* ARES_REC_TYPE_SRV */
    ARES_REC_TYPE_NAPTR, /* ARES_REC_TYPE_NAPTR */
    ARES_REC_TYPE_OPT, /* ARES_REC_TYPE_OPT */
    ARES_REC_TYPE_TLSA, /* ARES_REC_TYPE_TLSA */
    ARES_REC_TYPE_SVCB, /* ARES_REC_TYPE_SVCB */
    ARES_REC_TYPE_HTTPS, /* ARES_REC_TYPE_HTTPS */
    ARES_REC_TYPE_ANY, /* ARES_REC_TYPE_ANY */
    ARES_REC_TYPE_URI, /* ARES_REC_TYPE_URI */
    ARES_REC_TYPE_CAA, /* ARES_REC_TYPE_CAA */
    ARES_REC_TYPE_RAW_RR, /* ARES_REC_TYPE_RAW_RR */
    sizeof(ares_dns_class_t), /* ares_dns_class_t.size */
    _Alignof(ares_dns_class_t), /* ares_dns_class_t.align */
    ARES_CLASS_IN, /* ARES_CLASS_IN */
    ARES_CLASS_CHAOS, /* ARES_CLASS_CHAOS */
    ARES_CLASS_HESIOD, /* ARES_CLASS_HESIOD */
    ARES_CLASS_HESOID, /* ARES_CLASS_HESOID */
    ARES_CLASS_NONE, /* ARES_CLASS_NONE */
    ARES_CLASS_ANY, /* ARES_CLASS_ANY */
    sizeof(ares_dns_section_t), /* ares_dns_section_t.size */
    _Alignof(ares_dns_section_t), /* ares_dns_section_t.align */
    ARES_SECTION_ANSWER, /* ARES_SECTION_ANSWER */
    ARES_SECTION_AUTHORITY, /* ARES_SECTION_AUTHORITY */
    ARES_SECTION_ADDITIONAL, /* ARES_SECTION_ADDITIONAL */
    sizeof(ares_dns_opcode_t), /* ares_dns_opcode_t.size */
    _Alignof(ares_dns_opcode_t), /* ares_dns_opcode_t.align */
    ARES_OPCODE_QUERY, /* ARES_OPCODE_QUERY */
    ARES_OPCODE_IQUERY, /* ARES_OPCODE_IQUERY */
    ARES_OPCODE_STATUS, /* ARES_OPCODE_STATUS */
    ARES_OPCODE_NOTIFY, /* ARES_OPCODE_NOTIFY */
    ARES_OPCODE_UPDATE, /* ARES_OPCODE_UPDATE */
    sizeof(ares_dns_flags_t), /* ares_dns_flags_t.size */
    _Alignof(ares_dns_flags_t), /* ares_dns_flags_t.align */
    ARES_FLAG_QR, /* ARES_FLAG_QR */
    ARES_FLAG_AA, /* ARES_FLAG_AA */
    ARES_FLAG_TC, /* ARES_FLAG_TC */
    ARES_FLAG_RD, /* ARES_FLAG_RD */
    ARES_FLAG_RA, /* ARES_FLAG_RA */
    ARES_FLAG_AD, /* ARES_FLAG_AD */
    ARES_FLAG_CD, /* ARES_FLAG_CD */
    sizeof(ares_dns_rcode_t), /* ares_dns_rcode_t.size */
    _Alignof(ares_dns_rcode_t), /* ares_dns_rcode_t.align */
    ARES_RCODE_NOERROR, /* ARES_RCODE_NOERROR */
    ARES_RCODE_FORMERR, /* ARES_RCODE_FORMERR */
    ARES_RCODE_SERVFAIL, /* ARES_RCODE_SERVFAIL */
    ARES_RCODE_NXDOMAIN, /* ARES_RCODE_NXDOMAIN */
    ARES_RCODE_NOTIMP, /* ARES_RCODE_NOTIMP */
    ARES_RCODE_REFUSED, /* ARES_RCODE_REFUSED */
    ARES_RCODE_YXDOMAIN, /* ARES_RCODE_YXDOMAIN */
    ARES_RCODE_YXRRSET, /* ARES_RCODE_YXRRSET */
    ARES_RCODE_NXRRSET, /* ARES_RCODE_NXRRSET */
    ARES_RCODE_NOTAUTH, /* ARES_RCODE_NOTAUTH */
    ARES_RCODE_NOTZONE, /* ARES_RCODE_NOTZONE */
    ARES_RCODE_DSOTYPEI, /* ARES_RCODE_DSOTYPEI */
    ARES_RCODE_BADSIG, /* ARES_RCODE_BADSIG */
    ARES_RCODE_BADKEY, /* ARES_RCODE_BADKEY */
    ARES_RCODE_BADTIME, /* ARES_RCODE_BADTIME */
    ARES_RCODE_BADMODE, /* ARES_RCODE_BADMODE */
    ARES_RCODE_BADNAME, /* ARES_RCODE_BADNAME */
    ARES_RCODE_BADALG, /* ARES_RCODE_BADALG */
    ARES_RCODE_BADTRUNC, /* ARES_RCODE_BADTRUNC */
    ARES_RCODE_BADCOOKIE, /* ARES_RCODE_BADCOOKIE */
    sizeof(ares_dns_datatype_t), /* ares_dns_datatype_t.size */
    _Alignof(ares_dns_datatype_t), /* ares_dns_datatype_t.align */
    ARES_DATATYPE_INADDR, /* ARES_DATATYPE_INADDR */
    ARES_DATATYPE_INADDR6, /* ARES_DATATYPE_INADDR6 */
    ARES_DATATYPE_U8, /* ARES_DATATYPE_U8 */
    ARES_DATATYPE_U16, /* ARES_DATATYPE_U16 */
    ARES_DATATYPE_U32, /* ARES_DATATYPE_U32 */
    ARES_DATATYPE_NAME, /* ARES_DATATYPE_NAME */
    ARES_DATATYPE_STR, /* ARES_DATATYPE_STR */
    ARES_DATATYPE_BIN, /* ARES_DATATYPE_BIN */
    ARES_DATATYPE_BINP, /* ARES_DATATYPE_BINP */
    ARES_DATATYPE_OPT, /* ARES_DATATYPE_OPT */
    ARES_DATATYPE_ABINP, /* ARES_DATATYPE_ABINP */
    sizeof(ares_dns_rr_key_t), /* ares_dns_rr_key_t.size */
    _Alignof(ares_dns_rr_key_t), /* ares_dns_rr_key_t.align */
    ARES_RR_A_ADDR, /* ARES_RR_A_ADDR */
    ARES_RR_NS_NSDNAME, /* ARES_RR_NS_NSDNAME */
    ARES_RR_CNAME_CNAME, /* ARES_RR_CNAME_CNAME */
    ARES_RR_SOA_MNAME, /* ARES_RR_SOA_MNAME */
    ARES_RR_SOA_RNAME, /* ARES_RR_SOA_RNAME */
    ARES_RR_SOA_SERIAL, /* ARES_RR_SOA_SERIAL */
    ARES_RR_SOA_REFRESH, /* ARES_RR_SOA_REFRESH */
    ARES_RR_SOA_RETRY, /* ARES_RR_SOA_RETRY */
    ARES_RR_SOA_EXPIRE, /* ARES_RR_SOA_EXPIRE */
    ARES_RR_SOA_MINIMUM, /* ARES_RR_SOA_MINIMUM */
    ARES_RR_PTR_DNAME, /* ARES_RR_PTR_DNAME */
    ARES_RR_HINFO_CPU, /* ARES_RR_HINFO_CPU */
    ARES_RR_HINFO_OS, /* ARES_RR_HINFO_OS */
    ARES_RR_MX_PREFERENCE, /* ARES_RR_MX_PREFERENCE */
    ARES_RR_MX_EXCHANGE, /* ARES_RR_MX_EXCHANGE */
    ARES_RR_TXT_DATA, /* ARES_RR_TXT_DATA */
    ARES_RR_SIG_TYPE_COVERED, /* ARES_RR_SIG_TYPE_COVERED */
    ARES_RR_SIG_ALGORITHM, /* ARES_RR_SIG_ALGORITHM */
    ARES_RR_SIG_LABELS, /* ARES_RR_SIG_LABELS */
    ARES_RR_SIG_ORIGINAL_TTL, /* ARES_RR_SIG_ORIGINAL_TTL */
    ARES_RR_SIG_EXPIRATION, /* ARES_RR_SIG_EXPIRATION */
    ARES_RR_SIG_INCEPTION, /* ARES_RR_SIG_INCEPTION */
    ARES_RR_SIG_KEY_TAG, /* ARES_RR_SIG_KEY_TAG */
    ARES_RR_SIG_SIGNERS_NAME, /* ARES_RR_SIG_SIGNERS_NAME */
    ARES_RR_SIG_SIGNATURE, /* ARES_RR_SIG_SIGNATURE */
    ARES_RR_AAAA_ADDR, /* ARES_RR_AAAA_ADDR */
    ARES_RR_SRV_PRIORITY, /* ARES_RR_SRV_PRIORITY */
    ARES_RR_SRV_WEIGHT, /* ARES_RR_SRV_WEIGHT */
    ARES_RR_SRV_PORT, /* ARES_RR_SRV_PORT */
    ARES_RR_SRV_TARGET, /* ARES_RR_SRV_TARGET */
    ARES_RR_NAPTR_ORDER, /* ARES_RR_NAPTR_ORDER */
    ARES_RR_NAPTR_PREFERENCE, /* ARES_RR_NAPTR_PREFERENCE */
    ARES_RR_NAPTR_FLAGS, /* ARES_RR_NAPTR_FLAGS */
    ARES_RR_NAPTR_SERVICES, /* ARES_RR_NAPTR_SERVICES */
    ARES_RR_NAPTR_REGEXP, /* ARES_RR_NAPTR_REGEXP */
    ARES_RR_NAPTR_REPLACEMENT, /* ARES_RR_NAPTR_REPLACEMENT */
    ARES_RR_OPT_UDP_SIZE, /* ARES_RR_OPT_UDP_SIZE */
    ARES_RR_OPT_VERSION, /* ARES_RR_OPT_VERSION */
    ARES_RR_OPT_FLAGS, /* ARES_RR_OPT_FLAGS */
    ARES_RR_OPT_OPTIONS, /* ARES_RR_OPT_OPTIONS */
    ARES_RR_TLSA_CERT_USAGE, /* ARES_RR_TLSA_CERT_USAGE */
    ARES_RR_TLSA_SELECTOR, /* ARES_RR_TLSA_SELECTOR */
    ARES_RR_TLSA_MATCH, /* ARES_RR_TLSA_MATCH */
    ARES_RR_TLSA_DATA, /* ARES_RR_TLSA_DATA */
    ARES_RR_SVCB_PRIORITY, /* ARES_RR_SVCB_PRIORITY */
    ARES_RR_SVCB_TARGET, /* ARES_RR_SVCB_TARGET */
    ARES_RR_SVCB_PARAMS, /* ARES_RR_SVCB_PARAMS */
    ARES_RR_HTTPS_PRIORITY, /* ARES_RR_HTTPS_PRIORITY */
    ARES_RR_HTTPS_TARGET, /* ARES_RR_HTTPS_TARGET */
    ARES_RR_HTTPS_PARAMS, /* ARES_RR_HTTPS_PARAMS */
    ARES_RR_URI_PRIORITY, /* ARES_RR_URI_PRIORITY */
    ARES_RR_URI_WEIGHT, /* ARES_RR_URI_WEIGHT */
    ARES_RR_URI_TARGET, /* ARES_RR_URI_TARGET */
    ARES_RR_CAA_CRITICAL, /* ARES_RR_CAA_CRITICAL */
    ARES_RR_CAA_TAG, /* ARES_RR_CAA_TAG */
    ARES_RR_CAA_VALUE, /* ARES_RR_CAA_VALUE */
    ARES_RR_RAW_RR_TYPE, /* ARES_RR_RAW_RR_TYPE */
    ARES_RR_RAW_RR_DATA, /* ARES_RR_RAW_RR_DATA */
    sizeof(ares_tlsa_usage_t), /* ares_tlsa_usage_t.size */
    _Alignof(ares_tlsa_usage_t), /* ares_tlsa_usage_t.align */
    ARES_TLSA_USAGE_CA, /* ARES_TLSA_USAGE_CA */
    ARES_TLSA_USAGE_SERVICE, /* ARES_TLSA_USAGE_SERVICE */
    ARES_TLSA_USAGE_TRUSTANCHOR, /* ARES_TLSA_USAGE_TRUSTANCHOR */
    ARES_TLSA_USAGE_DOMAIN, /* ARES_TLSA_USAGE_DOMAIN */
    sizeof(ares_tlsa_selector_t), /* ares_tlsa_selector_t.size */
    _Alignof(ares_tlsa_selector_t), /* ares_tlsa_selector_t.align */
    ARES_TLSA_SELECTOR_FULL, /* ARES_TLSA_SELECTOR_FULL */
    ARES_TLSA_SELECTOR_SUBJPUBKEYINFO, /* ARES_TLSA_SELECTOR_SUBJPUBKEYINFO */
    sizeof(ares_tlsa_match_t), /* ares_tlsa_match_t.size */
    _Alignof(ares_tlsa_match_t), /* ares_tlsa_match_t.align */
    ARES_TLSA_MATCH_EXACT, /* ARES_TLSA_MATCH_EXACT */
    ARES_TLSA_MATCH_SHA256, /* ARES_TLSA_MATCH_SHA256 */
    ARES_TLSA_MATCH_SHA512, /* ARES_TLSA_MATCH_SHA512 */
    sizeof(ares_svcb_param_t), /* ares_svcb_param_t.size */
    _Alignof(ares_svcb_param_t), /* ares_svcb_param_t.align */
    ARES_SVCB_PARAM_MANDATORY, /* ARES_SVCB_PARAM_MANDATORY */
    ARES_SVCB_PARAM_ALPN, /* ARES_SVCB_PARAM_ALPN */
    ARES_SVCB_PARAM_NO_DEFAULT_ALPN, /* ARES_SVCB_PARAM_NO_DEFAULT_ALPN */
    ARES_SVCB_PARAM_PORT, /* ARES_SVCB_PARAM_PORT */
    ARES_SVCB_PARAM_IPV4HINT, /* ARES_SVCB_PARAM_IPV4HINT */
    ARES_SVCB_PARAM_ECH, /* ARES_SVCB_PARAM_ECH */
    ARES_SVCB_PARAM_IPV6HINT, /* ARES_SVCB_PARAM_IPV6HINT */
    sizeof(ares_opt_param_t), /* ares_opt_param_t.size */
    _Alignof(ares_opt_param_t), /* ares_opt_param_t.align */
    ARES_OPT_PARAM_LLQ, /* ARES_OPT_PARAM_LLQ */
    ARES_OPT_PARAM_UL, /* ARES_OPT_PARAM_UL */
    ARES_OPT_PARAM_NSID, /* ARES_OPT_PARAM_NSID */
    ARES_OPT_PARAM_DAU, /* ARES_OPT_PARAM_DAU */
    ARES_OPT_PARAM_DHU, /* ARES_OPT_PARAM_DHU */
    ARES_OPT_PARAM_N3U, /* ARES_OPT_PARAM_N3U */
    ARES_OPT_PARAM_EDNS_CLIENT_SUBNET, /* ARES_OPT_PARAM_EDNS_CLIENT_SUBNET */
    ARES_OPT_PARAM_EDNS_EXPIRE, /* ARES_OPT_PARAM_EDNS_EXPIRE */
    ARES_OPT_PARAM_COOKIE, /* ARES_OPT_PARAM_COOKIE */
    ARES_OPT_PARAM_EDNS_TCP_KEEPALIVE, /* ARES_OPT_PARAM_EDNS_TCP_KEEPALIVE */
    ARES_OPT_PARAM_PADDING, /* ARES_OPT_PARAM_PADDING */
    ARES_OPT_PARAM_CHAIN, /* ARES_OPT_PARAM_CHAIN */
    ARES_OPT_PARAM_EDNS_KEY_TAG, /* ARES_OPT_PARAM_EDNS_KEY_TAG */
    ARES_OPT_PARAM_EXTENDED_DNS_ERROR, /* ARES_OPT_PARAM_EXTENDED_DNS_ERROR */
    sizeof(ares_dns_opt_datatype_t), /* ares_dns_opt_datatype_t.size */
    _Alignof(ares_dns_opt_datatype_t), /* ares_dns_opt_datatype_t.align */
    ARES_OPT_DATATYPE_NONE, /* ARES_OPT_DATATYPE_NONE */
    ARES_OPT_DATATYPE_STR_LIST, /* ARES_OPT_DATATYPE_STR_LIST */
    ARES_OPT_DATATYPE_U8_LIST, /* ARES_OPT_DATATYPE_U8_LIST */
    ARES_OPT_DATATYPE_U16, /* ARES_OPT_DATATYPE_U16 */
    ARES_OPT_DATATYPE_U16_LIST, /* ARES_OPT_DATATYPE_U16_LIST */
    ARES_OPT_DATATYPE_U32, /* ARES_OPT_DATATYPE_U32 */
    ARES_OPT_DATATYPE_U32_LIST, /* ARES_OPT_DATATYPE_U32_LIST */
    ARES_OPT_DATATYPE_INADDR4_LIST, /* ARES_OPT_DATATYPE_INADDR4_LIST */
    ARES_OPT_DATATYPE_INADDR6_LIST, /* ARES_OPT_DATATYPE_INADDR6_LIST */
    ARES_OPT_DATATYPE_BIN, /* ARES_OPT_DATATYPE_BIN */
    ARES_OPT_DATATYPE_NAME, /* ARES_OPT_DATATYPE_NAME */
    sizeof(ares_dns_parse_flags_t), /* ares_dns_parse_flags_t.size */
    _Alignof(ares_dns_parse_flags_t), /* ares_dns_parse_flags_t.align */
    ARES_DNS_PARSE_AN_BASE_RAW, /* ARES_DNS_PARSE_AN_BASE_RAW */
    ARES_DNS_PARSE_NS_BASE_RAW, /* ARES_DNS_PARSE_NS_BASE_RAW */
    ARES_DNS_PARSE_AR_BASE_RAW, /* ARES_DNS_PARSE_AR_BASE_RAW */
    ARES_DNS_PARSE_AN_EXT_RAW, /* ARES_DNS_PARSE_AN_EXT_RAW */
    ARES_DNS_PARSE_NS_EXT_RAW, /* ARES_DNS_PARSE_NS_EXT_RAW */
    ARES_DNS_PARSE_AR_EXT_RAW, /* ARES_DNS_PARSE_AR_EXT_RAW */
  };
  if (index == (size_t)-1) return sizeof(values) / sizeof(values[0]);
  return index < sizeof(values) / sizeof(values[0]) ? values[index] : (size_t)-1;
}
