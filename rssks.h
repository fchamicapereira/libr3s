#ifndef __RSSKS_H__
#define __RSSKS_H__

#include "hash.h"
#include <z3.h>

typedef unsigned char byte_t;

typedef byte_t*  hash_input_t;
typedef byte_t   rss_key_t[KEY_SIZE];
typedef uint32_t hash_output_t;

typedef byte_t ipv6_t[16];
typedef byte_t ipv4_t[4];
typedef byte_t v_tag_t[4];  // verification tag (SCTP)
typedef byte_t vni_t[3];    // unique identifier for the individual VXLAN segment
typedef byte_t port_t[2];

typedef enum {
    
    INPUT_CFG_GENEVE_OAM,
    INPUT_CFG_VXLAN_GPE_OAM,

    INPUT_CFG_NON_FRAG_IPV4_TCP,
    INPUT_CFG_NON_FRAG_IPV4_UDP,
    INPUT_CFG_NON_FRAG_IPV4_SCTP,
    INPUT_CFG_NON_FRAG_IPV4,
    INPUT_CFG_FRAG_IPV4,

    INPUT_CFG_NON_FRAG_IPV6_TCP,
    INPUT_CFG_NON_FRAG_IPV6_UDP,
    INPUT_CFG_NON_FRAG_IPV6_SCTP,
    INPUT_CFG_NON_FRAG_IPV6,
    INPUT_CFG_FRAG_IPV6,

    INPUT_CFG_L2_TYPE,

} rss_input_cfg_t;

typedef enum {

    PF_UDP_OUTER,
    PF_VNI,

    PF_IPV4_SRC,
    PF_IPV4_DST,

    PF_IPV6_SRC,
    PF_IPV6_DST,

    PF_TCP_SRC,
    PF_TCP_DST,

    PF_UDP_SRC,
    PF_UDP_DST,

    PF_SCTP_SRC,
    PF_SCTP_DST,
    PF_SCTP_V_TAG,

    PF_L2_TYPE,

} packet_field_t;

typedef struct {
    port_t  udp_outer;
    vni_t   vni;

    ipv4_t  ipv4_src;
    ipv4_t  ipv4_dst;

    ipv6_t  ipv6_src;
    ipv6_t  ipv6_dst;

    port_t  tcp_src;
    port_t  tcp_dst;

    port_t  udp_src;
    port_t  udp_dst;

    port_t  sctp_src;
    port_t  sctp_dst;
    v_tag_t sctp_v_tag; // sctp verification tag

    // TODO: missing L2 ethertype
} headers_t;

extern Z3_ast mk_d_constraints(Z3_context ctx, Z3_ast d1, Z3_ast d2);

hash_cfg_t hash_cfg_init();
void hash_cfg_load_input_cfg(hash_cfg_t *cfg, rss_input_cfg_t input_cfg);
void hash_cfg_load_field(hash_cfg_t *cfg, packet_field_t pf);
bool hash_cfg_check_field(hash_cfg_t cfg, packet_field_t pf);

void z3_hash(rss_key_t k, headers_t h);
void check_d_constraints(headers_t h1, headers_t h2);
void find_k(rss_key_t k);

#endif