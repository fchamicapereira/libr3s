#ifndef __RSSKS_H__
#define __RSSKS_H__

#include <stdint.h>
#include <stdbool.h>

#include <z3.h>

#define HASH_INPUT_SIZE         13
#define HASH_OUTPUT_SIZE        4
#define KEY_SIZE                52

#define HASH_INPUT_SIZE_BITS    (HASH_INPUT_SIZE * 8)
#define HASH_OUTPUT_SIZE_BITS   (HASH_OUTPUT_SIZE * 8)
#define KEY_SIZE_BITS           (KEY_SIZE * 8)

typedef unsigned char  RSSKS_byte_t;
typedef RSSKS_byte_t*  RSSKS_bytes_t;

typedef RSSKS_bytes_t  RSSKS_in_t;
typedef RSSKS_byte_t   RSSKS_key_t[KEY_SIZE];
typedef uint32_t       RSSKS_out_t;

typedef RSSKS_byte_t   RSSKS_ipv6_t[16];
typedef RSSKS_byte_t   RSSKS_ipv4_t[4];
typedef RSSKS_byte_t   RSSKS_v_tag_t[4];  // verification tag (SCTP)
typedef RSSKS_byte_t   RSSKS_vni_t[3];    // unique identifier for the individual VXLAN segment
typedef RSSKS_byte_t   RSSKS_port_t[2];

typedef unsigned       RSSKS_in_cfg_t;

typedef enum {
    
    RSSKS_IN_OPT_GENEVE_OAM,
    RSSKS_IN_OPT_VXLAN_GPE_OAM,

    RSSKS_IN_OPT_NON_FRAG_IPV4_TCP,
    RSSKS_IN_OPT_NON_FRAG_IPV4_UDP,
    RSSKS_IN_OPT_NON_FRAG_IPV4_SCTP,
    RSSKS_IN_OPT_NON_FRAG_IPV4,
    RSSKS_IN_OPT_FRAG_IPV4,

    RSSKS_IN_OPT_NON_FRAG_IPV6_TCP,
    RSSKS_IN_OPT_NON_FRAG_IPV6_UDP,
    RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP,
    RSSKS_IN_OPT_NON_FRAG_IPV6,
    RSSKS_IN_OPT_FRAG_IPV6,

    RSSKS_IN_OPT_L2_TYPE,

} RSSKS_in_opt_t;

/*
 * The order is important!
 * From top to bottom, if one field is enumerated first, then
 * it is placed first on the hash input.
 * 
 * Eg, if one configured the hash to accept ipv4 src and dst,
 * and tcp src and dst, then the hash input would be
 * { ipv4_src, ipv4_dst, tcp_src, tcp_dst }.
 */
typedef enum {

    RSSKS_PF_IPV6_SRC,
    RSSKS_PF_IPV6_DST,

    RSSKS_PF_IPV4_SRC,
    RSSKS_PF_IPV4_DST,

    RSSKS_PF_UDP_OUTER,
    RSSKS_PF_VNI,

    RSSKS_PF_TCP_SRC,
    RSSKS_PF_TCP_DST,

    RSSKS_PF_UDP_SRC,
    RSSKS_PF_UDP_DST,

    RSSKS_PF_SCTP_SRC,
    RSSKS_PF_SCTP_DST,
    RSSKS_PF_SCTP_V_TAG,

    RSSKS_PF_L2_TYPE,

} RSSKS_pf_t;

// This is used for RSSKS_pf_t iteration
#define RSSKS_FIRST_PF RSSKS_PF_IPV6_SRC
#define RSSKS_LAST_PF  RSSKS_PF_L2_TYPE

typedef struct {
    RSSKS_port_t  udp_outer;
    RSSKS_vni_t   vni;

    RSSKS_ipv4_t  ipv4_src;
    RSSKS_ipv4_t  ipv4_dst;

    RSSKS_ipv6_t  ipv6_src;
    RSSKS_ipv6_t  ipv6_dst;

    RSSKS_port_t  tcp_src;
    RSSKS_port_t  tcp_dst;

    RSSKS_port_t  udp_src;
    RSSKS_port_t  udp_dst;

    RSSKS_port_t  sctp_src;
    RSSKS_port_t  sctp_dst;
    RSSKS_v_tag_t sctp_v_tag; // sctp verification tag

    // TODO: missing L2 ethertype
} RSSKS_headers_t;

typedef struct {
    RSSKS_in_cfg_t in_cfg;
    unsigned       in_sz; 
} RSSKS_cfg_t;

extern Z3_ast mk_d_constraints(Z3_context ctx, Z3_ast d1, Z3_ast d2);

RSSKS_cfg_t RSSKS_cfg_init();
void RSSKS_cfg_load_in_opt(RSSKS_cfg_t *cfg, RSSKS_in_opt_t in_opt);
void RSSKS_cfg_load_pf(RSSKS_cfg_t *cfg, RSSKS_pf_t pf);
bool RSSKS_cfg_check_pf(RSSKS_cfg_t cfg, RSSKS_pf_t pf);

RSSKS_out_t hash(RSSKS_cfg_t cfg, RSSKS_key_t k, RSSKS_headers_t h);

void z3_hash(RSSKS_key_t k, RSSKS_headers_t h);
void check_d_constraints(RSSKS_headers_t h1, RSSKS_headers_t h2);
void find_k(RSSKS_key_t k);

// DEBUG
void print_key(RSSKS_key_t k);
void print_headers(RSSKS_cfg_t cfg, RSSKS_headers_t headers);
void print_hash_input(RSSKS_cfg_t cfg, RSSKS_in_t hi);
void print_hash_output(RSSKS_out_t output);

#endif