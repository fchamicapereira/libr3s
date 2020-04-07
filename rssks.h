#ifndef __RSSKS_H__
#define __RSSKS_H__

#include "hash.h"
#include <z3.h>

typedef enum {
    
    GENEVE_OAM,
    VXLAN_GPE_OAM,

    NON_FRAG_IPV4_TCP,
    NON_FRAG_IPV4_UDP,
    NON_FRAG_IPV4_SCTP,
    NON_FRAG_IPV4,
    FRAG_IPV4,

    NON_FRAG_IPV6_TCP,
    NON_FRAG_IPV6_UDP,
    NON_FRAG_IPV6_SCTP,
    NON_FRAG_IPV6,
    FRAG_IPV6,

    L2_TYPE,

} rss_input_cfg_t;

extern Z3_ast mk_d_constraints(Z3_context ctx, Z3_ast d1, Z3_ast d2);

hash_cfg_t hash_cfg_init();
void hash_cfg_load_input_cfg(hash_cfg_t *cfg, rss_input_cfg_t input_cfg);
void hash_cfg_load_field(hash_cfg_t *cfg, packet_field_t pf);
bool hash_cfg_check_field(hash_cfg_t cfg, packet_field_t pf);

void z3_hash(rss_key_t k, headers_t h);
void check_d_constraints(headers_t h1, headers_t h2);
void find_k(rss_key_t k);

#endif