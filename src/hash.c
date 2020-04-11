#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#include "util.h"
#include "hash.h"
#include "debug.h"

size_t pf_sz_bits(RSSKS_pf_t pf)
{
    switch (pf)
    {
        case RSSKS_PF_UDP_OUTER:  return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_VNI:        return sizeof(RSSKS_vni_t)   * 8;
        case RSSKS_PF_IPV4_SRC:   return sizeof(RSSKS_ipv4_t)  * 8;
        case RSSKS_PF_IPV4_DST:   return sizeof(RSSKS_ipv4_t)  * 8;
        case RSSKS_PF_IPV6_SRC:   return sizeof(RSSKS_ipv6_t)  * 8;
        case RSSKS_PF_IPV6_DST:   return sizeof(RSSKS_ipv6_t)  * 8;
        case RSSKS_PF_TCP_SRC:    return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_TCP_DST:    return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_UDP_SRC:    return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_UDP_DST:    return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_SCTP_SRC:   return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_SCTP_DST:   return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_SCTP_V_TAG: return sizeof(RSSKS_v_tag_t) * 8;
        // TODO: missing RSSKS_PF_L2_TYPE
        default:            assert(false);
    }
}

RSSKS_bytes_t field_from_headers(RSSKS_headers_t *h, RSSKS_pf_t pf)
{
    switch (pf)
    {
        case RSSKS_PF_UDP_OUTER:  return (RSSKS_bytes_t) h->udp_outer;
        case RSSKS_PF_VNI:        return (RSSKS_bytes_t) h->vni;
        case RSSKS_PF_IPV4_SRC:   return (RSSKS_bytes_t) h->ipv4_src;
        case RSSKS_PF_IPV4_DST:   return (RSSKS_bytes_t) h->ipv4_dst;
        case RSSKS_PF_IPV6_SRC:   return (RSSKS_bytes_t) h->ipv6_src;
        case RSSKS_PF_IPV6_DST:   return (RSSKS_bytes_t) h->ipv6_dst;
        case RSSKS_PF_TCP_SRC:    return (RSSKS_bytes_t) h->tcp_src;
        case RSSKS_PF_TCP_DST:    return (RSSKS_bytes_t) h->tcp_dst;
        case RSSKS_PF_UDP_SRC:    return (RSSKS_bytes_t) h->udp_src;
        case RSSKS_PF_UDP_DST:    return (RSSKS_bytes_t) h->udp_dst;
        case RSSKS_PF_SCTP_SRC:   return (RSSKS_bytes_t) h->sctp_src;
        case RSSKS_PF_SCTP_DST:   return (RSSKS_bytes_t) h->sctp_dst;
        case RSSKS_PF_SCTP_V_TAG: return (RSSKS_bytes_t) h->sctp_v_tag;
        case RSSKS_PF_L2_TYPE:
            // TODO: fix this
            puts("[field_from_headers] l2 not implemented");
            exit(1);
    }
    
    printf("ERROR: field %d not found on header\n", pf);
    assert(false);
}

RSSKS_headers_t rand_headers(RSSKS_cfg_t cfg)
{
    RSSKS_headers_t h;
    RSSKS_pf_t      pf;
    RSSKS_byte_t    *field;
    unsigned        sz;
    
    init_rand();

    for (int ipf = RSSKS_FIRST_PF; ipf <= RSSKS_LAST_PF; ipf++)
    {   
        pf = (RSSKS_pf_t) ipf;

        if (!RSSKS_cfg_check_pf(cfg, pf)) continue;

        field = field_from_headers(&h, pf);
        sz    = pf_sz_bits(pf) / 8;

        for (unsigned byte = 0; byte < sz; byte++)
            field[byte] = (RSSKS_byte_t) rand();
    }

    return h;
}

void rand_key(RSSKS_key_t key)
{
    init_rand();

    for (int byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = rand() & 0xff;
}

void zero_key(RSSKS_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = 0;
}

bool is_zero_key(RSSKS_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        if (key[byte]) return false;
    return true;
}

RSSKS_in_t header_to_hash_input(RSSKS_cfg_t cfg, RSSKS_headers_t h)
{
    RSSKS_in_t   hi;
    unsigned     sz, offset;
    RSSKS_byte_t *field;
    RSSKS_pf_t   pf;

    hi     = (RSSKS_in_t) malloc(sizeof(RSSKS_byte_t) * (cfg.in_sz / 8));
    offset = 0;
    sz     = 0;

    for (int ipf = RSSKS_FIRST_PF; ipf <= RSSKS_LAST_PF; ipf++)
    {   
        pf = (RSSKS_pf_t) ipf;

        if (!RSSKS_cfg_check_pf(cfg, pf)) continue;

        field = field_from_headers(&h, pf);
        sz    = pf_sz_bits(pf) / 8;

        for (unsigned byte = 0; byte < sz; byte++, field++)
            hi[offset + byte] = *field;
        
        offset += sz;
    }

    return hi;
}

RSSKS_headers_t RSSKS_in_to_header(RSSKS_cfg_t cfg, RSSKS_in_t hi)
{
    RSSKS_headers_t h;
    unsigned        sz, offset;
    RSSKS_byte_t    *field;
    RSSKS_pf_t      pf;

    offset = 0;
    sz     = 0;

    for (int ipf = RSSKS_FIRST_PF; ipf <= RSSKS_LAST_PF; ipf++)
    {   
        pf = (RSSKS_pf_t) ipf;

        if (!RSSKS_cfg_check_pf(cfg, pf)) continue;

        field = field_from_headers(&h, pf);
        sz    = pf_sz_bits(pf) / 8;

        for (unsigned byte = 0; byte < sz; byte++, field++)
            (*field) = hi[offset + byte];
        
        offset += sz;
    }

    return h;
}

void lshift(RSSKS_key_t k)
{
    RSSKS_byte_t lsb, msb = 0; // there are no 1-bit data structures in C :(

    for (int i = KEY_SIZE; i >= 0; i--)
    {
        lsb = (k[i] >> 7) & 1;
        k[i] = ((k[i] << 1) | msb) & 0xff;
        msb = lsb;
    }

    k[KEY_SIZE - 1] |= msb;
}

RSSKS_out_t RSSKS_hash(RSSKS_cfg_t cfg, RSSKS_key_t k, RSSKS_headers_t h)
{
    RSSKS_out_t output;
    RSSKS_key_t k_copy;
    RSSKS_in_t  hi; 

    output = 0;
    hi     = header_to_hash_input(cfg, h);
    
    memcpy(k_copy, k, sizeof(RSSKS_byte_t) * KEY_SIZE);

    for (unsigned i = 0; i < cfg.in_sz / 8; i++)
    {
        // iterate every bit
        for (int shift = 7; shift >= 0; shift--)
        {
            if ((hi[i] >> shift) & 1) output ^= _32_LSB(k_copy);
            lshift(k_copy);
        }
    }

    free(hi);

    return output;
}

float k_dist_mean(RSSKS_cfg_t cfg, RSSKS_key_t k)
{
    RSSKS_headers_t h;
    RSSKS_out_t     o;
    unsigned        core_dist[CORES];
    float           mean;

    for (int core = 0; core < CORES; core++) core_dist[core] = 0;

    for (unsigned counter = 0; counter < STATS; counter++) {
        h = rand_headers(cfg);
        o = RSSKS_hash(cfg, k, h);

        core_dist[HASH_TO_CORE(o)] += 1;
    }

    mean = 0;
    for (int core = 0; core < CORES; core++)
        mean += core * core_dist[core];
    mean = mean / STATS;

    return mean;
}

bool k_test_dist(RSSKS_cfg_t cfg, RSSKS_key_t k)
{
    float observed_mean;
    float goal_mean;
    float dm;
    
    observed_mean = k_dist_mean(cfg, k);
    
    goal_mean = 0;
    for (int core = 0; core < CORES; core++) goal_mean += core;
    goal_mean /= CORES;

    dm = observed_mean > goal_mean
        ? (observed_mean - goal_mean) * 100.0 / CORES
        : (goal_mean - observed_mean) * 100.0 / CORES;

    #if DEBUG
        RSSKS_print_key(k);
    #endif
    DEBUG_LOG("observed mean %lf\n", observed_mean);
    DEBUG_LOG("dm %lf\n", dm);
    
    return dm <= DIST_THRESHOLD;
}
