#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#include "util.h"
#include "hash.h"

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

unsigned packet_field_offset_le_bits(RSSKS_cfg_t cfg, RSSKS_pf_t pf)
{
    unsigned offset = cfg.in_sz;

    // TODO: check the order
    // TODO: missing RSSKS_PF_L2_TYPE

    switch(pf)
    {
        case RSSKS_PF_UDP_OUTER:
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_OUTER)  ? pf_sz_bits(RSSKS_PF_UDP_OUTER) : 0;
        case RSSKS_PF_VNI:        
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_VNI)        ? pf_sz_bits(RSSKS_PF_VNI) : 0;
        case RSSKS_PF_TCP_DST:    
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_DST)    ? pf_sz_bits(RSSKS_PF_TCP_DST) : 0;
        case RSSKS_PF_TCP_SRC:    
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_SRC)    ? pf_sz_bits(RSSKS_PF_TCP_SRC) : 0;
        case RSSKS_PF_UDP_DST:    
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_DST)    ? pf_sz_bits(RSSKS_PF_UDP_DST) : 0;
        case RSSKS_PF_UDP_SRC:    
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_SRC)    ? pf_sz_bits(RSSKS_PF_UDP_SRC) : 0;
        case RSSKS_PF_SCTP_DST:   
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_DST)   ? pf_sz_bits(RSSKS_PF_SCTP_DST) : 0;
        case RSSKS_PF_SCTP_SRC:   
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_SRC)   ? pf_sz_bits(RSSKS_PF_SCTP_SRC) : 0;
        case RSSKS_PF_IPV4_DST:   
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_DST)   ? pf_sz_bits(RSSKS_PF_IPV4_DST) : 0;
        case RSSKS_PF_IPV4_SRC:
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_SRC)   ? pf_sz_bits(RSSKS_PF_IPV4_SRC) : 0;
        case RSSKS_PF_IPV6_DST:
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_DST)   ? pf_sz_bits(RSSKS_PF_IPV6_DST) : 0;
        case RSSKS_PF_IPV6_SRC:
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_SRC)   ? pf_sz_bits(RSSKS_PF_IPV6_SRC) : 0;
        case RSSKS_PF_SCTP_V_TAG:
            offset -= RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_V_TAG) ? pf_sz_bits(RSSKS_PF_SCTP_V_TAG) : 0;
    
        // TODO: fix this
            break;
        case RSSKS_PF_L2_TYPE:
            puts("[field_from_headers] l2 not implemented");
            exit(1);
    }

    assert(offset < cfg.in_sz);
    return offset;
}

void print_headers(RSSKS_cfg_t cfg, RSSKS_headers_t h)
{
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_OUTER))
        printf("udp outer : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_outer));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_VNI))
        printf("vni       : %u\n", _3_RSSKS_BYTE_T_TO_UINT32_T(h.vni));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_SRC))
        printf("ipv4 src  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(h.ipv4_src,  0), BYTE_FROM_BYTES(h.ipv4_src,  1),
            BYTE_FROM_BYTES(h.ipv4_src,  2), BYTE_FROM_BYTES(h.ipv4_src,  3));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_DST))
        printf("ipv4 dst  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(h.ipv4_dst,  0), BYTE_FROM_BYTES(h.ipv4_dst,  1),
            BYTE_FROM_BYTES(h.ipv4_dst,  2), BYTE_FROM_BYTES(h.ipv4_dst,  3));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_SRC))
        printf("ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(h.ipv6_src,  0), BYTE_FROM_BYTES(h.ipv6_src,  1),
            BYTE_FROM_BYTES(h.ipv6_src,  2), BYTE_FROM_BYTES(h.ipv6_src,  3),
            BYTE_FROM_BYTES(h.ipv6_src,  4), BYTE_FROM_BYTES(h.ipv6_src,  5),
            BYTE_FROM_BYTES(h.ipv6_src,  6), BYTE_FROM_BYTES(h.ipv6_src,  7),
            BYTE_FROM_BYTES(h.ipv6_src,  8), BYTE_FROM_BYTES(h.ipv6_src,  9),
            BYTE_FROM_BYTES(h.ipv6_src, 10), BYTE_FROM_BYTES(h.ipv6_src, 11),
            BYTE_FROM_BYTES(h.ipv6_src, 12), BYTE_FROM_BYTES(h.ipv6_src, 13),
            BYTE_FROM_BYTES(h.ipv6_src, 14), BYTE_FROM_BYTES(h.ipv6_src, 15));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_DST))
        printf("ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(h.ipv6_dst,  0), BYTE_FROM_BYTES(h.ipv6_dst,  1),
            BYTE_FROM_BYTES(h.ipv6_dst,  2), BYTE_FROM_BYTES(h.ipv6_dst,  3),
            BYTE_FROM_BYTES(h.ipv6_dst,  4), BYTE_FROM_BYTES(h.ipv6_dst,  5),
            BYTE_FROM_BYTES(h.ipv6_dst,  6), BYTE_FROM_BYTES(h.ipv6_dst,  7),
            BYTE_FROM_BYTES(h.ipv6_dst,  8), BYTE_FROM_BYTES(h.ipv6_dst,  9),
            BYTE_FROM_BYTES(h.ipv6_dst, 10), BYTE_FROM_BYTES(h.ipv6_dst, 11),
            BYTE_FROM_BYTES(h.ipv6_dst, 12), BYTE_FROM_BYTES(h.ipv6_dst, 13),
            BYTE_FROM_BYTES(h.ipv6_dst, 14), BYTE_FROM_BYTES(h.ipv6_dst, 15));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_SRC))
        printf("tcp src   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.tcp_src));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_DST))
        printf("tcp dst   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.tcp_dst));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_SRC))
        printf("udp src   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_src));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_DST))
        printf("udp dst   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_dst));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_SRC))
        printf("sctp src  : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_src));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_DST))
        printf("sctp dst  : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_dst));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_V_TAG))
        printf("sctp v tag: %u\n", _4_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_v_tag));
}

void print_hash_input(RSSKS_cfg_t cfg, RSSKS_in_t hi)
{
    printf("input     ");
    for (unsigned i = 0; i < cfg.in_sz / 8; i++)
        printf("%02x ", hi[i] & 0xff);
    puts("");
}

void print_key(RSSKS_key_t k)
{
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x ", k[i] & 0xff);
        if ((i+1) % 8 == 0) puts("");
    }
    puts("");
}

void print_hash_output(RSSKS_out_t output)
{
    printf("output    %02x %02x %02x %02x\n",
        (output >> 24) & 0xff,
        (output >> 16) & 0xff,
        (output >>  8) & 0xff,
        (output >>  0) & 0xff
    );
    printf("core      %d\n\n", HASH_TO_CORE(output));
}

void rand_header(RSSKS_headers_t *h, RSSKS_pf_t pf)
{
    RSSKS_byte_t *field = field_from_headers(h, pf);
    
    for (unsigned byte = 0; byte < pf_sz_bits(pf) / 8; byte++)
        field[byte] = (RSSKS_byte_t) rand();
}

RSSKS_headers_t rand_headers()
{
    RSSKS_headers_t h;
    
    init_rand();

    rand_header(&h, RSSKS_PF_UDP_OUTER);
    rand_header(&h, RSSKS_PF_VNI);
    rand_header(&h, RSSKS_PF_IPV4_SRC);
    rand_header(&h, RSSKS_PF_IPV4_DST);
    rand_header(&h, RSSKS_PF_IPV6_SRC);
    rand_header(&h, RSSKS_PF_IPV6_DST);
    rand_header(&h, RSSKS_PF_TCP_SRC);
    rand_header(&h, RSSKS_PF_TCP_DST);
    rand_header(&h, RSSKS_PF_UDP_SRC);
    rand_header(&h, RSSKS_PF_UDP_DST);
    rand_header(&h, RSSKS_PF_SCTP_SRC);
    rand_header(&h, RSSKS_PF_SCTP_DST);
    rand_header(&h, RSSKS_PF_SCTP_V_TAG);

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

RSSKS_out_t hash(RSSKS_cfg_t cfg, RSSKS_key_t k, RSSKS_headers_t h)
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
        h = rand_headers();
        o = hash(cfg, k, h);

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
        print_key(k);
    #endif
    DEBUG_LOG("observed mean %lf\n", observed_mean);
    DEBUG_LOG("dm %lf\n", dm);
    
    return dm <= DIST_THRESHOLD;
}

RSSKS_cfg_t RSSKS_cfg_init()
{
    RSSKS_cfg_t cfg = {
        .in_cfg = 0,
        .in_sz  = 0
    };

    return cfg;
}

void RSSKS_cfg_load_in_opt(RSSKS_cfg_t *cfg, RSSKS_in_opt_t in_opt)
{
    switch (in_opt)
    {
        case RSSKS_IN_OPT_GENEVE_OAM:
        case RSSKS_IN_OPT_VXLAN_GPE_OAM:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_OUTER);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_VNI);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_UDP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_TCP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_SCTP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4:
        case RSSKS_IN_OPT_FRAG_IPV4:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_UDP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_TCP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6:
        case RSSKS_IN_OPT_FRAG_IPV6:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            break;
        case RSSKS_IN_OPT_L2_TYPE:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_L2_TYPE);
        default:
            DEBUG_LOG("Input option unknown: %d\n", in_opt);
            assert(false);
    }
}

void RSSKS_cfg_load_pf(RSSKS_cfg_t *cfg, RSSKS_pf_t pf)
{
    if (RSSKS_cfg_check_pf(*cfg, pf)) return;

    // TODO: check incompatible packet fields (eg TCP + UDP)

    cfg->in_cfg = cfg->in_cfg | (1 << pf);
    cfg->in_sz  += pf_sz_bits(pf);
}

bool RSSKS_cfg_check_pf(RSSKS_cfg_t cfg, RSSKS_pf_t pf)
{
    return (cfg.in_cfg >> pf) & 1;
}
