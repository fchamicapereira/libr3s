#include "rssks.h"
#include "debug.h"

#include <stdio.h>

void RSSKS_print_headers(RSSKS_cfg_t cfg, RSSKS_headers_t h)
{
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_OUTER) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("udp outer : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_outer));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_VNI) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("vni       : %u\n", _3_RSSKS_BYTE_T_TO_UINT32_T(h.vni));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("ipv4 src  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(h.ipv4_src,  0), BYTE_FROM_BYTES(h.ipv4_src,  1),
            BYTE_FROM_BYTES(h.ipv4_src,  2), BYTE_FROM_BYTES(h.ipv4_src,  3));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("ipv4 dst  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(h.ipv4_dst,  0), BYTE_FROM_BYTES(h.ipv4_dst,  1),
            BYTE_FROM_BYTES(h.ipv4_dst,  2), BYTE_FROM_BYTES(h.ipv4_dst,  3));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(h.ipv6_src,  0), BYTE_FROM_BYTES(h.ipv6_src,  1),
            BYTE_FROM_BYTES(h.ipv6_src,  2), BYTE_FROM_BYTES(h.ipv6_src,  3),
            BYTE_FROM_BYTES(h.ipv6_src,  4), BYTE_FROM_BYTES(h.ipv6_src,  5),
            BYTE_FROM_BYTES(h.ipv6_src,  6), BYTE_FROM_BYTES(h.ipv6_src,  7),
            BYTE_FROM_BYTES(h.ipv6_src,  8), BYTE_FROM_BYTES(h.ipv6_src,  9),
            BYTE_FROM_BYTES(h.ipv6_src, 10), BYTE_FROM_BYTES(h.ipv6_src, 11),
            BYTE_FROM_BYTES(h.ipv6_src, 12), BYTE_FROM_BYTES(h.ipv6_src, 13),
            BYTE_FROM_BYTES(h.ipv6_src, 14), BYTE_FROM_BYTES(h.ipv6_src, 15));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(h.ipv6_dst,  0), BYTE_FROM_BYTES(h.ipv6_dst,  1),
            BYTE_FROM_BYTES(h.ipv6_dst,  2), BYTE_FROM_BYTES(h.ipv6_dst,  3),
            BYTE_FROM_BYTES(h.ipv6_dst,  4), BYTE_FROM_BYTES(h.ipv6_dst,  5),
            BYTE_FROM_BYTES(h.ipv6_dst,  6), BYTE_FROM_BYTES(h.ipv6_dst,  7),
            BYTE_FROM_BYTES(h.ipv6_dst,  8), BYTE_FROM_BYTES(h.ipv6_dst,  9),
            BYTE_FROM_BYTES(h.ipv6_dst, 10), BYTE_FROM_BYTES(h.ipv6_dst, 11),
            BYTE_FROM_BYTES(h.ipv6_dst, 12), BYTE_FROM_BYTES(h.ipv6_dst, 13),
            BYTE_FROM_BYTES(h.ipv6_dst, 14), BYTE_FROM_BYTES(h.ipv6_dst, 15));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("tcp src   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.tcp_src));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("tcp dst   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.tcp_dst));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("udp src   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_src));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("udp dst   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_dst));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("sctp src  : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_src));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("sctp dst  : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_dst));
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_V_TAG) == RSSKS_STATUS_PF_ALREADY_LOADED)
        printf("sctp v tag: %u\n", _4_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_v_tag));
}

void RSSKS_print_hash_input(RSSKS_cfg_t cfg, RSSKS_in_t hi)
{
    printf("input     ");
    for (unsigned i = 0; i < cfg.in_sz / 8; i++)
        printf("%02x ", hi[i] & 0xff);
    puts("");
}

void RSSKS_print_key(RSSKS_key_t k)
{
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x ", k[i] & 0xff);
        if ((i+1) % 8 == 0) puts("");
    }
    puts("");
}

void RSSKS_print_hash_output(RSSKS_out_t output)
{
    printf("output    %02x %02x %02x %02x\n",
        (output >> 24) & 0xff,
        (output >> 16) & 0xff,
        (output >>  8) & 0xff,
        (output >>  0) & 0xff
    );
    printf("core      %d\n\n", HASH_TO_CORE(output));
}