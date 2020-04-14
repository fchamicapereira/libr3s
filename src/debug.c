#include "rssks.h"
#include "debug.h"

#include <stdio.h>
#include <string.h>

#define _4_RSSKS_BYTE_T_TO_UINT32_T(v) ((uint32_t) (\
    ((BYTE_FROM_BYTES((v), 0)) << 24) + ((BYTE_FROM_BYTES((v), 1)) << 16) + \
    ((BYTE_FROM_BYTES((v), 2)) <<  8) + ((BYTE_FROM_BYTES((v), 3)) <<  0) ))

#define _3_RSSKS_BYTE_T_TO_UINT32_T(v) ((uint32_t) (\
    ((BYTE_FROM_BYTES((v), 0)) << 16) + ((BYTE_FROM_BYTES((v), 1)) <<  8) + \
    ((BYTE_FROM_BYTES((v), 2)) <<  0) ))

#define _2_RSSKS_BYTE_T_TO_UINT32_T(v) ((uint16_t) (\
    ((BYTE_FROM_BYTES((v), 0)) <<  8) + ((BYTE_FROM_BYTES((v), 1)) <<  0) ))

#define APPEND(dst, buffer, f_, ...)              {\
        sprintf((buffer), (f_), ##__VA_ARGS__);    \
        strcat((dst), (buffer));                   \
    }

RSSKS_string_t __headers_to_string(RSSKS_cfg_t cfg, RSSKS_headers_t h)
{
    RSSKS_string_t result;
    char buffer[100];
    result.headers[0] = '\0';

    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_OUTER) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "udp outer : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_outer));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_VNI) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "vni       : %u\n", _3_RSSKS_BYTE_T_TO_UINT32_T(h.vni));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "ipv4 src  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(h.ipv4_src,  0), BYTE_FROM_BYTES(h.ipv4_src,  1),
            BYTE_FROM_BYTES(h.ipv4_src,  2), BYTE_FROM_BYTES(h.ipv4_src,  3));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV4_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "ipv4 dst  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(h.ipv4_dst,  0), BYTE_FROM_BYTES(h.ipv4_dst,  1),
            BYTE_FROM_BYTES(h.ipv4_dst,  2), BYTE_FROM_BYTES(h.ipv4_dst,  3));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(h.ipv6_src,  0), BYTE_FROM_BYTES(h.ipv6_src,  1),
            BYTE_FROM_BYTES(h.ipv6_src,  2), BYTE_FROM_BYTES(h.ipv6_src,  3),
            BYTE_FROM_BYTES(h.ipv6_src,  4), BYTE_FROM_BYTES(h.ipv6_src,  5),
            BYTE_FROM_BYTES(h.ipv6_src,  6), BYTE_FROM_BYTES(h.ipv6_src,  7),
            BYTE_FROM_BYTES(h.ipv6_src,  8), BYTE_FROM_BYTES(h.ipv6_src,  9),
            BYTE_FROM_BYTES(h.ipv6_src, 10), BYTE_FROM_BYTES(h.ipv6_src, 11),
            BYTE_FROM_BYTES(h.ipv6_src, 12), BYTE_FROM_BYTES(h.ipv6_src, 13),
            BYTE_FROM_BYTES(h.ipv6_src, 14), BYTE_FROM_BYTES(h.ipv6_src, 15));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_IPV6_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(h.ipv6_dst,  0), BYTE_FROM_BYTES(h.ipv6_dst,  1),
            BYTE_FROM_BYTES(h.ipv6_dst,  2), BYTE_FROM_BYTES(h.ipv6_dst,  3),
            BYTE_FROM_BYTES(h.ipv6_dst,  4), BYTE_FROM_BYTES(h.ipv6_dst,  5),
            BYTE_FROM_BYTES(h.ipv6_dst,  6), BYTE_FROM_BYTES(h.ipv6_dst,  7),
            BYTE_FROM_BYTES(h.ipv6_dst,  8), BYTE_FROM_BYTES(h.ipv6_dst,  9),
            BYTE_FROM_BYTES(h.ipv6_dst, 10), BYTE_FROM_BYTES(h.ipv6_dst, 11),
            BYTE_FROM_BYTES(h.ipv6_dst, 12), BYTE_FROM_BYTES(h.ipv6_dst, 13),
            BYTE_FROM_BYTES(h.ipv6_dst, 14), BYTE_FROM_BYTES(h.ipv6_dst, 15));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "tcp src   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.tcp_src));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_TCP_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "tcp dst   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.tcp_dst));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "udp src   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_src));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_UDP_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "udp dst   : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.udp_dst));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_SRC) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "sctp src  : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_src));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_DST) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "sctp dst  : %u\n", _2_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_dst));
    
    if (RSSKS_cfg_check_pf(cfg, RSSKS_PF_SCTP_V_TAG) == RSSKS_STATUS_PF_ALREADY_LOADED)
        APPEND(result.headers, buffer, "sctp v tag: %u\n", _4_RSSKS_BYTE_T_TO_UINT32_T(h.sctp_v_tag));

    return result;
}

RSSKS_string_t __key_to_string(RSSKS_key_t k)
{
    RSSKS_string_t result;
    char            *ptr;

    ptr = result.key;
    for (int i = 0; i < KEY_SIZE; i++) {
        sprintf(ptr, "%02x ", k[i] & 0xff);
        ptr += 3;

        if ((i+1) % 8 == 0) *(ptr++) = '\n';
    }

    *(ptr++) = '\n';
    *ptr     = '\0';

    return result;
}

RSSKS_string_t __hash_output_to_string(RSSKS_out_t output)
{
    RSSKS_string_t result;
    
    result.output[0] = '\0';

    sprintf(result.output, "output    %02x %02x %02x %02x\n",
        (output >> 24) & 0xff,
        (output >> 16) & 0xff,
        (output >>  8) & 0xff,
        (output >>  0) & 0xff
    );
    
    return result;
}