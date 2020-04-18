#include "../include/r3s.h"
#include "printer.h"
#include "packet.h"
#include "config.h"

#include <stdio.h>
#include <string.h>

#define _4_R3S_BYTE_T_TO_UINT32_T(v) ((uint32_t) (\
    ((BYTE_FROM_BYTES((v), 0)) << 24) + ((BYTE_FROM_BYTES((v), 1)) << 16) + \
    ((BYTE_FROM_BYTES((v), 2)) <<  8) + ((BYTE_FROM_BYTES((v), 3)) <<  0) ))

#define _3_R3S_BYTE_T_TO_UINT32_T(v) ((uint32_t) (\
    ((BYTE_FROM_BYTES((v), 0)) << 16) + ((BYTE_FROM_BYTES((v), 1)) <<  8) + \
    ((BYTE_FROM_BYTES((v), 2)) <<  0) ))

#define _2_R3S_BYTE_T_TO_UINT32_T(v) ((uint16_t) (\
    ((BYTE_FROM_BYTES((v), 0)) <<  8) + ((BYTE_FROM_BYTES((v), 1)) <<  0) ))

#define APPEND(dst, f_, ...)                 {\
        char buffer[100];                     \
        sprintf(buffer, (f_), ##__VA_ARGS__); \
        strcat((dst), (buffer));              \
    }

R3S_string_t __packet_to_string(R3S_packet_t p)
{
    R3S_string_t result;

    result.packet[0] = '\0';

    if (R3S_packet_has_pf(p, R3S_PF_VXLAN_UDP_OUTER)) {
        APPEND(result.packet, "udp outer : %u\n", _2_R3S_BYTE_T_TO_UINT32_T(p.vxlan.outer));
    } 
    
    if (R3S_packet_has_pf(p, R3S_PF_VXLAN_VNI))
        APPEND(result.packet, "vni       : %u\n", _3_R3S_BYTE_T_TO_UINT32_T(p.vxlan.vni));
    
    if (R3S_packet_has_pf(p, R3S_PF_IPV4_SRC))
        APPEND(result.packet, "ipv4 src  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(p.ipv4.src,  0), BYTE_FROM_BYTES(p.ipv4.src,  1),
            BYTE_FROM_BYTES(p.ipv4.src,  2), BYTE_FROM_BYTES(p.ipv4.src,  3));
    
    if (R3S_packet_has_pf(p, R3S_PF_IPV4_DST))
        APPEND(result.packet, "ipv4 dst  : %u.%u.%u.%u\n",
            BYTE_FROM_BYTES(p.ipv4.dst,  0), BYTE_FROM_BYTES(p.ipv4.dst,  1),
            BYTE_FROM_BYTES(p.ipv4.dst,  2), BYTE_FROM_BYTES(p.ipv4.dst,  3));
    
    if (R3S_packet_has_pf(p, R3S_PF_IPV6_SRC))
        APPEND(result.packet, "ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(p.ipv6.src,  0), BYTE_FROM_BYTES(p.ipv6.src,  1),
            BYTE_FROM_BYTES(p.ipv6.src,  2), BYTE_FROM_BYTES(p.ipv6.src,  3),
            BYTE_FROM_BYTES(p.ipv6.src,  4), BYTE_FROM_BYTES(p.ipv6.src,  5),
            BYTE_FROM_BYTES(p.ipv6.src,  6), BYTE_FROM_BYTES(p.ipv6.src,  7),
            BYTE_FROM_BYTES(p.ipv6.src,  8), BYTE_FROM_BYTES(p.ipv6.src,  9),
            BYTE_FROM_BYTES(p.ipv6.src, 10), BYTE_FROM_BYTES(p.ipv6.src, 11),
            BYTE_FROM_BYTES(p.ipv6.src, 12), BYTE_FROM_BYTES(p.ipv6.src, 13),
            BYTE_FROM_BYTES(p.ipv6.src, 14), BYTE_FROM_BYTES(p.ipv6.src, 15));
    
    if (R3S_packet_has_pf(p, R3S_PF_IPV6_DST))
        APPEND(result.packet, "ipv6 src  : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            BYTE_FROM_BYTES(p.ipv6.dst,  0), BYTE_FROM_BYTES(p.ipv6.dst,  1),
            BYTE_FROM_BYTES(p.ipv6.dst,  2), BYTE_FROM_BYTES(p.ipv6.dst,  3),
            BYTE_FROM_BYTES(p.ipv6.dst,  4), BYTE_FROM_BYTES(p.ipv6.dst,  5),
            BYTE_FROM_BYTES(p.ipv6.dst,  6), BYTE_FROM_BYTES(p.ipv6.dst,  7),
            BYTE_FROM_BYTES(p.ipv6.dst,  8), BYTE_FROM_BYTES(p.ipv6.dst,  9),
            BYTE_FROM_BYTES(p.ipv6.dst, 10), BYTE_FROM_BYTES(p.ipv6.dst, 11),
            BYTE_FROM_BYTES(p.ipv6.dst, 12), BYTE_FROM_BYTES(p.ipv6.dst, 13),
            BYTE_FROM_BYTES(p.ipv6.dst, 14), BYTE_FROM_BYTES(p.ipv6.dst, 15));
    
    if (R3S_packet_has_pf(p, R3S_PF_TCP_SRC))
        APPEND(result.packet, "tcp src   : %u\n", _2_R3S_BYTE_T_TO_UINT32_T(p.tcp.src));
    
    if (R3S_packet_has_pf(p, R3S_PF_TCP_DST))
        APPEND(result.packet, "tcp dst   : %u\n", _2_R3S_BYTE_T_TO_UINT32_T(p.tcp.dst));
    
    if (R3S_packet_has_pf(p, R3S_PF_UDP_SRC))
        APPEND(result.packet, "udp src   : %u\n", _2_R3S_BYTE_T_TO_UINT32_T(p.udp.src));
    
    if (R3S_packet_has_pf(p, R3S_PF_UDP_DST))
        APPEND(result.packet, "udp dst   : %u\n", _2_R3S_BYTE_T_TO_UINT32_T(p.udp.dst));
    
    if (R3S_packet_has_pf(p, R3S_PF_SCTP_SRC))
        APPEND(result.packet, "sctp src  : %u\n", _2_R3S_BYTE_T_TO_UINT32_T(p.sctp.src));
    
    if (R3S_packet_has_pf(p, R3S_PF_SCTP_DST))
        APPEND(result.packet, "sctp dst  : %u\n", _2_R3S_BYTE_T_TO_UINT32_T(p.sctp.dst));
    
    if (R3S_packet_has_pf(p, R3S_PF_SCTP_V_TAG))
        APPEND(result.packet, "sctp v tag: %u\n", _4_R3S_BYTE_T_TO_UINT32_T(p.sctp.tag));

    return result;
}

R3S_string_t __key_to_string(R3S_key_t k)
{
    R3S_string_t result;
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

R3S_string_t __hash_output_to_string(R3S_out_t output)
{
    R3S_string_t result;
    
    result.output[0] = '\0';

    sprintf(result.output, "output    %02x %02x %02x %02x\n",
        (output >> 24) & 0xff,
        (output >> 16) & 0xff,
        (output >>  8) & 0xff,
        (output >>  0) & 0xff
    );
    
    return result;
}

R3S_string_t __status_to_string(R3S_status_t status)
{
    R3S_string_t result;
    
    result.status[0] = '\0';

    switch (status)
    {
        case R3S_STATUS_SUCCESS:
            sprintf(result.status, "success"); break;
        case R3S_STATUS_NO_SOLUTION:
            sprintf(result.status, "no solution"); break;
        case R3S_STATUS_BAD_SOLUTION:
            sprintf(result.status, "bad solution"); break;
        case R3S_STATUS_HAS_SOLUTION:
            sprintf(result.status, "has solution"); break;
        case R3S_STATUS_PF_UNKNOWN:
            sprintf(result.status, "unknown packet field"); break;
        case R3S_STATUS_PF_LOADED:
            sprintf(result.status, "packet field loaded"); break;
        case R3S_STATUS_PF_NOT_LOADED:
            sprintf(result.status, "packet field not loaded"); break;
        case R3S_STATUS_PF_INCOMPATIBLE:
            sprintf(result.status, "incompatible packet field"); break;
        case R3S_STATUS_OPT_UNKNOWN:
            sprintf(result.status, "unknown option"); break;
        case R3S_STATUS_FAILURE:
            sprintf(result.status, "failure"); break;
    }

    return result;
}

R3S_string_t __in_opt_to_string(R3S_in_opt_t opt)
{
    R3S_string_t result;
    
    result.opt[0] = '\0';

    switch (opt)
    {
        case R3S_IN_OPT_GENEVE_OAM:
            sprintf(result.opt, "Geneve OAM"); break;
        case R3S_IN_OPT_VXLAN_GPE_OAM:
            sprintf(result.opt, "VXLAN GPE OAM"); break;
        case R3S_IN_OPT_NON_FRAG_IPV4_TCP:
            sprintf(result.opt, "Non-frag TCP/IPv4"); break;
        case R3S_IN_OPT_NON_FRAG_IPV4_UDP:
            sprintf(result.opt, "Non-frag UDP/IPv4"); break;
        case R3S_IN_OPT_NON_FRAG_IPV4_SCTP:
            sprintf(result.opt, "Non-frag SCTP/IPv4"); break;
        case R3S_IN_OPT_NON_FRAG_IPV4:
            sprintf(result.opt, "Non-frag IPv4"); break;
        case R3S_IN_OPT_FRAG_IPV4:
            sprintf(result.opt, "Frag IPv4"); break;
        case R3S_IN_OPT_NON_FRAG_IPV6_TCP:
            sprintf(result.opt, "Non-frag TCP/IPv6"); break;
        case R3S_IN_OPT_NON_FRAG_IPV6_UDP:
            sprintf(result.opt, "Non-frag UDP/IPv6"); break;
        case R3S_IN_OPT_NON_FRAG_IPV6_SCTP:
            sprintf(result.opt, "Non-frag SCTP/IPv6"); break;
        case R3S_IN_OPT_NON_FRAG_IPV6:
            sprintf(result.opt, "Non-frag IPv6"); break;
        case R3S_IN_OPT_FRAG_IPV6:
            sprintf(result.opt, "Frag IPv6"); break;
        case R3S_IN_OPT_ETHERTYPE:
            sprintf(result.opt, "Ethertype"); break;
    }

    return result;
}

R3S_string_t __pf_to_string(R3S_pf_t pf)
{
    R3S_string_t result;
    
    result.pf[0] = '\0';

    switch (pf)
    {
        case R3S_PF_VXLAN_UDP_OUTER:
            sprintf(result.opt, "VXLAN UDP outer"); break;
        case R3S_PF_VXLAN_VNI:
            sprintf(result.opt, "VXLAN VNI"); break;
        case R3S_PF_IPV6_SRC:
            sprintf(result.opt, "IPv6 src"); break;
        case R3S_PF_IPV6_DST:
            sprintf(result.opt, "IPv6 dst"); break;
        case R3S_PF_IPV4_SRC:
            sprintf(result.opt, "IPv4 src"); break;
        case R3S_PF_IPV4_DST:
            sprintf(result.opt, "IPv4 dst"); break;
        case R3S_PF_TCP_SRC:
            sprintf(result.opt, "TCP src"); break;
        case R3S_PF_TCP_DST:
            sprintf(result.opt, "TCP dst"); break;
        case R3S_PF_UDP_SRC:
            sprintf(result.opt, "UDP src"); break;
        case R3S_PF_UDP_DST:
            sprintf(result.opt, "UDP dst"); break;
        case R3S_PF_SCTP_SRC:
            sprintf(result.opt, "SCTP src"); break;
        case R3S_PF_SCTP_DST:
            sprintf(result.opt, "SCTP dst"); break;
        case R3S_PF_SCTP_V_TAG:
            sprintf(result.opt, "SCTP verification"); break;
        case R3S_PF_ETHERTYPE:
            sprintf(result.opt, "Ethertype"); break;
    }

    return result;
}

R3S_string_t __cfg_to_string(R3S_cfg_t cfg)
{
    R3S_string_t result;

    result.cfg[0] = '\0';

    APPEND(result.cfg, "cores: %d\n", cfg.n_procs);
    APPEND(result.cfg, "keys : %d\n", cfg.n_keys);
    APPEND(result.cfg, "cfgs :\n");

    for (unsigned iopt = 0; iopt < cfg.n_loaded_opts; iopt++)
    {
        APPEND(result.cfg, "\totp: %s\n", __in_opt_to_string(cfg.loaded_opts[iopt].opt).opt);
        APPEND(result.cfg, "\tsz : %u bits\n", cfg.loaded_opts[iopt].sz);
        APPEND(result.cfg, "\tpfs:\n");

        for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
            if (R3S_cfg_check_pf(cfg, iopt, (R3S_pf_t) ipf) == R3S_STATUS_PF_LOADED)
                APPEND(result.cfg, "\t\t* %s\n", __pf_to_string((R3S_pf_t) ipf).pf);
    }

    return result;
}
