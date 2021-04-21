#include "../include/r3s.h"
#include "packet.h"
#include "util.h"
#include "config.h"

#include <stdlib.h>
#include <assert.h>

size_t R3S_pf_sz_bits(R3S_pf_t pf)
{
    switch (pf)
    {
        case R3S_PF_VXLAN_UDP_OUTER:  return sizeof(R3S_port_t)  * 8;
        case R3S_PF_VXLAN_VNI:        return sizeof(R3S_vni_t)   * 8;
        case R3S_PF_IPV4_SRC:         return sizeof(R3S_ipv4_t)  * 8;
        case R3S_PF_IPV4_DST:         return sizeof(R3S_ipv4_t)  * 8;
        case R3S_PF_IPV6_SRC:         return sizeof(R3S_ipv6_t)  * 8;
        case R3S_PF_IPV6_DST:         return sizeof(R3S_ipv6_t)  * 8;
        case R3S_PF_TCP_SRC:          return sizeof(R3S_port_t)  * 8;
        case R3S_PF_TCP_DST:          return sizeof(R3S_port_t)  * 8;
        case R3S_PF_UDP_SRC:          return sizeof(R3S_port_t)  * 8;
        case R3S_PF_UDP_DST:          return sizeof(R3S_port_t)  * 8;
        case R3S_PF_SCTP_SRC:         return sizeof(R3S_port_t)  * 8;
        case R3S_PF_SCTP_DST:         return sizeof(R3S_port_t)  * 8;
        case R3S_PF_SCTP_V_TAG:       return sizeof(R3S_v_tag_t) * 8;
        case R3S_PF_ETHERTYPE:        return 6;
        default:                        assert(false);
    }
}

R3S_bytes_t R3S_packet_get_field(R3S_packet_t *p, R3S_pf_t pf)
{
    switch (pf)
    {
        case R3S_PF_VXLAN_UDP_OUTER:  return (R3S_bytes_t) p->vxlan.outer;
        case R3S_PF_VXLAN_VNI:        return (R3S_bytes_t) p->vxlan.vni;
        case R3S_PF_IPV4_SRC:         return (R3S_bytes_t) p->ipv4.src;
        case R3S_PF_IPV4_DST:         return (R3S_bytes_t) p->ipv4.dst;
        case R3S_PF_IPV6_SRC:         return (R3S_bytes_t) p->ipv6.src;
        case R3S_PF_IPV6_DST:         return (R3S_bytes_t) p->ipv6.dst;
        case R3S_PF_TCP_SRC:          return (R3S_bytes_t) p->tcp.src;
        case R3S_PF_TCP_DST:          return (R3S_bytes_t) p->tcp.dst;
        case R3S_PF_UDP_SRC:          return (R3S_bytes_t) p->udp.src;
        case R3S_PF_UDP_DST:          return (R3S_bytes_t) p->udp.dst;
        case R3S_PF_SCTP_SRC:         return (R3S_bytes_t) p->sctp.src;
        case R3S_PF_SCTP_DST:         return (R3S_bytes_t) p->sctp.dst;
        case R3S_PF_SCTP_V_TAG:       return (R3S_bytes_t) p->sctp.tag;
        case R3S_PF_ETHERTYPE:        return (R3S_bytes_t) p->ethertype;
    }
    
    fprintf(stderr, "ERROR: field %d not found on header\n", pf);
    assert(false);
}

void R3S_packet_init(R3S_packet_t *p)
{
    p->cfg = 0;
}

bool R3S_packet_has_pf(R3S_packet_t p, R3S_pf_t pf)
{
    return (p.cfg >> pf) & 1;
}

R3S_status_t R3S_packet_set_pf(R3S_cfg_t cfg, R3S_pf_t pf, R3S_bytes_t v, R3S_packet_t *p)
{
    R3S_bytes_t field;
    R3S_in_cfg_t test_cfg;
    unsigned    n_pfs;
    bool        compatible_pf;

    test_cfg = p->cfg | (1 << pf);

    if (!R3S_cfg_are_compatible_pfs(cfg, test_cfg))
        return R3S_STATUS_PF_INCOMPATIBLE;

    p->cfg   = test_cfg;
    field = R3S_packet_get_field(p, pf);

    for (unsigned byte = 0; byte < R3S_pf_sz(pf); byte++)
        field[byte] = v[byte];

    return R3S_STATUS_SUCCESS;
}

R3S_status_t R3S_packet_set_ethertype(R3S_cfg_t cfg, R3S_ethertype_t ethertype, R3S_packet_t *p)
{
    return R3S_packet_set_pf(cfg, R3S_PF_ETHERTYPE, ethertype, p);
}

R3S_status_t R3S_packet_set_ipv4(R3S_cfg_t cfg, R3S_ipv4_t src, R3S_ipv4_t dst, R3S_packet_t *p)
{
    R3S_status_t status;

    status = R3S_packet_set_pf(cfg, R3S_PF_IPV4_SRC, src, p);
    if (status != R3S_STATUS_SUCCESS) return status;

    status = R3S_packet_set_pf(cfg, R3S_PF_IPV4_DST, dst, p);
    return status;
}

R3S_status_t R3S_packet_set_ipv6(R3S_cfg_t cfg, R3S_ipv6_t src, R3S_ipv6_t dst, R3S_packet_t *p)
{
    R3S_status_t status;

    status = R3S_packet_set_pf(cfg, R3S_PF_IPV6_SRC, src, p);
    if (status != R3S_STATUS_SUCCESS) return status;

    status = R3S_packet_set_pf(cfg, R3S_PF_IPV6_DST, dst, p);
    return status;
}

R3S_status_t R3S_packet_set_tcp(R3S_cfg_t cfg, R3S_port_t src, R3S_port_t dst, R3S_packet_t *p)
{
    R3S_status_t status;

    status = R3S_packet_set_pf(cfg, R3S_PF_TCP_SRC, src, p);
    if (status != R3S_STATUS_SUCCESS) return status;

    status = R3S_packet_set_pf(cfg, R3S_PF_TCP_DST, dst, p);
    return status;
}

R3S_status_t R3S_packet_set_udp(R3S_cfg_t cfg, R3S_port_t src, R3S_port_t dst, R3S_packet_t *p)
{
    R3S_status_t status;

    status = R3S_packet_set_pf(cfg, R3S_PF_UDP_SRC, src, p);
    if (status != R3S_STATUS_SUCCESS) return status;

    status = R3S_packet_set_pf(cfg, R3S_PF_UDP_DST, dst, p);
    return status;
}

R3S_status_t R3S_packet_set_sctp(R3S_cfg_t cfg, R3S_port_t src, R3S_port_t dst, R3S_v_tag_t tag, R3S_packet_t *p)
{
    R3S_status_t status;

    status = R3S_packet_set_pf(cfg, R3S_PF_SCTP_SRC, src, p);
    if (status != R3S_STATUS_SUCCESS) return status;

    status = R3S_packet_set_pf(cfg, R3S_PF_SCTP_DST, dst, p);
    if (status != R3S_STATUS_SUCCESS) return status;

    status = R3S_packet_set_pf(cfg, R3S_PF_SCTP_V_TAG, tag, p);
    return status;
}

R3S_status_t R3S_packet_set_vxlan(R3S_cfg_t cfg, R3S_port_t outer, R3S_vni_t vni, out R3S_packet_t *p)
{
    R3S_status_t status;

    status = R3S_packet_set_pf(cfg, R3S_PF_VXLAN_UDP_OUTER, outer, p);
    if (status != R3S_STATUS_SUCCESS) return status;

    status = R3S_packet_set_pf(cfg, R3S_PF_VXLAN_VNI, vni, p);
    return status;
}

R3S_status_t R3S_packet_rand(R3S_cfg_t cfg, out R3S_packet_t *p)
{
    R3S_pf_t    pf;
    unsigned    chosen_opt;
    R3S_bytes_t v;
    unsigned    sz;

    R3S_packet_init(p);
    init_rand();

    v          = NULL;
    chosen_opt = rand() % cfg->n_loaded_opts;

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {   
        pf = (R3S_pf_t) ipf;
        
        if (R3S_loaded_opt_check_pf(cfg->loaded_opts[chosen_opt], pf) != R3S_STATUS_PF_LOADED)
            continue;

        sz = R3S_pf_sz(pf);
        v  = (R3S_bytes_t) realloc(v, sizeof(R3S_byte_t) * sz);

        for (unsigned byte = 0; byte < sz; byte++)
            v[byte] = (R3S_byte_t) rand() & 0xff;
        
        R3S_packet_set_pf(cfg, pf, v, p);
    }

    free(v);

    return R3S_STATUS_SUCCESS;
}

R3S_status_t R3S_packets_rand(R3S_cfg_t cfg, unsigned n_packets, out R3S_packet_t **p)
{
    *p = (R3S_packet_t*) malloc(sizeof(R3S_packet_t) * n_packets);
    
    for (unsigned ipacket = 0; ipacket < n_packets; ipacket++)
        R3S_packet_rand(cfg, &((*p)[ipacket]));

    return R3S_STATUS_SUCCESS;
}

R3S_status_t R3S_packet_to_loaded_opt(R3S_cfg_t cfg, R3S_packet_t p, R3S_loaded_opt_t *loaded_opt)
{
    unsigned n_opts;
    int chosen_iopt;

    int      match;
    int      max_match;

    max_match   = 0;
    chosen_iopt = -1;
    n_opts      = cfg->n_loaded_opts;
    
    for (unsigned iopt = 0; iopt < n_opts; iopt++)
    {
        match = 0;

        for (unsigned ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
        {
            if (R3S_loaded_opt_check_pf(cfg->loaded_opts[iopt], (R3S_pf_t) ipf) == R3S_STATUS_PF_NOT_LOADED)
                continue;

            if (!R3S_packet_has_pf(p, (R3S_pf_t) ipf)) { match = 0; break; }
            
            match++;
        }

        if (match > max_match)
        {
            chosen_iopt = iopt;
            max_match = match;
        }
    }

    if (chosen_iopt == -1) return R3S_STATUS_NO_SOLUTION;
    
    *loaded_opt = cfg->loaded_opts[chosen_iopt];

    return R3S_STATUS_SUCCESS;
}
