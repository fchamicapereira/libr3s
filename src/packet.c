#include "rssks.h"
#include "packet.h"
#include "util.h"

#include <stdlib.h>
#include <assert.h>

size_t RSSKS_pf_sz_bits(RSSKS_pf_t pf)
{
    switch (pf)
    {
        case RSSKS_PF_VXLAN_UDP_OUTER:  return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_VXLAN_VNI:        return sizeof(RSSKS_vni_t)   * 8;
        case RSSKS_PF_IPV4_SRC:         return sizeof(RSSKS_ipv4_t)  * 8;
        case RSSKS_PF_IPV4_DST:         return sizeof(RSSKS_ipv4_t)  * 8;
        case RSSKS_PF_IPV6_SRC:         return sizeof(RSSKS_ipv6_t)  * 8;
        case RSSKS_PF_IPV6_DST:         return sizeof(RSSKS_ipv6_t)  * 8;
        case RSSKS_PF_TCP_SRC:          return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_TCP_DST:          return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_UDP_SRC:          return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_UDP_DST:          return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_SCTP_SRC:         return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_SCTP_DST:         return sizeof(RSSKS_port_t)  * 8;
        case RSSKS_PF_SCTP_V_TAG:       return sizeof(RSSKS_v_tag_t) * 8;
        case RSSKS_PF_ETHERTYPE:        return 6;
        default:                        assert(false);
    }
}

RSSKS_bytes_t RSSKS_field_from_packet(RSSKS_packet_t *p, RSSKS_pf_t pf)
{
    switch (pf)
    {
        case RSSKS_PF_VXLAN_UDP_OUTER:  return (RSSKS_bytes_t) p->vxlan.outer;
        case RSSKS_PF_VXLAN_VNI:        return (RSSKS_bytes_t) p->vxlan.vni;
        case RSSKS_PF_IPV4_SRC:         return (RSSKS_bytes_t) p->ipv4.src;
        case RSSKS_PF_IPV4_DST:         return (RSSKS_bytes_t) p->ipv4.dst;
        case RSSKS_PF_IPV6_SRC:         return (RSSKS_bytes_t) p->ipv6.src;
        case RSSKS_PF_IPV6_DST:         return (RSSKS_bytes_t) p->ipv6.dst;
        case RSSKS_PF_TCP_SRC:          return (RSSKS_bytes_t) p->tcp.src;
        case RSSKS_PF_TCP_DST:          return (RSSKS_bytes_t) p->tcp.dst;
        case RSSKS_PF_UDP_SRC:          return (RSSKS_bytes_t) p->udp.src;
        case RSSKS_PF_UDP_DST:          return (RSSKS_bytes_t) p->udp.dst;
        case RSSKS_PF_SCTP_SRC:         return (RSSKS_bytes_t) p->sctp.src;
        case RSSKS_PF_SCTP_DST:         return (RSSKS_bytes_t) p->sctp.dst;
        case RSSKS_PF_SCTP_V_TAG:       return (RSSKS_bytes_t) p->sctp.tag;
        case RSSKS_PF_ETHERTYPE:        return (RSSKS_bytes_t) p->ethertype;
    }
    
    printf("ERROR: field %d not found on header\n", pf);
    assert(false);
}

void RSSKS_packet_init(RSSKS_packet_t *p)
{
    p->cfg = 0;
}

bool RSSKS_packet_has_pf(RSSKS_packet_t p, RSSKS_pf_t pf)
{
    return (p.cfg >> pf) & 1;
}

RSSKS_status_t RSSKS_packet_set_pf(RSSKS_pf_t pf, RSSKS_bytes_t v, RSSKS_packet_t *p)
{
    RSSKS_bytes_t field;

    switch (pf)
    {
        case RSSKS_PF_VXLAN_UDP_OUTER:
            if (!RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_SRC)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (!RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_DST)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_VXLAN_VNI:
            if (!RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_SRC)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (!RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_DST)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_IPV6_SRC:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV4_SRC)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV4_DST)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_IPV6_DST:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV4_SRC)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV4_DST)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_IPV4_SRC:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV6_SRC)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV6_DST)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_IPV4_DST:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV6_SRC)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_IPV6_DST)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_TCP_SRC:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_UDP_OUTER)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_VNI))       return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_SRC))        return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_DST))        return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_V_TAG))      return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_TCP_DST:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_UDP_OUTER)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_VNI))       return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_SRC))        return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_DST))        return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_V_TAG))      return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_UDP_SRC:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_SRC))        return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_DST))        return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_V_TAG))      return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_UDP_DST:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_SRC))    return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_DST))    return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_SRC))   return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_DST))   return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_SCTP_V_TAG)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_SCTP_SRC:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_UDP_OUTER)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_VNI))       return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_SCTP_DST:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_UDP_OUTER)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_VNI))       return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_SCTP_V_TAG:
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_UDP_OUTER)) return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_VXLAN_VNI))       return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_TCP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_SRC))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            if (RSSKS_packet_has_pf(*p, RSSKS_PF_UDP_DST))         return RSSKS_STATUS_PF_INCOMPATIBLE;
            break;

        case RSSKS_PF_ETHERTYPE:
            break;
    }

    p->cfg |= (1 << pf);
    field = RSSKS_field_from_packet(p, pf);

    for (unsigned byte = 0; byte < RSSKS_pf_sz(pf); byte++)
        field[byte] = v[byte];

    return RSSKS_STATUS_SUCCESS;
}

RSSKS_status_t RSSKS_packet_set_ethertype(RSSKS_ethertype_t ethertype, RSSKS_packet_t *p)
{
    return RSSKS_packet_set_pf(RSSKS_PF_ETHERTYPE, ethertype, p);
}

RSSKS_status_t RSSKS_packet_set_ipv4(RSSKS_ipv4_t src, RSSKS_ipv4_t dst, RSSKS_packet_t *p)
{
    RSSKS_status_t status;

    status = RSSKS_packet_set_pf(RSSKS_PF_IPV4_SRC, src, p);
    if (status != RSSKS_STATUS_SUCCESS) return status;

    status = RSSKS_packet_set_pf(RSSKS_PF_IPV4_DST, dst, p);
    return status;
}

RSSKS_status_t RSSKS_packet_set_ipv6(RSSKS_ipv6_t src, RSSKS_ipv6_t dst, RSSKS_packet_t *p)
{
    RSSKS_status_t status;

    status = RSSKS_packet_set_pf(RSSKS_PF_IPV6_SRC, src, p);
    if (status != RSSKS_STATUS_SUCCESS) return status;

    status = RSSKS_packet_set_pf(RSSKS_PF_IPV6_DST, dst, p);
    return status;
}

RSSKS_status_t RSSKS_packet_set_tcp(RSSKS_port_t src, RSSKS_port_t dst, RSSKS_packet_t *p)
{
    RSSKS_status_t status;

    status = RSSKS_packet_set_pf(RSSKS_PF_TCP_SRC, src, p);
    if (status != RSSKS_STATUS_SUCCESS) return status;

    status = RSSKS_packet_set_pf(RSSKS_PF_TCP_DST, dst, p);
    return status;
}

RSSKS_status_t RSSKS_packet_set_udp(RSSKS_port_t src, RSSKS_port_t dst, RSSKS_packet_t *p)
{
    RSSKS_status_t status;

    status = RSSKS_packet_set_pf(RSSKS_PF_UDP_SRC, src, p);
    if (status != RSSKS_STATUS_SUCCESS) return status;

    status = RSSKS_packet_set_pf(RSSKS_PF_UDP_DST, dst, p);
    return status;
}

RSSKS_status_t RSSKS_packet_set_sctp(RSSKS_port_t src, RSSKS_port_t dst, RSSKS_v_tag_t tag, RSSKS_packet_t *p)
{
    RSSKS_status_t status;

    status = RSSKS_packet_set_pf(RSSKS_PF_SCTP_SRC, src, p);
    if (status != RSSKS_STATUS_SUCCESS) return status;

    status = RSSKS_packet_set_pf(RSSKS_PF_SCTP_DST, dst, p);
    if (status != RSSKS_STATUS_SUCCESS) return status;

    status = RSSKS_packet_set_pf(RSSKS_PF_SCTP_V_TAG, tag, p);
    return status;
}

RSSKS_status_t RSSKS_packet_set_vxlan(RSSKS_port_t outer, RSSKS_vni_t vni, out RSSKS_packet_t *p)
{
    RSSKS_status_t status;

    status = RSSKS_packet_set_pf(RSSKS_PF_VXLAN_UDP_OUTER, outer, p);
    if (status != RSSKS_STATUS_SUCCESS) return status;

    status = RSSKS_packet_set_pf(RSSKS_PF_VXLAN_VNI, vni, p);
    return status;
}

RSSKS_status_t RSSKS_rand_packet(RSSKS_cfg_t cfg, out RSSKS_packet_t *p)
{
    RSSKS_pf_t      pf;
    int             *pfarr;
    RSSKS_bytes_t   v;
    unsigned        sz, n;

    RSSKS_packet_init(p);

    pfarr = (int*) malloc(sizeof(int) * (RSSKS_LAST_PF - RSSKS_FIRST_PF + 1));
    v     = NULL;
    n     = 0;

    for (int ipf = RSSKS_FIRST_PF; ipf <= RSSKS_LAST_PF; ipf++)
        pfarr[n++] = ipf;
    
    shuffle(pfarr, n);
    init_rand();

    for (unsigned i = 0; i < n; i++)
    {   
        pf = (RSSKS_pf_t) pfarr[i];
        
        if (RSSKS_cfg_check_pf(cfg, pf) != RSSKS_STATUS_PF_ALREADY_LOADED)
            continue;

        sz = RSSKS_pf_sz(pf);
        v  = (RSSKS_bytes_t) realloc(v, sizeof(RSSKS_byte_t) * sz);

        for (unsigned byte = 0; byte < sz; byte++)
            v[byte] = (RSSKS_byte_t) rand() & 0xff;
        
        RSSKS_packet_set_pf(pf, v, p);
    }

    free(pfarr);
    free(v);

    return RSSKS_STATUS_SUCCESS;
}
