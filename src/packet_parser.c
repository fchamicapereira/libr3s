#include "../include/r3s.h"

#include "printer.h"
#include "packet.h"
#include "config.h"

#include <stdlib.h>
#include <pcap.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>

#include <netinet/sctp.h>
#include <arpa/inet.h>

typedef struct {
    R3S_cfg_t    cfg;
    R3S_packet_t *packets;
    unsigned     n_packets;
} R3S_parsed_packets_t;

struct sctphdr
{
  unsigned short    source;
  unsigned short    dest;
  unsigned int      veriftag;
  unsigned int      sctp_sum;
};

void parse_packet_with_opt(
    R3S_cfg_t cfg,
    R3S_loaded_opt_t opt,
    const struct pcap_pkthdr *pkthdr,
    const R3S_byte_t *packet,
    out R3S_packet_t *pp
)
{
    R3S_status_t               status;

    const R3S_byte_t           *l3_hdr;
    const R3S_byte_t           *l4_hdr;

    const struct ether_header  *ether_hdr;
    const struct ip            *ip_hdr;
    const struct ip6_hdr       *ip6_hdr;
    const struct tcphdr        *tcp_hdr;
    const struct udphdr        *udp_hdr;
    const struct sctphdr       *sctp_hdr;

    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    unsigned sourcePort, destPort;
    unsigned v_tag;

    ether_hdr = (struct ether_header *) packet;
    l3_hdr    = packet + sizeof(struct ether_header);
    l4_hdr    = l3_hdr + sizeof(struct ip);

    ip_hdr    = NULL;

    R3S_packet_init(pp);

    switch (ntohs(ether_hdr->ether_type))
    {
        case ETHERTYPE_IP:
            status = R3S_loaded_opt_check_pf(opt, R3S_PF_IPV4_SRC);
            if (status != R3S_STATUS_PF_LOADED) break;

            status = R3S_loaded_opt_check_pf(opt, R3S_PF_IPV4_DST);
            if (status != R3S_STATUS_PF_LOADED) break;

            ip_hdr = (struct ip*) l3_hdr;

            unsigned sourceIPv, destIPv;

            in_addr_t addr_s = ip_hdr->ip_src.s_addr;
            in_addr_t addr_d = ip_hdr->ip_dst.s_addr;
            
            R3S_ipv4_t ipv4_src;
            ipv4_src[0] = (addr_s >>  0) & 0xff;
            ipv4_src[1] = (addr_s >>  8) & 0xff;
            ipv4_src[2] = (addr_s >> 16) & 0xff;
            ipv4_src[3] = (addr_s >> 24) & 0xff;

            R3S_ipv4_t ipv4_dst;
            ipv4_dst[0] = (addr_d >>  0) & 0xff;
            ipv4_dst[1] = (addr_d >>  8) & 0xff;
            ipv4_dst[2] = (addr_d >> 16) & 0xff;
            ipv4_dst[3] = (addr_d >> 24) & 0xff;

            R3S_packet_set_pf(cfg, R3S_PF_IPV4_SRC, ipv4_src, pp);
            R3S_packet_set_pf(cfg, R3S_PF_IPV4_DST, ipv4_dst, pp);

            break;

        case ETHERTYPE_IPV6:
            status = R3S_loaded_opt_check_pf(opt, R3S_PF_IPV6_SRC);
            if (status != R3S_STATUS_PF_LOADED) break;

            status = R3S_loaded_opt_check_pf(opt, R3S_PF_IPV6_DST);
            if (status != R3S_STATUS_PF_LOADED) break;

            ip6_hdr = (struct ip6_hdr*) l3_hdr;

            R3S_ipv6_t ipv6_src;
            for (unsigned i = 0; i < INET_ADDRSTRLEN; i++)
                ipv6_src[i] = (R3S_byte_t) ip6_hdr->ip6_src.s6_addr[i];

            R3S_ipv6_t ipv6_dst;
            for (unsigned i = 0; i < INET_ADDRSTRLEN; i++)
                ipv6_dst[i] = (R3S_byte_t) ip6_hdr->ip6_dst.s6_addr[i];

            R3S_packet_set_pf(cfg, R3S_PF_IPV6_SRC, ipv6_src, pp);
            R3S_packet_set_pf(cfg, R3S_PF_IPV6_DST, ipv6_dst, pp);

            break;

        default:
            fprintf(stderr, "Undealt l3 protocol\n");
            break;
    }

    if (ip_hdr == NULL) return;

    switch (ip_hdr->ip_p)
    {
        case IPPROTO_TCP:
            status = R3S_loaded_opt_check_pf(opt, R3S_PF_TCP_SRC);
            if (status != R3S_STATUS_PF_LOADED) break;

            status = R3S_loaded_opt_check_pf(opt, R3S_PF_TCP_DST);
            if (status != R3S_STATUS_PF_LOADED) break;

            tcp_hdr    = (struct tcphdr*) l4_hdr;
            sourcePort = ntohs(tcp_hdr->source);
            destPort   = ntohs(tcp_hdr->dest);

            R3S_port_t tcp_src;
            tcp_src[0] = (sourcePort >> 8) & 0xff;
            tcp_src[1] = (sourcePort >> 0) & 0xff;

            R3S_port_t tcp_dst;
            tcp_dst[0] = (destPort >> 8) & 0xff;
            tcp_dst[1] = (destPort >> 0) & 0xff;

            R3S_packet_set_pf(cfg, R3S_PF_TCP_SRC, tcp_src, pp);
            R3S_packet_set_pf(cfg, R3S_PF_TCP_DST, tcp_dst, pp);

            break;

        case IPPROTO_UDP:
            status = R3S_loaded_opt_check_pf(opt, R3S_PF_UDP_SRC);
            if (status != R3S_STATUS_PF_LOADED) break;

            status = R3S_loaded_opt_check_pf(opt, R3S_PF_UDP_DST);
            if (status != R3S_STATUS_PF_LOADED) break;

            udp_hdr    = (struct udphdr*) l4_hdr;
            sourcePort = ntohs(udp_hdr->source);
            destPort   = ntohs(udp_hdr->dest);

            R3S_port_t udp_src;
            udp_src[0] = (sourcePort >> 8) & 0xff;
            udp_src[1] = (sourcePort >> 0) & 0xff;

            R3S_port_t udp_dst;
            udp_dst[0] = (destPort >> 8) & 0xff;
            udp_dst[1] = (destPort >> 0) & 0xff;

            R3S_packet_set_pf(cfg, R3S_PF_UDP_SRC, udp_src, pp);
            R3S_packet_set_pf(cfg, R3S_PF_UDP_DST, udp_dst, pp);

            break;

        case IPPROTO_SCTP:
            status = R3S_loaded_opt_check_pf(opt, R3S_PF_SCTP_SRC);
            if (status != R3S_STATUS_PF_LOADED) break;

            status = R3S_loaded_opt_check_pf(opt, R3S_PF_SCTP_DST);
            if (status != R3S_STATUS_PF_LOADED) break;

            status = R3S_loaded_opt_check_pf(opt, R3S_PF_SCTP_V_TAG);
            if (status != R3S_STATUS_PF_LOADED) break;

            sctp_hdr   = (struct sctphdr*) l4_hdr;
            sourcePort = ntohs(sctp_hdr->source);
            destPort   = ntohs(sctp_hdr->dest);
            v_tag      = ntohl(sctp_hdr->veriftag);

            break;

        default:
            fprintf(stderr, "Undealt l4 protocol\n");
            break;
    }
}

void packetHandler(R3S_byte_t *user_data, const struct pcap_pkthdr* pkthdr, const R3S_byte_t* packet) {
    R3S_parsed_packets_t *pps;
    R3S_packet_t          pp;

    pps = (R3S_parsed_packets_t*) user_data;

    for (unsigned iopt = 0; iopt < pps->cfg->n_loaded_opts; iopt++)
    {
        parse_packet_with_opt(pps->cfg, pps->cfg->loaded_opts[iopt] , pkthdr, packet, &pp);
        
        if (pp.cfg != 0)
        {
            pps->packets = (R3S_packet_t*) realloc(
                pps->packets,
                sizeof(R3S_packet_t) * (pps->n_packets+1)
            );

            pps->packets[pps->n_packets] = pp;
            pps->n_packets++;
            return;
        }
    }
}

R3S_status_t R3S_packets_parse(R3S_cfg_t cfg, char* filename, out R3S_packet_t **packets, int *n_packets)
{
    R3S_parsed_packets_t pps;
    char                 errbuf[PCAP_ERRBUF_SIZE];
    pcap_t               *handle;

    pps.cfg       = cfg;
    pps.packets   = NULL;
    pps.n_packets = 0;

    handle = pcap_open_offline(filename, errbuf);
    
    if (handle == NULL) {
        DEBUG_PLOG("Couldn't open %s: %s\n", filename, errbuf);
        return R3S_STATUS_FAILURE;
    }

    if (pcap_loop(handle, 0, packetHandler, (R3S_byte_t*) &pps) < 0) {
        DEBUG_PLOG("pcap_loop() failed: %s\n", pcap_geterr(handle));
        return R3S_STATUS_FAILURE;
    }

    *packets   = pps.packets;
    *n_packets = pps.n_packets;

    return R3S_STATUS_SUCCESS;
}
