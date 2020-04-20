#include <stdio.h>
#include <r3s.h>

#include <pcap.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <arpa/inet.h>

void packetHandler(R3S_byte_t *userData, const struct pcap_pkthdr* pkthdr, const R3S_byte_t* packet) {

    const R3S_byte_t           *l3_hdr;
    const R3S_byte_t           *l4_hdr;

    const struct ether_header  *ether_hdr;
    const struct ip            *ip_hdr;
    const struct tcphdr        *tcp_hdr;
    const struct udphdr        *udp_hdr;

    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    unsigned sourcePort, destPort;
    int dataLength = 0;
    int i;

    ether_hdr = (struct ether_header *) packet;
    l3_hdr    = packet + sizeof(struct ether_header);
    l4_hdr    = l3_hdr + sizeof(struct ip);

    switch (ntohs(ether_hdr->ether_type))
    {
        case ETHERTYPE_IP:
            ip_hdr = (struct ip*) l3_hdr;

            inet_ntop(AF_INET, &(ip_hdr->ip_src), sourceIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), destIP, INET_ADDRSTRLEN);
            
            printf("src IP: %s\n", sourceIP);
            printf("dst IP: %s\n", destIP);

            switch (ip_hdr->ip_p)
            {
                case IPPROTO_TCP:
                    tcp_hdr  = (struct tcphdr*) l4_hdr;
                    sourcePort = ntohs(tcp_hdr->source);
                    destPort   = ntohs(tcp_hdr->dest);

                    printf("tcp src: %u\n", sourcePort);
                    printf("tcp dst: %u\n", destPort);

                    break;
                case IPPROTO_UDP:
                    udp_hdr    = (struct udphdr*) l4_hdr;
                    sourcePort = ntohs(udp_hdr->source);
                    destPort   = ntohs(udp_hdr->dest);

                    printf("udp src: %u\n", sourcePort);
                    printf("udp dst: %u\n", destPort);

                    break;
                case IPPROTO_ICMP:
                    printf("ICMP\n");
                    break;
                default:
                    printf("Undealt l4 protocol\n");
            }
            break;
        default:
            printf("Undealt l3 protocol\n");
    }
}

int main(int argc, char *argv[])
{
    int                 i;
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                fname[100] = "/home/fcp/libr3s/pcap/GENERAL_barryscomputer_PracticalPacketAnalysis.pcap";
    pcap_t              *handle;
    struct pcap_pkthdr  hdr;	    /* The header that pcap gives us */
    const R3S_byte_t    *packet;    /* The actual packet */
    struct ether_header *eptr;      /* net/ethernet.h */

    handle = pcap_open_offline(fname, errbuf);
    
    if (handle == NULL) {
        printf("Couldn't open %s: %s\n", fname, errbuf);
        return 2;
    }

    if (pcap_loop(handle, 0, packetHandler, NULL) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(handle));
        return 0;
    }
    
    printf("done\n");

    return(0);
}