#include <stdio.h>
#include <r3s.h>

int main() {
    R3S_cfg_t       cfg;
    R3S_key_t       k;
    R3S_cnstrs_func cnstrs[1];
    R3S_status_t    status;
    char            pcap[50];
    R3S_packet_t    *packets;
    int             n_packets;

    sprintf(pcap, "/home/fcp/libr3s/pcap/v6.pcap");

    R3S_cfg_init(&cfg);
    
    R3S_cfg_load_in_opt(&cfg, R3S_IN_OPT_NON_FRAG_IPV6);
    //R3S_cfg_load_in_opt(&cfg, R3S_IN_OPT_NON_FRAG_IPV4);

    status = R3S_parse_packets(cfg, pcap, &packets, &n_packets);

    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("Status: %s\n", R3S_status_to_string(status));

    for (unsigned i = 0; i < n_packets; i++)
        printf("packet %u\n%s\n", i, R3S_packet_to_string(packets[i]));

    R3S_cfg_delete(&cfg);
}