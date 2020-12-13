#include <stdio.h>
#include <stdlib.h>
#include <r3s.h>

int main() {
    R3S_cfg_t       cfg;
    R3S_key_t       k;
    R3S_status_t    status;
    R3S_stats_t stats;
    char            pcap[50];
    R3S_packet_t    *packets;
    int             n_packets;

    sprintf(pcap, "/home/fcp/libr3s/pcap/zipf.pcap");

    R3S_cfg_init(&cfg);
    R3S_cfg_set_number_of_keys(cfg, 1);
    
    R3S_cfg_load_opt(cfg, R3S_OPT_NON_FRAG_IPV4_TCP);

    status = R3S_packets_parse(cfg, pcap, &packets, &n_packets);

    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("Status: %s\n", R3S_status_to_string(status));

    for (unsigned i = 0; i < n_packets; i++)
        printf("packet %u\n%s\n", i, R3S_packet_to_string(packets[i]));
    
    R3S_key_rand(cfg, k);
    printf("Key:\n%s\n", R3S_key_to_string(k));

    for (unsigned n_cores = 2; n_cores <= 32; n_cores *= 2)
    {
        R3S_stats_init(cfg, n_cores, &stats);
        R3S_stats_from_packets(k, packets, n_packets, &stats);
        printf("%u cores stats:\n%s\n", n_cores, R3S_stats_to_string(stats));
    }

    free(packets);

    R3S_cfg_delete(cfg);
}
