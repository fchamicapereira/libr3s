#include "../include/r3s.h"

#include <stdlib.h>
#include <math.h>

void R3S_stats_init(R3S_cfg_t cfg, unsigned n_cores, out R3S_key_stats_t *stats)
{
    stats->cfg        = cfg;
    stats->n_cores    = n_cores;
    stats->avg_dist   = 0;
    stats->std_dev    = 0;

    stats->core_stats = (R3S_core_stats_t*) malloc(sizeof(R3S_core_stats_t) * n_cores);
    
    for (unsigned core = 0; core < n_cores; core++) 
    {
        stats->core_stats[core].n_packets  = 0;
        stats->core_stats[core].percentage = 0;
    }
}

void R3S_stats_reset(R3S_cfg_t cfg, unsigned n_cores, out R3S_key_stats_t *stats)
{
    free(stats->core_stats);
    R3S_stats_init(cfg, n_cores, stats);
}

void R3S_stats_delete(out R3S_key_stats_t *stats)
{
    free(stats->core_stats);
}

R3S_status_t R3S_stats_from_packets(R3S_key_t key, R3S_packet_t *packets, int n_packets, out R3S_key_stats_t *stats)
{
    R3S_packet_t packet;
    R3S_out_t    output;
    unsigned     deviation;

    for (unsigned ipacket = 0; ipacket < n_packets; ipacket++) {
        packet = packets[ipacket];
        R3S_hash(stats->cfg, key, packet, &output);
        stats->core_stats[output % stats->n_cores].n_packets++;
    }

    for (unsigned core = 0; core < stats->n_cores; core++)
    {
        stats->core_stats[core].percentage = 100 * (
            (float) stats->core_stats[core].n_packets / n_packets);

        stats->avg_dist += stats->core_stats[core].percentage;
    }
    stats->avg_dist /= (float) stats->n_cores;

    for (unsigned core = 0; core < stats->n_cores; core++)
    {
        deviation = stats->core_stats[core].percentage - stats->avg_dist;
        stats->std_dev += deviation * deviation;
    }

    stats->std_dev /= stats->n_cores;
    stats->std_dev = sqrt(stats->std_dev);
    
}