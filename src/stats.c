#include "../include/r3s.h"
#include "hash.h"
#include "printer.h"

#include <sys/sysinfo.h>
#include <stdlib.h>
#include <math.h>

void R3S_stats_init(R3S_cfg_t cfg, unsigned n_cores, out R3S_stats_t *stats)
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

void R3S_stats_reset(R3S_cfg_t cfg, unsigned n_cores, out R3S_stats_t *stats)
{
    R3S_stats_delete(stats);
    R3S_stats_init(cfg, n_cores, stats);
}

void R3S_stats_delete(out R3S_stats_t *stats)
{
    if (stats->core_stats)
        free(stats->core_stats);
}

R3S_status_t R3S_stats_from_packets(R3S_key_t key, R3S_packet_t *packets, int n_packets, out R3S_stats_t *stats)
{
    R3S_packet_t packet;
    R3S_key_hash_out_t    output;
    unsigned     deviation;

    for (unsigned ipacket = 0; ipacket < n_packets; ipacket++) {
        packet = packets[ipacket];
        R3S_key_hash(stats->cfg, key, packet, &output);
        stats->core_stats[HASH_TO_CORE(output, stats->n_cores)].n_packets++;
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

    return R3S_STATUS_SUCCESS;
}

bool R3S_stats_eval(R3S_cfg_t cfg, R3S_key_t key, out R3S_stats_t *stats)
{
    R3S_key_t    rand_key;
    R3S_stats_t  rand_key_stats;
    R3S_packet_t *packets;
    R3S_status_t status;
    int          n_packets;
    unsigned     n_cores;

    n_cores = cfg->skew_analysis_params.n_cores == 0 ?
        get_nprocs() : cfg->skew_analysis_params.n_cores;
    
    R3S_stats_reset(cfg, n_cores, stats);

    if (cfg->skew_analysis_params.pcap_fname != NULL)
    {
        status = R3S_packets_parse(cfg, cfg->skew_analysis_params.pcap_fname, &packets, &n_packets);
        if (status != R3S_STATUS_SUCCESS)
        {
            DEBUG_PLOG("Key evaluation failed: %s\n", R3S_status_to_string(status));
            free(packets);
            return false;
        }
    } else
    {
        n_packets = STATS;
        status = R3S_packets_rand(cfg, n_packets, &packets);
        if (status != R3S_STATUS_SUCCESS)
        {
            DEBUG_PLOG("Key evaluation failed: %s\n", R3S_status_to_string(status));
            free(packets);
            return false;
        }
    }

    status = R3S_stats_from_packets(key, packets, n_packets, stats);
    if (status != R3S_STATUS_SUCCESS)
    {
        DEBUG_PLOG("Key evaluation failed: %s\n", R3S_status_to_string(status));
        free(packets);
        return false;
    }

    DEBUG_PLOG("Key evaluation:\n%s\n%s\n",
        R3S_key_to_string(key),
        R3S_stats_to_string(*stats));

    if (cfg->skew_analysis_params.std_dev_threshold > 0
        && stats->std_dev < cfg->skew_analysis_params.std_dev_threshold)
    {
        free(packets);
        return false;
    } else if (cfg->skew_analysis_params.std_dev_threshold < 0)
    {
        R3S_stats_init(cfg, n_cores, &rand_key_stats);
        R3S_key_rand(cfg, rand_key);
        status = R3S_stats_from_packets(rand_key, packets, n_packets, &rand_key_stats);
        
        if (status != R3S_STATUS_SUCCESS)
        {
            DEBUG_PLOG("Key evaluation failed: %s\n", R3S_status_to_string(status));
            R3S_stats_delete(&rand_key_stats);
            free(packets);
            return false;
        }

        DEBUG_PLOG("Comparing against std dev = %6.2f %%\n", rand_key_stats.std_dev);

        if (stats->std_dev > rand_key_stats.std_dev * 1.1)
        {
            free(packets);
            R3S_stats_delete(&rand_key_stats);
            return false;
        }

        R3S_stats_delete(&rand_key_stats);
    }

    free(packets);

    return true;
}
