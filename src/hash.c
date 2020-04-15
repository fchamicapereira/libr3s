#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#include "util.h"
#include "hash.h"
#include "string.h"
#include "packet.h"

void RSSKS_rand_key(RSSKS_cfg_t cfg, RSSKS_key_t key)
{
    init_rand();

    for (unsigned byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = rand() & 0xff;
}

void RSSKS_zero_key(RSSKS_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = 0;
}

bool RSSKS_is_zero_key(RSSKS_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        if (key[byte]) return false;
    return true;
}

RSSKS_in_t RSSKS_packet_to_hash_input(RSSKS_cfg_t cfg, RSSKS_packet_t p)
{
    RSSKS_in_t   hi;
    unsigned     sz, offset;
    RSSKS_byte_t *field;
    RSSKS_pf_t   pf;

    hi     = (RSSKS_in_t) malloc(sizeof(RSSKS_byte_t) * (cfg.in_sz / 8));
    offset = 0;
    sz     = 0;

    for (int ipf = RSSKS_FIRST_PF; ipf <= RSSKS_LAST_PF; ipf++)
    {   
        pf = (RSSKS_pf_t) ipf;

        if (RSSKS_cfg_check_pf(cfg, pf) != RSSKS_STATUS_PF_ALREADY_LOADED)
            continue;
        
        if (!RSSKS_packet_has_pf(p, pf)) continue;

        field = RSSKS_field_from_packet(&p, pf);
        sz    = RSSKS_pf_sz(pf);

        for (unsigned byte = 0; byte < sz; byte++, field++)
            hi[offset + byte] = *field;
        
        offset += sz;
    }

    return hi;
}

RSSKS_packet_t RSSKS_in_to_packet(RSSKS_cfg_t cfg, RSSKS_in_t hi, RSSKS_packet_cfg_t p_cfg)
{
    RSSKS_packet_t p;
    unsigned       sz, offset;
    RSSKS_byte_t   *field;
    RSSKS_pf_t     pf;

    p.cfg  = p_cfg;
    offset = 0;
    sz     = 0;

    for (int ipf = RSSKS_FIRST_PF; ipf <= RSSKS_LAST_PF; ipf++)
    {   
        pf = (RSSKS_pf_t) ipf;

        if (RSSKS_cfg_check_pf(cfg, pf) != RSSKS_STATUS_PF_ALREADY_LOADED)
            continue;
        
        if (!RSSKS_packet_has_pf(p, pf)) continue;

        field = RSSKS_field_from_packet(&p, pf);
        sz    = RSSKS_pf_sz(pf);

        for (unsigned byte = 0; byte < sz; byte++, field++)
            (*field) = hi[offset + byte];
        
        offset += sz;
    }

    return p;
}

void lshift(RSSKS_key_t k)
{
    RSSKS_byte_t lsb, msb = 0; // there are no 1-bit data structures in C :(

    for (int i = KEY_SIZE; i >= 0; i--)
    {
        lsb = (k[i] >> 7) & 1;
        k[i] = ((k[i] << 1) | msb) & 0xff;
        msb = lsb;
    }

    k[KEY_SIZE - 1] |= msb;
}

RSSKS_status_t RSSKS_hash(RSSKS_cfg_t cfg, RSSKS_key_t k, RSSKS_packet_t p, out RSSKS_out_t *o)
{
    RSSKS_key_t k_copy;
    RSSKS_in_t  hi; 

    *o = 0;
    hi = RSSKS_packet_to_hash_input(cfg, p);
    
    memcpy(k_copy, k, sizeof(RSSKS_byte_t) * KEY_SIZE);

    for (unsigned i = 0; i < cfg.in_sz / 8; i++)
    {
        // iterate every bit
        for (int shift = 7; shift >= 0; shift--)
        {
            if ((hi[i] >> shift) & 1) *o ^= _32_LSB(k_copy);
            lshift(k_copy);
        }
    }

    free(hi);

    return RSSKS_STATUS_SUCCESS;
}

float k_dist_mean(RSSKS_cfg_t cfg, RSSKS_key_t k)
{
    RSSKS_packet_t  p;
    RSSKS_out_t     o;
    unsigned        core_dist[CORES];
    float           mean;

    for (int core = 0; core < CORES; core++) core_dist[core] = 0;

    for (unsigned counter = 0; counter < STATS; counter++) {
        RSSKS_rand_packet(cfg, &p);
        RSSKS_hash(cfg, k, p, &o);

        core_dist[HASH_TO_CORE(o)] += 1;
    }

    mean = 0;
    for (int core = 0; core < CORES; core++)
        mean += core * core_dist[core];
    mean = mean / STATS;

    return mean;
}

bool RSSKS_k_test_dist(RSSKS_cfg_t cfg, RSSKS_key_t k)
{
    float observed_mean;
    float goal_mean;
    float dm;
    
    observed_mean = k_dist_mean(cfg, k);
    
    goal_mean = 0;
    for (int core = 0; core < CORES; core++) goal_mean += core;
    goal_mean /= CORES;

    dm = observed_mean > goal_mean
        ? (observed_mean - goal_mean) * 100.0 / CORES
        : (goal_mean - observed_mean) * 100.0 / CORES;

    DEBUG_PLOG("key:            \n\
        \r%s                    \n\
        \rmean       : %.3lf    \n\
        \rdm         : %.3lf %% \n\
        \rthreshold  : %.3lf %% \n",
        RSSKS_key_to_string(k),
        observed_mean,
        dm,
        DIST_THRESHOLD);
    
    return dm <= DIST_THRESHOLD;
}
