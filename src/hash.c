#include "util.h"
#include "hash.h"
#include "printer.h"
#include "packet.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>
#include <string.h>

void R3S_rand_key(R3S_cfg_t cfg, R3S_key_t key)
{
    init_rand();

    for (unsigned byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = rand() & 0xff;
}

void R3S_zero_key(R3S_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = 0;
}

bool R3S_is_zero_key(R3S_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        if (key[byte]) return false;
    return true;
}

R3S_in_t R3S_packet_to_hash_input(R3S_cfg_t cfg, unsigned iopt, R3S_packet_t p)
{
    R3S_in_t   hi;
    unsigned     sz, offset;
    R3S_byte_t *field;
    R3S_pf_t   pf;

    hi     = (R3S_in_t) malloc(sizeof(R3S_byte_t) * (cfg.loaded_opts[iopt].sz / 8));
    offset = 0;
    sz     = 0;

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {   
        pf = (R3S_pf_t) ipf;

        if (R3S_cfg_check_pf(cfg, iopt, pf) != R3S_STATUS_PF_LOADED)
            continue;
        
        if (!R3S_packet_has_pf(p, pf)) continue;

        field = R3S_packet_get_field(&p, pf);
        sz    = R3S_pf_sz(pf);

        for (unsigned byte = 0; byte < sz; byte++, field++)
            hi[offset + byte] = *field;
        
        offset += sz;
    }

    return hi;
}

R3S_packet_t R3S_in_to_packet(R3S_cfg_t cfg, unsigned iopt, R3S_in_t hi, R3S_in_cfg_t p_cfg)
{
    R3S_packet_t p;
    unsigned       sz, offset;
    R3S_byte_t   *field;
    R3S_pf_t     pf;

    p.cfg  = p_cfg;
    offset = 0;
    sz     = 0;

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {   
        pf = (R3S_pf_t) ipf;

        if (R3S_cfg_check_pf(cfg, iopt, pf) != R3S_STATUS_PF_LOADED)
            continue;
        
        if (!R3S_packet_has_pf(p, pf)) continue;

        field = R3S_packet_get_field(&p, pf);
        sz    = R3S_pf_sz(pf);

        for (unsigned byte = 0; byte < sz; byte++, field++)
            (*field) = hi[offset + byte];
        
        offset += sz;
    }

    return p;
}

void lshift(R3S_key_t k)
{
    R3S_byte_t lsb, msb = 0; // there are no 1-bit data structures in C :(

    for (int i = KEY_SIZE; i >= 0; i--)
    {
        lsb = (k[i] >> 7) & 1;
        k[i] = ((k[i] << 1) | msb) & 0xff;
        msb = lsb;
    }

    k[KEY_SIZE - 1] |= msb;
}

R3S_status_t R3S_hash(R3S_cfg_t cfg, R3S_key_t k, R3S_packet_t p, out R3S_out_t *o)
{
    R3S_key_t    k_copy;
    R3S_in_t     hi;
    R3S_status_t status;
    unsigned     ipot;

    status = R3S_packet_to_in_opt(cfg, p, &ipot);

    if (status != R3S_STATUS_SUCCESS) return status;

    *o = 0;
    hi = R3S_packet_to_hash_input(cfg, ipot, p);
    
    memcpy(k_copy, k, sizeof(R3S_byte_t) * KEY_SIZE);

    for (unsigned i = 0; i < cfg.loaded_opts[ipot].sz / 8; i++)
    {
        // iterate every bit
        for (int shift = 7; shift >= 0; shift--)
        {
            if ((hi[i] >> shift) & 1) *o ^= _32_LSB(k_copy);
            lshift(k_copy);
        }
    }

    free(hi);

    return R3S_STATUS_SUCCESS;
}

float k_dist_mean(R3S_cfg_t cfg, R3S_key_t k)
{
    R3S_packet_t  p;
    R3S_out_t     o;
    unsigned        core_dist[CORES];
    float           mean;

    for (int core = 0; core < CORES; core++) core_dist[core] = 0;

    for (unsigned counter = 0; counter < STATS; counter++) {
        R3S_rand_packet(cfg, &p);
        R3S_hash(cfg, k, p, &o);
        core_dist[HASH_TO_CORE(o)] += 1;
    }

    mean = 0;
    for (int core = 0; core < CORES; core++)
        mean += core * core_dist[core];
    mean = mean / (float) STATS;

    return mean;
}

bool R3S_k_test_dist(R3S_cfg_t cfg, R3S_key_t k)
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
        R3S_key_to_string(k),
        observed_mean,
        dm,
        DIST_THRESHOLD);
    
    return dm <= DIST_THRESHOLD;
}
