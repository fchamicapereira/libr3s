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

void R3S_key_rand(R3S_cfg_t cfg, R3S_key_t key)
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

R3S_key_hash_in_t R3S_packet_to_hash_input(R3S_cfg_t cfg, unsigned iopt, R3S_packet_t p)
{
    R3S_key_hash_in_t   hi;
    unsigned     sz, offset;
    R3S_byte_t *field;
    R3S_pf_t   pf;

    hi     = (R3S_key_hash_in_t) malloc(sizeof(R3S_byte_t) * (cfg.loaded_opts[iopt].sz / 8));
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

R3S_packet_t R3S_key_hash_in_to_packet(R3S_cfg_t cfg, unsigned iopt, R3S_key_hash_in_t hi, R3S_in_cfg_t p_cfg)
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

R3S_status_t R3S_key_hash(R3S_cfg_t cfg, R3S_key_t k, R3S_packet_t p, out R3S_key_hash_out_t *o)
{
    R3S_key_t    k_copy;
    R3S_key_hash_in_t     hi;
    R3S_status_t status;
    unsigned     ipot;

    status = R3S_packet_to_opt(cfg, p, &ipot);

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

