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

R3S_key_hash_in_t R3S_packet_to_hash_input(R3S_loaded_opt_t opt, R3S_packet_t p)
{
    R3S_key_hash_in_t hi;
    unsigned          sz, offset;
    R3S_byte_t        *field;
    R3S_pf_t          pf;

    hi     = (R3S_key_hash_in_t) malloc(sizeof(R3S_byte_t) * (opt.sz / 8));
    offset = 0;
    sz     = 0;

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {   
        pf = (R3S_pf_t) ipf;

        if (R3S_loaded_opt_check_pf(opt, pf) != R3S_STATUS_PF_LOADED)
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

R3S_packet_t R3S_key_hash_in_to_packet(R3S_cfg_t cfg, R3S_loaded_opt_t opt, R3S_key_hash_in_t hi)
{
    R3S_packet_t p;
    unsigned     sz, offset;
    R3S_pf_t     pf;

    R3S_packet_init(&p);

    offset = 0;

    // This requires the order of R3S_pf_t to be the order that each packet field
    // appears on a packet.
    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {   
        pf = (R3S_pf_t) ipf;

        if (R3S_loaded_opt_check_pf(opt, pf) != R3S_STATUS_PF_LOADED)
            continue;

        R3S_status_t status = R3S_packet_set_pf(cfg, pf, (R3S_bytes_t) &(hi[offset]), &p);
        assert(status == R3S_STATUS_SUCCESS);

        offset += R3S_pf_sz(pf);
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
    R3S_key_t         k_copy;
    R3S_key_hash_in_t hi;
    R3S_status_t      status;
    R3S_loaded_opt_t  loaded_opt;
    R3S_packet_ast_t  packet_ast;

    status = R3S_packet_to_loaded_opt(cfg, p, &loaded_opt);

    if (status != R3S_STATUS_SUCCESS) return status;

    *o = 0;
    hi = R3S_packet_to_hash_input(loaded_opt, p);
    
    memcpy(k_copy, k, sizeof(R3S_byte_t) * KEY_SIZE);

    for (unsigned i = 0; i < loaded_opt.sz / 8; i++)
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

