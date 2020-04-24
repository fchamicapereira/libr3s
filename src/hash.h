#ifndef __R3S_HASH_H__
#define __R3S_HASH_H__

#include "../include/r3s.h"

#define STATS                   1000000
#define DIST_THRESHOLD          0.1

typedef unsigned packet_fields_t;

R3S_in_t       R3S_packet_to_hash_input(R3S_cfg_t cfg, unsigned iopt, R3S_packet_t h);
R3S_packet_t   R3S_in_to_packet(R3S_cfg_t cfg, unsigned iopt, R3S_in_t hi, R3S_in_cfg_t p_cfg);
void           R3S_rand_key(R3S_cfg_t cfg, out R3S_key_t key);
void           R3S_zero_key(R3S_key_t key);
bool           R3S_is_zero_key(R3S_key_t key);

#endif