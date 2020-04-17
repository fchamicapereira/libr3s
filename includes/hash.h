#ifndef __RSSKS_HASH_H__
#define __RSSKS_HASH_H__

#include "rssks.h"

#define STATS                   1000000
#define DIST_THRESHOLD          0.1

typedef unsigned packet_fields_t;

RSSKS_in_t     RSSKS_packet_to_hash_input(RSSKS_cfg_t cfg, unsigned iopt, RSSKS_packet_t h);
RSSKS_packet_t RSSKS_in_to_packet(RSSKS_cfg_t cfg, unsigned iopt, RSSKS_in_t hi, RSSKS_packet_cfg_t p_cfg);
void           RSSKS_rand_key(RSSKS_cfg_t cfg, out RSSKS_key_t key);
void           RSSKS_zero_key(RSSKS_key_t key);
bool           RSSKS_is_zero_key(RSSKS_key_t key);
bool           RSSKS_k_test_dist(RSSKS_cfg_t cfg, RSSKS_key_t k);

#endif