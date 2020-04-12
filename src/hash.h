#ifndef __HASH_H__
#define __HASH_H__

#include "rssks.h"

#define STATS                   1'000'000
#define DIST_THRESHOLD          0.1

typedef unsigned packet_fields_t;

size_t pf_sz_bits(RSSKS_pf_t pf);
RSSKS_bytes_t field_from_headers(RSSKS_headers_t *h, RSSKS_pf_t pf);
RSSKS_in_t header_to_hash_input(RSSKS_cfg_t cfg, RSSKS_headers_t h);
RSSKS_headers_t RSSKS_in_to_header(RSSKS_cfg_t cfg, RSSKS_in_t hi);

void rand_key(RSSKS_cfg_t cfg, out RSSKS_key_t key);
void zero_key(RSSKS_key_t key);
bool is_zero_key(RSSKS_key_t key);
bool k_test_dist(RSSKS_cfg_t cfg, RSSKS_key_t k);

#endif