#ifndef __HASH_H__
#define __HASH_H__

#include "rssks.h"

#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

#define STATS                   1'000'000
#define DIST_THRESHOLD          0.1

#define CORES                   8
#define HASH_TO_CORE(hash)      (hash % CORES)

#define HASH_INPUT_SIZE         13
#define HASH_OUTPUT_SIZE        4
#define KEY_SIZE                52

#define HASH_INPUT_SIZE_BITS    (HASH_INPUT_SIZE * 8)
#define HASH_OUTPUT_SIZE_BITS   (HASH_OUTPUT_SIZE * 8)
#define KEY_SIZE_BITS           (KEY_SIZE * 8)

#define BIT_FROM_BYTE(b, i)     (((b) >> (i)) & 1)
#define BIT_FROM_KEY(b, k)      (BIT_FROM_BYTE(k[(b) / 8], 7 - ((b) % 8)))

typedef unsigned packet_fields_t;

typedef struct {
    rss_input_cfg_t input_cfg;
    unsigned        input_size; 
} hash_cfg_t;

// big-endian version
unsigned packet_field_offset_be_bits(hash_cfg_t cfg, packet_field_t pf);

// little-endian version
unsigned packet_field_offset_le_bits(hash_cfg_t cfg, packet_field_t pf);

// DEBUG
void print_key(rss_key_t k);
void print_headers(headers_t headers, bool tidy);
void print_hash_input(hash_input_t input);
void print_hash_output(hash_output_t output);

headers_t rand_headers();
void rand_key(rss_key_t key);
void zero_key(rss_key_t key);
bool is_zero_key(rss_key_t key);
headers_t header_from_constraints(headers_t h);
hash_output_t hash(rss_key_t k, headers_t h);
bool k_test_dist(rss_key_t k);

#endif