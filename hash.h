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

typedef enum {
    UDP_OUTER,
    VNI,

    IPV4_SRC,
    IPV4_DST,

    IPV6_SRC,
    IPV6_DST,

    TCP_SRC,
    TCP_DST,

    UDP_SRC,
    UDP_DST,

    SCTP_SRC,
    SCTP_DST,
    SCTP_V_TAG,

    L2_TYPE,
} packet_field_t;

typedef unsigned char byte_t;

typedef byte_t*  hash_input_t;
typedef byte_t   rss_key_t[KEY_SIZE];
typedef uint32_t hash_output_t;

typedef byte_t   ipv6_t[16];
typedef uint32_t ipv4_t;
typedef uint32_t v_tag_t;  // verification tag (SCTP)
typedef byte_t   vni_t[3]; // unique identifier for the individual VXLAN segment
typedef uint16_t port_t;

typedef struct {
    port_t  udp_outer;
    vni_t   vni;

    ipv4_t  ipv4_src;
    ipv4_t  ipv4_dst;

    ipv6_t  ipv6_src;
    ipv6_t  ipv6_dst;

    port_t  tcp_src;
    port_t  tcp_dst;

    port_t  udp_src;
    port_t  udp_dst;

    port_t  sctp_src;
    port_t  sctp_dst;
    v_tag_t sctp_v_tag; // sctp verification tag

    // missing L2 ethertype
} headers_t;

typedef unsigned packet_fields_t;

typedef struct {
    rss_input_cfg_t input_cfg;
    unsigned        input_size; 
} hash_cfg_t;

// big-endian version
unsigned packet_field_offset_be_bits(packet_field_t pf);

// little-endian version
unsigned packet_field_offset_le_bits(packet_field_t pf);

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