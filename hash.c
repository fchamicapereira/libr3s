#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>

#include "util.h"
#include "hash.h"

void print_headers_verbose(headers_t headers)
{
    printf("src IP    %hu.%hu.%hu.%hu\n",
        (headers.src_ip   >> 24) & 0xff,
        (headers.src_ip   >> 16) & 0xff,
        (headers.src_ip   >>  8) & 0xff,
        (headers.src_ip   >>  0) & 0xff);
    
    printf("dst IP    %hu.%hu.%hu.%hu\n",
        (headers.dst_ip   >> 24) & 0xff,
        (headers.dst_ip   >> 16) & 0xff,
        (headers.dst_ip   >>  8) & 0xff,
        (headers.dst_ip   >>  0) & 0xff);
    
    printf("src port  %hu\n", headers.src_port);
    printf("dst port  %hu\n", headers.dst_port);

    printf("protocol  ");
    switch (headers.protocol) {
        case IPPROTO_ICMP: puts("ICMP"); break;
        case IPPROTO_TCP:  puts("TCP");  break;
        case IPPROTO_UDP:  puts("UDP");  break;
        default: printf("%d \t *** WARNING: protocol unaccounted ***\n", headers.protocol);
    }

    puts("");
}

void print_headers_tidy(headers_t headers)
{
    printf("%3hu.%3hu.%3hu.%3hu:%5hu => %3hu.%3hu.%3hu.%3hu:%5hu  ",
        (headers.src_ip   >> 24) & 0xff,
        (headers.src_ip   >> 16) & 0xff,
        (headers.src_ip   >>  8) & 0xff,
        (headers.src_ip   >>  0) & 0xff,
        headers.src_port,
        (headers.dst_ip   >> 24) & 0xff,
        (headers.dst_ip   >> 16) & 0xff,
        (headers.dst_ip   >>  8) & 0xff,
        (headers.dst_ip   >>  0) & 0xff,
        headers.dst_port
    );

    switch (headers.protocol) {
        case IPPROTO_ICMP: printf("ICMP"); break;
        case IPPROTO_TCP:  printf("TCP");  break;
        case IPPROTO_UDP:  printf("UDP");  break;
        default: printf("%d \t *** WARNING: protocol unaccounted ***", headers.protocol);
    }

    puts("");
}

void print_headers(headers_t headers, bool tidy)
{
    if (tidy) print_headers_tidy(headers);
    else      print_headers_verbose(headers);
}

void print_hash_input(hash_input_t hi)
{
    printf("input     ");
    for (int i = 0; i < HASH_INPUT_SIZE; i++)
        printf("%02x ", hi[i] & 0xff);
    puts("");
}

void print_key(rss_key_t k)
{
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x ", k[i] & 0xff);
        if ((i+1) % 8 == 0) puts("");
    }
    puts("");
}

void print_hash_output(hash_output_t output)
{
    printf("output    %02x %02x %02x %02x\n",
        (output >> 24) & 0xff,
        (output >> 16) & 0xff,
        (output >>  8) & 0xff,
        (output >>  0) & 0xff
    );
    printf("core      %d\n\n", HASH_TO_CORE(output));
}

headers_t rand_headers()
{
    headers_t headers;
    int protocols[3] = { IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP };
    unsigned int seed;
    
    // get the seed
    FILE* urandom = fopen("/dev/urandom", "r");
    fread(&seed, sizeof(int), 1, urandom);
    fclose(urandom);
   
    srand(seed);

    headers.src_ip   = (ipv4_t) rand();
    headers.dst_ip   = (ipv4_t) rand();
    headers.src_port = (port_t) rand();
    headers.dst_port = (port_t) rand();
    headers.protocol = protocols[rand() % 3];

    return headers;
}

void rand_key(rss_key_t key)
{
    init_rand();

    for (int byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = rand() & 0xff;
}

void zero_key(rss_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        key[byte] = 0;
}

bool is_zero_key(rss_key_t key)
{
    for (int byte = 0; byte < KEY_SIZE; byte++)
        if (key[byte]) return false;
    return true;
}

hash_input_t header_to_hash_input(headers_t headers)
{
    hash_input_t hi = (hash_input_t) malloc(HASH_INPUT_SIZE);
    unsigned offset;

    offset = packet_field_offset_be_bits(SRC_IP);
    
    hi[offset / 8 + 0] = (headers.src_ip   >> 24) & 0xff;
    hi[offset / 8 + 1] = (headers.src_ip   >> 16) & 0xff;
    hi[offset / 8 + 2] = (headers.src_ip   >>  8) & 0xff;
    hi[offset / 8 + 3] = (headers.src_ip   >>  0) & 0xff;

    offset = packet_field_offset_be_bits(DST_IP);

    hi[offset / 8 + 0] = (headers.dst_ip   >> 24) & 0xff;
    hi[offset / 8 + 1] = (headers.dst_ip   >> 16) & 0xff;
    hi[offset / 8 + 2] = (headers.dst_ip   >>  8) & 0xff;
    hi[offset / 8 + 3] = (headers.dst_ip   >>  0) & 0xff;

    offset = packet_field_offset_be_bits(SRC_PORT);

    hi[offset / 8 + 0] = (headers.src_port >>  8) & 0xff;
    hi[offset / 8 + 1] = (headers.src_port >>  0) & 0xff;

    offset = packet_field_offset_be_bits(DST_PORT);

    hi[offset / 8 + 0] = (headers.dst_port >>  8) & 0xff;
    hi[offset / 8 + 1] = (headers.dst_port >>  0) & 0xff;

    offset = packet_field_offset_be_bits(PROTOCOL);

    hi[offset / 8] = (headers.protocol >>  0) & 0xff;

    return hi;
}

headers_t hash_input_to_header(hash_input_t hi)
{
    headers_t headers;
    unsigned offset;

    offset = packet_field_offset_be_bits(SRC_IP);
    
    headers.src_ip   = 0;
    headers.src_ip   = (headers.src_ip << 8) | (hi[offset / 8 + 0] & 0xff);
    headers.src_ip   = (headers.src_ip << 8) | (hi[offset / 8 + 1] & 0xff);
    headers.src_ip   = (headers.src_ip << 8) | (hi[offset / 8 + 2] & 0xff);
    headers.src_ip   = (headers.src_ip << 8) | (hi[offset / 8 + 3] & 0xff);

    offset = packet_field_offset_be_bits(DST_IP);

    headers.dst_ip   = 0;
    headers.dst_ip   = (headers.dst_ip << 8) | (hi[offset / 8 + 0] & 0xff);
    headers.dst_ip   = (headers.dst_ip << 8) | (hi[offset / 8 + 1] & 0xff);
    headers.dst_ip   = (headers.dst_ip << 8) | (hi[offset / 8 + 2] & 0xff);
    headers.dst_ip   = (headers.dst_ip << 8) | (hi[offset / 8 + 3] & 0xff);

    offset = packet_field_offset_be_bits(SRC_PORT);

    headers.src_port = 0;
    headers.src_port = (headers.src_port << 8) | (hi[offset / 8 + 0] & 0xff);
    headers.src_port = (headers.src_port << 8) | (hi[offset / 8 + 1] & 0xff);

    offset = packet_field_offset_be_bits(DST_PORT);

    headers.dst_port = 0;
    headers.dst_port = (headers.dst_port << 8) | (hi[offset / 8 + 0] & 0xff);
    headers.dst_port = (headers.dst_port << 8) | (hi[offset / 8 + 1] & 0xff);

    offset = packet_field_offset_be_bits(PROTOCOL);

    headers.protocol = headers.protocol | (hi[offset / 8] & 0xff);

    return headers;
}

void lshift(rss_key_t k)
{
    byte_t lsb, msb = 0; // there are no 1-bit data structures in C :(

    for (int i = KEY_SIZE; i >= 0; i--)
    {
        lsb = (k[i] >> 7) & 1;
        k[i] = ((k[i] << 1) | msb) & 0xff;
        msb = lsb;
    }

    k[KEY_SIZE - 1] |= msb;
}

hash_output_t hash(rss_key_t k, headers_t h)
{
    hash_output_t output = 0;
    rss_key_t     k_copy;
    hash_input_t  hi; 

    hi = header_to_hash_input(h);

    memcpy(k_copy, k, sizeof(byte_t) * KEY_SIZE);

    for (int i = 0; i < HASH_INPUT_SIZE; i++)
    {
        // iterate every bit
        for (int shift = 7; shift >= 0; shift--)
        {
            if ((hi[i] >> shift) & 1) output ^= _32_LSB(k_copy);
            lshift(k_copy);
        }
    }

    free(hi);

    return output;
}

float k_dist_mean(rss_key_t k)
{
    headers_t     h;
    hash_output_t o;
    unsigned      core_dist[CORES];
    float         mean;

    for (int core = 0; core < CORES; core++) core_dist[core] = 0;

    for (unsigned counter = 0; counter < STATS; counter++) {
        h = rand_headers();
        o = hash(k, h);

        core_dist[HASH_TO_CORE(o)] += 1;
    }

    mean = 0;
    for (int core = 0; core < CORES; core++)
        mean += core * core_dist[core];
    mean = mean / STATS;

    return mean;
}

bool k_test_dist(rss_key_t k)
{
    float observed_mean;
    float goal_mean;
    float dm;
    
    observed_mean = k_dist_mean(k);
    
    goal_mean = 0;
    for (int core = 0; core < CORES; core++) goal_mean += core;
    goal_mean /= CORES;

    dm = observed_mean > goal_mean
        ? (observed_mean - goal_mean) * 100.0 / CORES
        : (goal_mean - observed_mean) * 100.0 / CORES;

    #if DEBUG
        print_key(k);
    #endif
    DEBUG_LOG("observed mean %lf\n", observed_mean);
    DEBUG_LOG("dm %lf\n", dm);
    
    return dm <= DIST_THRESHOLD;
}

unsigned packet_field_offset_be_bits(packet_field_t pf)
{
    unsigned offset = 0;

    switch(pf)
    {
        case PROTOCOL: offset += sizeof(port_t) * 8;
        case DST_PORT: offset += sizeof(port_t) * 8;
        case SRC_PORT: offset += sizeof(ipv4_t) * 8;
        case DST_IP:   offset += sizeof(ipv4_t) * 8;
        case SRC_IP:   break;
        default:       assert(false);
    }

    assert(offset < HASH_INPUT_SIZE_BITS);
    return offset;
}

unsigned packet_field_offset_le_bits(packet_field_t pf)
{
    unsigned offset = HASH_INPUT_SIZE_BITS;

    switch(pf)
    {
        case PROTOCOL: offset -= sizeof(protocol_t) * 8;
        case DST_PORT: offset -= sizeof(port_t) * 8;
        case SRC_PORT: offset -= sizeof(port_t) * 8;
        case DST_IP:   offset -= sizeof(ipv4_t) * 8;
        case SRC_IP:   offset -= sizeof(ipv4_t) * 8; break;
        default:       assert(false);
    }

    assert(offset < HASH_INPUT_SIZE_BITS);
    return offset;
}

size_t packet_field_sz_bits(packet_field_t pf)
{
    switch (pf)
    {
        case PROTOCOL: return sizeof(protocol_t) * 8;
        case DST_PORT: return sizeof(port_t) * 8;
        case SRC_PORT: return sizeof(port_t) * 8;
        case DST_IP:   return sizeof(ipv4_t) * 8;
        case SRC_IP:   return sizeof(ipv4_t) * 8;
        default:       assert(false);
    }
}

hash_cfg_t hash_cfg_init()
{
    hash_cfg_t cfg = {
        .input_cfg     = 0,
        .input_size = 0
    };

    return cfg;
}

void hash_cfg_load_input_cfg(hash_cfg_t *cfg, rss_input_cfg_t input_cfg)
{
    if (hash_cfg_check_field(*cfg, input_cfg)) return;

    switch (input_cfg)
    {
        case GENEVE_OAM:
        case VXLAN_GPE_OAM:
            hash_cfg_load_field(cfg, UDP_OUTER);
            hash_cfg_load_field(cfg, VNI);
            break;
        case NON_FRAG_IPV4_UDP:
            hash_cfg_load_field(cfg, IPV4_SRC);
            hash_cfg_load_field(cfg, IPV4_DST);
            hash_cfg_load_field(cfg, UDP_SRC);
            hash_cfg_load_field(cfg, UDP_DST);
            break;
        case NON_FRAG_IPV4_TCP:
            hash_cfg_load_field(cfg, IPV4_SRC);
            hash_cfg_load_field(cfg, IPV4_DST);
            hash_cfg_load_field(cfg, TCP_SRC);
            hash_cfg_load_field(cfg, TCP_DST);
            break;
        case NON_FRAG_IPV4_SCTP:
            hash_cfg_load_field(cfg, IPV4_SRC);
            hash_cfg_load_field(cfg, IPV4_DST);
            hash_cfg_load_field(cfg, SCTP_SRC);
            hash_cfg_load_field(cfg, SCTP_DST);
            hash_cfg_load_field(cfg, SCTP_V_TAG);
            break;
        case NON_FRAG_IPV4:
        case FRAG_IPV4:
            hash_cfg_load_field(cfg, IPV4_SRC);
            hash_cfg_load_field(cfg, IPV4_DST);
            break;
        case NON_FRAG_IPV6_UDP:
            hash_cfg_load_field(cfg, IPV6_SRC);
            hash_cfg_load_field(cfg, IPV6_DST);
            hash_cfg_load_field(cfg, UDP_SRC);
            hash_cfg_load_field(cfg, UDP_DST);
            break;
        case NON_FRAG_IPV6_TCP:
            hash_cfg_load_field(cfg, IPV6_SRC);
            hash_cfg_load_field(cfg, IPV6_DST);
            hash_cfg_load_field(cfg, TCP_SRC);
            hash_cfg_load_field(cfg, TCP_DST);
            break;
        case NON_FRAG_IPV6_SCTP:
            hash_cfg_load_field(cfg, IPV6_SRC);
            hash_cfg_load_field(cfg, IPV6_DST);
            hash_cfg_load_field(cfg, SCTP_SRC);
            hash_cfg_load_field(cfg, SCTP_DST);
            hash_cfg_load_field(cfg, SCTP_V_TAG);
            break;
        case NON_FRAG_IPV6:
        case FRAG_IPV6:
            hash_cfg_load_field(cfg, IPV6_SRC);
            hash_cfg_load_field(cfg, IPV6_DST);
            break;
        default:
            DEBUG_LOG("Input configuration unknown: %d\n", input_cfg);
            assert(false);
    }
}

void hash_cfg_load_field(hash_cfg_t *cfg, packet_field_t pf)
{
    if (hash_cfg_check_field(*cfg, pf)) return;

    cfg->input_cfg  = cfg->input_cfg | (1 << pf);
    cfg->input_size += packet_field_sz_bits(pf);
}

bool hash_cfg_check_field(hash_cfg_t cfg, packet_field_t pf);
{
    return (cfg.input_cfg >> pf) & 1;
}
