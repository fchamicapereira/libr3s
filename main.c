#include <stdio.h>
#include <stdlib.h>

#include "rssks.h"
#include "hash.h"

/*
Z3_ast mk_d_constraints(Z3_context ctx, Z3_ast d1, Z3_ast d2)
{
    Z3_ast d1_src_ip, d1_dst_ip, d1_src_port, d1_dst_port, d1_protocol;
    Z3_ast d2_src_ip, d2_dst_ip, d2_src_port, d2_dst_port, d2_protocol;
    Z3_ast _and_args[5];

    unsigned src_ip_offset   = packet_field_offset_le_bits(SRC_IP);
    unsigned dst_ip_offset   = packet_field_offset_le_bits(DST_IP);
    unsigned src_port_offset = packet_field_offset_le_bits(SRC_PORT);
    unsigned dst_port_offset = packet_field_offset_le_bits(DST_PORT);
    unsigned protocol_offset = packet_field_offset_le_bits(PROTOCOL);

    unsigned ip_sz         = sizeof(RSSKS_ipv4_t) * 8;
    unsigned port_sz       = sizeof(RSSKS_port_t) * 8;
    unsigned protocol_sz   = sizeof(protocol_t) * 8;

    d1_src_ip    = Z3_mk_extract(ctx, src_ip_offset + ip_sz - 1, src_ip_offset, d1);
    d1_src_port  = Z3_mk_extract(ctx, src_port_offset + port_sz - 1, src_port_offset, d1);
    d1_dst_ip    = Z3_mk_extract(ctx, dst_ip_offset + ip_sz - 1, dst_ip_offset, d1);
    d1_dst_port  = Z3_mk_extract(ctx, dst_port_offset + port_sz - 1, dst_port_offset, d1);
    d1_protocol  = Z3_mk_extract(ctx, protocol_offset + protocol_sz - 1, protocol_offset, d1);

    d2_dst_ip    = Z3_mk_extract(ctx, dst_ip_offset + ip_sz - 1, dst_ip_offset, d2);
    d2_dst_port  = Z3_mk_extract(ctx, dst_port_offset + port_sz - 1, dst_port_offset, d2);
    
    d2_src_ip    = Z3_mk_extract(ctx, src_ip_offset + ip_sz - 1, src_ip_offset, d2);
    d2_src_port  = Z3_mk_extract(ctx, src_port_offset + port_sz - 1, src_port_offset, d2);
    d2_protocol  = Z3_mk_extract(ctx, protocol_offset + protocol_sz - 1, protocol_offset, d2);

    _and_args[0] = Z3_mk_eq(ctx, d1_src_ip, d2_dst_ip);
    _and_args[1] = Z3_mk_eq(ctx, d1_dst_ip, d2_src_ip);
    _and_args[2] = Z3_mk_eq(ctx, d1_src_port, d2_dst_port);
    _and_args[3] = Z3_mk_eq(ctx, d1_dst_port, d2_src_port);
    _and_args[4] = Z3_mk_eq(ctx, d1_protocol, d2_protocol);

    return Z3_mk_and(ctx, 5, _and_args);
}

void check_k(RSSKS_key_t k)
{
    RSSKS_headers_t     h1, h2;
    RSSKS_out_t o1, o2;

    for (int i = 0; i < 100; i++)
    {
        printf("Test %3d / %3d\n", i, 100);

        h1 = rand_headers();
        h2 = header_from_constraints(h1);

        printf("  "); print_headers(h1, true);
        printf("  "); print_headers(h2, true);

        o1 = hash(k, h1);
        o2 = hash(k, h2);

        if (o1 == o2) printf("PASSED\n\n");
        else {
            printf("FAILED\n");
            exit(1);
        }
    }

    k_test_dist(k);
}
*/

int main () {
    RSSKS_out_t o;
    RSSKS_headers_t h;
    RSSKS_key_t k = {
        0x5c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05, 0xc0, 
        0x00, 0x80, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x08, 
        0x01, 0xf2, 0xa1, 0x03, 0x62, 0xb1, 0x9a, 0x87, 
        0x18, 0xae, 0x5d, 0x0e, 0x3a, 0x9b, 0x1d, 0x16, 
        0xb0, 0x21, 0xbe, 0xf9, 0xa4, 0xa4, 0x64, 0xea, 
        0xf7, 0x7c, 0x99, 0xc6, 0x09, 0xb9, 0xd3, 0x7a, 
        0xab, 0x74, 0x7d, 0x0d
    };
    
    // h = rand_headers();
    
    /*
    h.src_ip   = 0b1000'0000'0000'0000'0000'0000'0000'0000;
    h.dst_ip   = 0;
    h.src_port = 0;
    h.dst_port = 0;
    h.protocol = 0;
    */

    /*
    h.src_ip = 0x420995bb;
    h.src_port = 2794;
    h.dst_ip = 0xa18e6450;
    h.dst_port = 1766;
    h.protocol = 0;

    o = hash(k, h);
    z3_hash(k, h);

    print_hash_output(o);
    */

    //find_k(k);
    //print_key(k);

    RSSKS_cfg_t cfg = RSSKS_cfg_init();
    
    puts("\nheaders");
    print_headers(cfg, h);

    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP);

    h = rand_headers();
    puts("\nheaders");
    print_headers(cfg, h);

}