#include <rssks.h>

void ipv4_1()
{
    RSSKS_cfg_t     cfg;
    RSSKS_out_t     o;
    RSSKS_headers_t h;
    RSSKS_key_t     k = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    RSSKS_cfg_init(&cfg);
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);

    h.ipv4_dst[0] = 161;
    h.ipv4_dst[1] = 142;
    h.ipv4_dst[2] = 100;
    h.ipv4_dst[3] = 80;

    h.tcp_dst[0]  = (1766 >> 8) & 0xff;
    h.tcp_dst[1]  = (1766 >> 0) & 0xff;

    h.ipv4_src[0] = 66;
    h.ipv4_src[1] = 9;
    h.ipv4_src[2] = 149;
    h.ipv4_src[3] = 187;

    h.tcp_src[0]  = (2794 >> 8) & 0xff;
    h.tcp_src[1]  = (2794 >> 0) & 0xff;

    printf("%s\n", RSSKS_headers_to_string(cfg, h).headers);

    RSSKS_hash(cfg, k, h, &o);

    printf("%s\n", RSSKS_hash_output_to_string(o).output);
}

void ipv4_2()
{
    RSSKS_cfg_t     cfg;
    RSSKS_out_t     o;
    RSSKS_headers_t h;
    RSSKS_key_t     k = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    RSSKS_cfg_init(&cfg);
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);

    h.ipv4_dst[0] = 65;
    h.ipv4_dst[1] = 69;
    h.ipv4_dst[2] = 140;
    h.ipv4_dst[3] = 83;

    h.tcp_dst[0]  = (4739 >> 8) & 0xff;
    h.tcp_dst[1]  = (4739 >> 0) & 0xff;

    h.ipv4_src[0] = 199;
    h.ipv4_src[1] = 92;
    h.ipv4_src[2] = 111;
    h.ipv4_src[3] = 2;

    h.tcp_src[0]  = (14230 >> 8) & 0xff;
    h.tcp_src[1]  = (14230 >> 0) & 0xff;

    printf("%s\n", RSSKS_headers_to_string(cfg, h).headers);

    RSSKS_hash(cfg, k, h, &o);

    printf("%s\n", RSSKS_hash_output_to_string(o).output);
}

void ipv4_tcp_1()
{
    RSSKS_cfg_t     cfg;
    RSSKS_out_t     o;
    RSSKS_headers_t h;
    RSSKS_key_t     k = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    RSSKS_cfg_init(&cfg);
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4_TCP);

    h.ipv4_dst[0] = 161;
    h.ipv4_dst[1] = 142;
    h.ipv4_dst[2] = 100;
    h.ipv4_dst[3] = 80;

    h.tcp_dst[0]  = (1766 >> 8) & 0xff;
    h.tcp_dst[1]  = (1766 >> 0) & 0xff;

    h.ipv4_src[0] = 66;
    h.ipv4_src[1] = 9;
    h.ipv4_src[2] = 149;
    h.ipv4_src[3] = 187;

    h.tcp_src[0]  = (2794 >> 8) & 0xff;
    h.tcp_src[1]  = (2794 >> 0) & 0xff;

    printf("%s\n", RSSKS_headers_to_string(cfg, h).headers);

    RSSKS_hash(cfg, k, h, &o);

    printf("%s\n", RSSKS_hash_output_to_string(o).output);
}

void ipv6_tcp_1()
{
    RSSKS_cfg_t     cfg;
    RSSKS_out_t     o;
    RSSKS_headers_t h;
    RSSKS_key_t     k = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    RSSKS_cfg_init(&cfg);
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV6_TCP);

    h.ipv6_dst[0]  = 0x3f;
    h.ipv6_dst[1]  = 0xfe;
    h.ipv6_dst[2]  = 0x25;
    h.ipv6_dst[3]  = 0x01;

    h.ipv6_dst[4]  = 0x02;
    h.ipv6_dst[5]  = 0x00;
    h.ipv6_dst[6]  = 0x00;
    h.ipv6_dst[7]  = 0x03;

    h.ipv6_dst[8]  = 0;
    h.ipv6_dst[9]  = 0;
    h.ipv6_dst[10] = 0;
    h.ipv6_dst[11] = 0;

    h.ipv6_dst[12] = 0;
    h.ipv6_dst[13] = 0;
    h.ipv6_dst[14] = 0;
    h.ipv6_dst[15] = 1;

    h.tcp_dst[0]   = (1766 >> 8) & 0xff;
    h.tcp_dst[1]   = (1766 >> 0) & 0xff;

    h.ipv6_src[0]  = 0x3f;
    h.ipv6_src[1]  = 0xfe;
    h.ipv6_src[2]  = 0x25;
    h.ipv6_src[3]  = 0x01;

    h.ipv6_src[4]  = 0x02;
    h.ipv6_src[5]  = 0x00;
    h.ipv6_src[6]  = 0x1f;
    h.ipv6_src[7]  = 0xff;

    h.ipv6_src[8]  = 0;
    h.ipv6_src[9]  = 0;
    h.ipv6_src[10] = 0;
    h.ipv6_src[11] = 0;

    h.ipv6_src[12] = 0;
    h.ipv6_src[13] = 0;
    h.ipv6_src[14] = 0;
    h.ipv6_src[15] = 7;

    h.tcp_src[0]   = (2794 >> 8) & 0xff;
    h.tcp_src[1]   = (2794 >> 0) & 0xff;

    printf("%s\n", RSSKS_headers_to_string(cfg, h).headers);

    RSSKS_hash(cfg, k, h, &o);

    printf("%s\n", RSSKS_hash_output_to_string(o).output);
}

int main () {
    ipv4_1();
    ipv4_2();
    ipv4_tcp_1();
    ipv6_tcp_1();
}