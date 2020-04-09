#include <stdio.h>
#include <rssks.h>

Z3_ast mk_d_cnstrs(RSSKS_cfg_t rssks_cfg, Z3_context ctx, Z3_ast d1, Z3_ast d2)
{
    Z3_ast d1_ipv4_src, d1_ipv4_dst, d1_tcp_src, d1_tcp_dst;
    Z3_ast d2_ipv4_src, d2_ipv4_dst, d2_tcp_src, d2_tcp_dst;
    Z3_ast _and_args[4];

    d1_ipv4_src = extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_SRC);
    d1_ipv4_dst = extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_DST);

    d1_tcp_src  = extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_TCP_SRC);
    d1_tcp_dst  = extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_TCP_DST);

    d2_ipv4_src = extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_IPV4_SRC);
    d2_ipv4_dst = extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_IPV4_DST);

    d2_tcp_src  = extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_TCP_SRC);
    d2_tcp_dst  = extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_TCP_DST);


    _and_args[0] = Z3_mk_eq(ctx, d1_ipv4_src, d2_ipv4_dst);
    _and_args[1] = Z3_mk_eq(ctx, d1_ipv4_dst, d2_ipv4_src);
    _and_args[2] = Z3_mk_eq(ctx, d1_tcp_src, d2_tcp_dst);
    _and_args[3] = Z3_mk_eq(ctx, d1_tcp_dst, d2_tcp_src);

    return Z3_mk_and(ctx, 4, _and_args);
}

int main () {
    RSSKS_cfg_t cfg;
    RSSKS_key_t k;

    cfg = RSSKS_cfg_init();
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4_TCP);

    find_k(cfg, &mk_d_cnstrs, k);
    print_key(k);
}