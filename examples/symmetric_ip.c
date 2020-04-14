#include <rssks.h>

Z3_ast mk_d_cnstrs(RSSKS_cfg_t rssks_cfg, Z3_context ctx, Z3_ast d1, Z3_ast d2)
{
    Z3_ast d1_ipv4_src, d1_ipv4_dst;
    Z3_ast d2_ipv4_src, d2_ipv4_dst;
    Z3_ast and_args[2];

    RSSKS_extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_SRC, &d1_ipv4_src);
    RSSKS_extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_DST, &d1_ipv4_dst);

    RSSKS_extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_IPV4_SRC, &d2_ipv4_src);
    RSSKS_extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_IPV4_DST, &d2_ipv4_dst);

    and_args[0] = Z3_mk_eq(ctx, d1_ipv4_src, d2_ipv4_dst);
    and_args[1] = Z3_mk_eq(ctx, d1_ipv4_dst, d2_ipv4_src);

    return Z3_mk_and(ctx, 2, and_args);
}

int main () {
    RSSKS_cfg_t       cfg;
    RSSKS_key_t       k;
    RSSKS_cnstrs_func cnstrs[1];

    RSSKS_cfg_init(&cfg);
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);

    cnstrs[0] = &mk_d_cnstrs;
    RSSKS_find_keys(cfg, cnstrs, &k);
    
    printf("result:\n%s\n", RSSKS_key_to_string(k));
}