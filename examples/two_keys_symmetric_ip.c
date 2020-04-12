#include <rssks.h>

Z3_ast mk_d_cnstrs(RSSKS_cfg_t rssks_cfg, Z3_context ctx, Z3_ast d1, Z3_ast d2)
{
    Z3_ast d1_ipv4_src, d1_ipv4_dst;
    Z3_ast d2_ipv4_src, d2_ipv4_dst;
    Z3_ast and_args[2];

    d1_ipv4_src = RSSKS_extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_SRC);
    d1_ipv4_dst = RSSKS_extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_DST);

    d2_ipv4_src = RSSKS_extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_IPV4_SRC);
    d2_ipv4_dst = RSSKS_extract_pf_from_d(rssks_cfg, ctx, d2, RSSKS_PF_IPV4_DST);

    and_args[0] = Z3_mk_eq(ctx, d1_ipv4_src, d2_ipv4_dst);
    and_args[1] = Z3_mk_eq(ctx, d1_ipv4_dst, d2_ipv4_src);

    return Z3_mk_and(ctx, 2, and_args);
}

int validate(RSSKS_cfg_t cfg, RSSKS_key_t k1, RSSKS_key_t k2)
{
    RSSKS_headers_t h1, h2;
    RSSKS_out_t     o1, o2;

    for (int i = 0; i < 25; i++)
    {
        h1 = RSSKS_rand_headers(cfg);
        h2 = RSSKS_headers_from_cnstrs(cfg, &mk_d_cnstrs, h1);
        o1 = RSSKS_hash(cfg, k1, h1);
        o2 = RSSKS_hash(cfg, k2, h2);

        printf("\n===== iteration %d =====\n", i);

        printf("\n*** port 1\n\n");
        RSSKS_print_headers(cfg, h1);
        RSSKS_print_hash_output(o1);

        printf("\n*** port 2\n\n");
        RSSKS_print_headers(cfg, h2);
        RSSKS_print_hash_output(o1);

        if (o1 != o2)
        {
            printf("Failed! %u != %u. Exiting.\n", o1, o2);
            return 0;
        }
    }

    return 1;
}

int main () {
    RSSKS_cfg_t       cfg;
    RSSKS_key_t       keys[2];
    RSSKS_cnstrs_func cnstrs[1];

    cfg        = RSSKS_cfg_init();
    cfg.n_keys = 2;
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);

    cnstrs[0] = NULL;
    cnstrs[1] = NULL;
    cnstrs[2] = &mk_d_cnstrs;

    RSSKS_find_keys(cfg, cnstrs, keys);
    
    printf("k1:\n");
    RSSKS_print_key(keys[0]);

    printf("k2:\n");
    RSSKS_print_key(keys[1]);

    validate(cfg, keys[0], keys[1]);
}