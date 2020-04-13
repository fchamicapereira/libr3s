#include <rssks.h>
#include <assert.h>

Z3_ast mk_d_cnstrs(RSSKS_cfg_t rssks_cfg, Z3_context ctx, Z3_ast d1, Z3_ast d2)
{
    Z3_ast d1_ipv4_src;
    Z3_ast eq_ipv4;

    RSSKS_extract_pf_from_d(rssks_cfg, ctx, d1, RSSKS_PF_IPV4_SRC, &d1_ipv4_src);

    eq_ipv4  = Z3_mk_eq(ctx, d1_ipv4_src, d1_ipv4_src);

    return eq_ipv4;
}

int main () {
    RSSKS_cfg_t       cfg;
    RSSKS_key_t       k;
    RSSKS_cnstrs_func cnstrs[1];
    RSSKS_status_t    status;

    RSSKS_cfg_init(&cfg);
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);

    cnstrs[0] = &mk_d_cnstrs;

    status = RSSKS_find_keys(cfg, cnstrs, &k);

    assert(status == RSSKS_STATUS_NO_SOLUTION);
    
    printf("No solution\n");
}