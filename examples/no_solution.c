#include <rssks.h>
#include <assert.h>

Z3_ast mk_p_cnstrs(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    RSSKS_status_t status;
    Z3_ast         p1_ipv4_src;
    Z3_ast         eq_ipv4;

    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p1, RSSKS_PF_IPV4_SRC, &p1_ipv4_src);

    if (status != RSSKS_STATUS_SUCCESS) return NULL;

    eq_ipv4  = Z3_mk_eq(ctx, p1_ipv4_src, p1_ipv4_src);

    return eq_ipv4;
}

int main () {
    RSSKS_cfg_t       cfg;
    RSSKS_key_t       k;
    RSSKS_cnstrs_func cnstrs[1];
    RSSKS_status_t    status;

    RSSKS_cfg_init(&cfg);
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);

    cnstrs[0] = &mk_p_cnstrs;
    status    = RSSKS_find_keys(cfg, cnstrs, &k);

    printf("%s\n", RSSKS_cfg_to_string(cfg));
    printf("%s\n", RSSKS_status_to_string(status));
    RSSKS_cfg_delete(&cfg);
}