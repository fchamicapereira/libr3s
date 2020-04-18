#include <r3s.h>
#include <assert.h>

Z3_ast mk_p_cnstrs(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    R3S_status_t status;
    Z3_ast         p1_ipv4_src;
    Z3_ast         eq_ipv4;

    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p1, R3S_PF_IPV4_SRC, &p1_ipv4_src);

    if (status != R3S_STATUS_SUCCESS) return NULL;

    eq_ipv4  = Z3_mk_eq(ctx, p1_ipv4_src, p1_ipv4_src);

    return eq_ipv4;
}

int main () {
    R3S_cfg_t       cfg;
    R3S_key_t       k;
    R3S_cnstrs_func cnstrs[1];
    R3S_status_t    status;

    R3S_cfg_init(&cfg);
    R3S_cfg_load_in_opt(&cfg, R3S_IN_OPT_NON_FRAG_IPV4);

    cnstrs[0] = &mk_p_cnstrs;
    status    = R3S_find_keys(cfg, cnstrs, &k);

    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("%s\n", R3S_status_to_string(status));
    R3S_cfg_delete(&cfg);
}