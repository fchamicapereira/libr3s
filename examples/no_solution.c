#include <r3s.h>
#include <assert.h>

Z3_ast mk_p_cnstrs(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2)
{
    R3S_status_t status;
    Z3_ast       p1_ipv4_src;
    Z3_ast       eq_ipv4;

    status = R3S_packet_extract_pf(cfg, p1, R3S_PF_IPV4_SRC, &p1_ipv4_src);

    if (status != R3S_STATUS_SUCCESS) return NULL;

    eq_ipv4  = Z3_mk_eq(cfg->ctx, p1_ipv4_src, p1_ipv4_src);

    return eq_ipv4;
}

int main () {
    R3S_cfg_t       cfg;
    R3S_key_t       k;
    R3S_status_t    status;

    R3S_cfg_init(&cfg);
    R3S_cfg_set_number_of_keys(cfg, 1);
    R3S_cfg_load_opt(cfg, R3S_OPT_NON_FRAG_IPV4_TCP);

    status = R3S_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &k);

    printf("%s\n", R3S_cfg_to_string(cfg));

    // R3S_STATUS_NO_SOLUTION
    printf("%s\n", R3S_status_to_string(status));

    R3S_cfg_delete(cfg);
}
