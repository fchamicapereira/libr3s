#include <r3s.h>

Z3_ast mk_p_cnstrs(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2)
{
    return NULL;
}

int main () {
    R3S_cfg_t    cfg;
    R3S_key_t    k;
    R3S_status_t status;

    R3S_cfg_init(&cfg);
    R3S_cfg_set_number_of_keys(cfg, 1);
    R3S_cfg_load_opt(cfg, R3S_OPT_NON_FRAG_IPV4_TCP);
    R3S_cfg_set_skew_analysis(cfg, false);

    status = R3S_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &k);
    
    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("%s\n", R3S_status_to_string(status));

    R3S_cfg_delete(cfg);
}
