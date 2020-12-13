#include <r3s.h>

int main () {
    R3S_status_t    status;
    R3S_cfg_t       cfg;
    R3S_key_t       k;

    R3S_cfg_init(&cfg);
    R3S_cfg_set_number_of_keys(cfg, 1);

    R3S_cfg_load_opt(cfg, R3S_OPT_NON_FRAG_IPV4_TCP);
    R3S_cfg_set_skew_analysis(cfg, false);

    status = R3S_keys_fit_cnstrs(cfg, &R3S_cnstr_symmetric_ip, &k);
    
    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("%s\n", R3S_status_to_string(status));

    if (status == R3S_STATUS_SUCCESS)
        printf("result:\n%s\n", R3S_key_to_string(k));

    R3S_cfg_delete(cfg);
}
