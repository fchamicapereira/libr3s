#include <r3s.h>

Z3_ast mk_p_cnstrs(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2)
{
    if (
        p1.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4 && 
        p2.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4
    ) return R3S_cnstr_symmetric_ip(cfg, p1, p2);
    
    if (
        p1.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4_TCP &&
        p2.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4_TCP
    ) return R3S_cnstr_symmetric_tcp_ip(cfg, p1, p2);
    
    return NULL;
}

int validate(R3S_cfg_t cfg, R3S_key_t k)
{
    R3S_packet_t p1, p2;
    R3S_key_hash_out_t o1, o2;
    R3S_packet_from_cnstrs_data_t data;

    for (int i = 0; i < 25; i++)
    {
        R3S_packet_rand(cfg, &p1);

        data.constraints = &mk_p_cnstrs;
        data.packet_in   = p1;
        data.key_id_in   = 0;
        data.key_id_out  = 0;

        R3S_packet_from_cnstrs(cfg, data, &p2);

        R3S_key_hash(cfg, k, p1, &o1);
        R3S_key_hash(cfg, k, p2, &o2);

        printf("\n===== iteration %d =====\n", i);

        printf("%s\n", R3S_packet_to_string(p1));
        printf("%s\n", R3S_key_hash_output_to_string(o1));

        printf("%s\n", R3S_packet_to_string(p2));
        printf("%s\n", R3S_key_hash_output_to_string(o2));;

        if (o1 != o2)
        {
            printf("Failed! %u != %u. Exiting.\n", o1, o2);
            return 0;
        }
    }

    return 1;
}

int main () {
    R3S_cfg_t       cfg;
    R3S_key_t       k;
    R3S_status_t    status;

    R3S_cfg_init(&cfg, 1);
    R3S_cfg_load_opt(cfg, R3S_OPT_NON_FRAG_IPV4);
    R3S_cfg_load_opt(cfg, R3S_OPT_NON_FRAG_IPV4_TCP);

    status = R3S_keys_fit_cnstrs(cfg, &mk_p_cnstrs, &k);

    validate(cfg, k);
    
    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("%s\n", R3S_status_to_string(status));

    if (status == R3S_STATUS_SUCCESS)
        printf("result:\n%s\n", R3S_key_to_string(k));

    R3S_cfg_delete(cfg);
}
