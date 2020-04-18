#include <r3s.h>

Z3_ast p_cnstrs(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    return iopt == 0
        ? R3S_mk_symmetric_ip_cnstr(r3s_cfg, iopt, ctx, p1, p2)
        : R3S_mk_symmetric_tcp_ip_cnstr(r3s_cfg, iopt, ctx, p1, p2);
}

int validate(R3S_cfg_t cfg, R3S_key_t k)
{
    R3S_packet_t p1, p2;
    R3S_out_t    o1, o2;

    for (int i = 0; i < 25; i++)
    {
        R3S_rand_packet(cfg, &p1);
        R3S_packet_from_cnstrs(cfg, p1, &p_cnstrs, &p2);

        R3S_hash(cfg, k, p1, &o1);
        R3S_hash(cfg, k, p2, &o2);

        printf("\n===== iteration %d =====\n", i);

        printf("%s\n", R3S_packet_to_string(p1));
        printf("%s\n", R3S_hash_output_to_string(o1));

        printf("%s\n", R3S_packet_to_string(p1));
        printf("%s\n", R3S_hash_output_to_string(o2));;

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
    R3S_cnstrs_func cnstrs[1];
    R3S_status_t    status;

    R3S_cfg_init(&cfg);
    R3S_cfg_load_in_opt(&cfg, R3S_IN_OPT_NON_FRAG_IPV4);
    R3S_cfg_load_in_opt(&cfg, R3S_IN_OPT_NON_FRAG_IPV4_TCP);

    cnstrs[0] = &p_cnstrs;
    status    = R3S_find_keys(cfg, cnstrs, &k);

    validate(cfg, k);
    
    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("%s\n", R3S_status_to_string(status));

    if (status == R3S_STATUS_SUCCESS)
        printf("result:\n%s\n", R3S_key_to_string(k));

    R3S_cfg_delete(&cfg);
}