#include <r3s.h>

Z3_ast mk_p_cnstrs(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2) {

    // symmetric TCP/IP on first key (device)
    if (p1.key_id == 0 && p2.key_id == 0) {
        return R3S_cnstr_symmetric_tcp_ip(cfg, p1, p2);
    }

    // symmetric IP between the first and the second keys (devices)
    else if (p1.key_id != p2.key_id) {
        return R3S_cnstr_symmetric_ip(cfg, p1, p2);
    }

    // no constraints on the second key alone
    else {
        return NULL;
    }

}

int validate(R3S_cfg_t cfg, R3S_key_t k1, R3S_key_t k2)
{
    R3S_packet_t p1_1, p1_2, p12_1, p12_2;
    R3S_key_hash_out_t o1_1, o1_2, o12_1, o12_2;
    R3S_packet_from_cnstrs_data_t data;

    for (int i = 0; i < 25; i++)
    {
        R3S_packet_rand(cfg, &p1_1);
        R3S_packet_rand(cfg, &p12_1);

        data.constraints = &mk_p_cnstrs;
        data.packet_in   = p1_1;
        data.key_id_in   = 0;
        data.key_id_out  = 0;
        
        R3S_packet_from_cnstrs(cfg, data, &p1_2);

        data.constraints = &mk_p_cnstrs;
        data.packet_in   = p12_1;
        data.key_id_in   = 0;
        data.key_id_out  = 1;

        R3S_packet_from_cnstrs(cfg, data, &p12_2);

        R3S_key_hash(cfg, k1, p1_1, &o1_1);
        R3S_key_hash(cfg, k2, p1_2, &o1_2);
        R3S_key_hash(cfg, k1, p12_1, &o12_1);
        R3S_key_hash(cfg, k2, p12_2, &o12_2);

        printf("\n===== iteration %d =====\n", i);

        printf("\n*** port 1 \n\n");
        printf("%s\n", R3S_packet_to_string(p1_1));
        printf("%s\n", R3S_key_hash_output_to_string(o1_1));

        printf("%s\n", R3S_packet_to_string(p1_2));
        printf("%s\n", R3S_key_hash_output_to_string(o1_2));;

        if (o1_1 != o1_2)
        {
            printf("Failed! %u != %u. Exiting.\n", o1_1, o1_2);
            return 0;
        }

        printf("\n*** port 1 (~ port 2)\n\n");
        printf("%s\n", R3S_packet_to_string(p12_1));
        printf("%s\n", R3S_key_hash_output_to_string(o12_1));

        printf("\n*** port 2 (~ port 1)\n\n");
        printf("%s\n", R3S_packet_to_string(p12_2));
        printf("%s\n", R3S_key_hash_output_to_string(o12_2));

        if (o12_1 != o12_2)
        {
            printf("Failed! %u != %u. Exiting.\n", o12_1, o12_2);
            return 0;
        }
    }

    return 1;
}

int main () {
    R3S_status_t    status;
    R3S_cfg_t       cfg;
    R3S_key_t       keys[2];

    R3S_cfg_init(&cfg);
    R3S_cfg_set_number_of_keys(cfg, 2);
    
    R3S_cfg_load_opt(cfg, R3S_OPT_NON_FRAG_IPV4_TCP);

    status = R3S_keys_fit_cnstrs(cfg, &mk_p_cnstrs, keys);

    validate(cfg, keys[0], keys[1]);
    
    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("%s\n", R3S_status_to_string(status));

    if (status == R3S_STATUS_SUCCESS)
    {
        printf("k1:\n%s\n", R3S_key_to_string(keys[0]));
        printf("k2:\n%s\n", R3S_key_to_string(keys[1]));
    }

    R3S_cfg_delete(cfg);
}
