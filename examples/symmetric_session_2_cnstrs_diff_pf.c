#include <r3s.h>

int validate(R3S_cfg_t cfg, R3S_key_t k1, R3S_key_t k2)
{
    R3S_packet_t p1_1, p1_2, p12_1, p12_2;
    R3S_out_t    o1_1, o1_2, o12_1, o12_2;

    for (int i = 0; i < 25; i++)
    {
        R3S_rand_packet(cfg, &p1_1);
        R3S_rand_packet(cfg, &p12_1);
        
        R3S_packet_from_cnstrs(cfg, p1_1, &R3S_mk_symmetric_tcp_ip_cnstr, &p1_2);
        R3S_packet_from_cnstrs(cfg, p12_1, &R3S_mk_symmetric_ip_cnstr, &p12_2);

        R3S_hash(cfg, k1, p1_1, &o1_1);
        R3S_hash(cfg, k2, p1_2, &o1_2);
        R3S_hash(cfg, k1, p12_1, &o12_1);
        R3S_hash(cfg, k2, p12_2, &o12_2);

        printf("\n===== iteration %d =====\n", i);

        printf("\n*** port 1 \n\n");
        printf("%s\n", R3S_packet_to_string(p1_1));
        printf("%s\n", R3S_hash_output_to_string(o1_1));

        printf("%s\n", R3S_packet_to_string(p1_2));
        printf("%s\n", R3S_hash_output_to_string(o1_2));;

        if (o1_1 != o1_2)
        {
            printf("Failed! %u != %u. Exiting.\n", o1_1, o1_2);
            return 0;
        }

        printf("\n*** port 1 (~ port 2)\n\n");
        printf("%s\n", R3S_packet_to_string(p12_1));
        printf("%s\n", R3S_hash_output_to_string(o12_1));

        printf("\n*** port 2 (~ port 1)\n\n");
        printf("%s\n", R3S_packet_to_string(p12_2));
        printf("%s\n", R3S_hash_output_to_string(o12_2));

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
    R3S_cnstrs_func cnstrs[3];

    R3S_cfg_init(&cfg);
    cfg.n_keys = 2;
    
    R3S_cfg_load_in_opt(&cfg, R3S_IN_OPT_NON_FRAG_IPV4_TCP);

    cnstrs[0] = &R3S_mk_symmetric_tcp_ip_cnstr;
    cnstrs[1] = NULL;
    cnstrs[2] = &R3S_mk_symmetric_ip_cnstr;
    status    = R3S_find_keys(cfg, cnstrs, keys);

    validate(cfg, keys[0], keys[1]);
    
    printf("%s\n", R3S_cfg_to_string(cfg));
    printf("%s\n", R3S_status_to_string(status));

    if (status == R3S_STATUS_SUCCESS)
    {
        printf("k1:\n%s\n", R3S_key_to_string(keys[0]));
        printf("k2:\n%s\n", R3S_key_to_string(keys[1]));
    }

    R3S_cfg_delete(&cfg);
}