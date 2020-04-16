#include <rssks.h>

Z3_ast p_cnstrs(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    return iopt == 0
        ? RSSKS_mk_symmetric_ip_cnstr(rssks_cfg, iopt, ctx, p1, p2)
        : RSSKS_mk_symmetric_tcp_ip_cnstr(rssks_cfg, iopt, ctx, p1, p2);
}

int validate(RSSKS_cfg_t cfg, RSSKS_key_t k)
{
    RSSKS_packet_t p1, p2;
    RSSKS_out_t    o1, o2;

    for (int i = 0; i < 25; i++)
    {
        RSSKS_rand_packet(cfg, &p1);
        RSSKS_packet_from_cnstrs(cfg, p1, &p_cnstrs, &p2);

        RSSKS_hash(cfg, k, p1, &o1);
        RSSKS_hash(cfg, k, p2, &o2);

        printf("\n===== iteration %d =====\n", i);

        printf("%s\n", RSSKS_packet_to_string(p1));
        printf("%s\n", RSSKS_hash_output_to_string(o1));

        printf("%s\n", RSSKS_packet_to_string(p1));
        printf("%s\n", RSSKS_hash_output_to_string(o2));;

        if (o1 != o2)
        {
            printf("Failed! %u != %u. Exiting.\n", o1, o2);
            return 0;
        }
    }

    return 1;
}

int main () {
    RSSKS_cfg_t       cfg;
    RSSKS_key_t       k;
    RSSKS_cnstrs_func cnstrs[1];
    RSSKS_status_t    status;

    RSSKS_cfg_init(&cfg);
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4_TCP);

    cnstrs[0] = &p_cnstrs;
    status    = RSSKS_find_keys(cfg, cnstrs, &k);

    validate(cfg, k);
    
    printf("%s\n", RSSKS_cfg_to_string(cfg));
    printf("%s\n", RSSKS_status_to_string(status));

    if (status == RSSKS_STATUS_SUCCESS)
        printf("result:\n%s\n", RSSKS_key_to_string(k));

    RSSKS_cfg_delete(&cfg);
}