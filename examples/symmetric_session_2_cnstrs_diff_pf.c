#include <rssks.h>

Z3_ast k1_k2_cnstrs(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    RSSKS_status_t status;
    Z3_ast         p1_ipv4_src, p1_ipv4_dst;
    Z3_ast         p2_ipv4_src, p2_ipv4_dst;
    Z3_ast         and_args[2];

    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p1, RSSKS_PF_IPV4_SRC, &p1_ipv4_src);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;

    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p1, RSSKS_PF_IPV4_DST, &p1_ipv4_dst);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;

    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p2, RSSKS_PF_IPV4_SRC, &p2_ipv4_src);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;

    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p2, RSSKS_PF_IPV4_DST, &p2_ipv4_dst);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;


    and_args[0] = Z3_mk_eq(ctx, p1_ipv4_src, p2_ipv4_dst);
    and_args[1] = Z3_mk_eq(ctx, p1_ipv4_dst, p2_ipv4_src);

    return Z3_mk_and(ctx, 2, and_args);
}

Z3_ast k1_cnstrs(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    RSSKS_status_t status;
    Z3_ast         p1_ipv4_src, p1_ipv4_dst, p1_tcp_src, p1_tcp_dst;
    Z3_ast         p2_ipv4_src, p2_ipv4_dst, p2_tcp_src, p2_tcp_dst;
    Z3_ast         and_args[4];

    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p1, RSSKS_PF_IPV4_SRC, &p1_ipv4_src);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p1, RSSKS_PF_IPV4_DST, &p1_ipv4_dst);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p1, RSSKS_PF_TCP_SRC, &p1_tcp_src);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p1, RSSKS_PF_TCP_DST, &p1_tcp_dst);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p2, RSSKS_PF_IPV4_SRC, &p2_ipv4_src);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p2, RSSKS_PF_IPV4_DST, &p2_ipv4_dst);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p2, RSSKS_PF_TCP_SRC, &p2_tcp_src);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    status = RSSKS_extract_pf_from_p(rssks_cfg, iopt, ctx, p2, RSSKS_PF_TCP_DST, &p2_tcp_dst);
    if (status != RSSKS_STATUS_SUCCESS) return NULL;
    
    and_args[0] = Z3_mk_eq(ctx, p1_ipv4_src, p2_ipv4_dst);
    and_args[1] = Z3_mk_eq(ctx, p1_ipv4_dst, p2_ipv4_src);
    and_args[2] = Z3_mk_eq(ctx, p1_tcp_src, p2_tcp_dst);
    and_args[3] = Z3_mk_eq(ctx, p1_tcp_dst, p2_tcp_src);

    return Z3_mk_and(ctx, 4, and_args);
}

int validate(RSSKS_cfg_t cfg, RSSKS_key_t k1, RSSKS_key_t k2)
{
    RSSKS_packet_t p1_1, p1_2, p12_1, p12_2;
    RSSKS_out_t    o1_1, o1_2, o12_1, o12_2;

    for (int i = 0; i < 25; i++)
    {
        RSSKS_rand_packet(cfg, &p1_1);
        RSSKS_rand_packet(cfg, &p12_1);
        
        RSSKS_packet_from_cnstrs(cfg, p1_1, &k1_cnstrs, &p1_2);
        RSSKS_packet_from_cnstrs(cfg, p12_1, &k1_cnstrs, &p12_2);

        RSSKS_hash(cfg, k1, p1_1, &o1_1);
        RSSKS_hash(cfg, k2, p1_2, &o1_2);
        RSSKS_hash(cfg, k1, p12_1, &o12_1);
        RSSKS_hash(cfg, k2, p12_2, &o12_2);

        printf("\n===== iteration %d =====\n", i);

        printf("\n*** port 1 \n\n");
        printf("%s\n", RSSKS_packet_to_string(p1_1));
        printf("%s\n", RSSKS_hash_output_to_string(o1_1));

        printf("%s\n", RSSKS_packet_to_string(p1_2));
        printf("%s\n", RSSKS_hash_output_to_string(o1_2));;

        if (o1_1 != o1_2)
        {
            printf("Failed! %u != %u. Exiting.\n", o1_1, o1_2);
            return 0;
        }

        printf("\n*** port 1 (~ port 2)\n\n");
        printf("%s\n", RSSKS_packet_to_string(p12_1));
        printf("%s\n", RSSKS_hash_output_to_string(o12_1));

        printf("\n*** port 2 (~ port 1)\n\n");
        printf("%s\n", RSSKS_packet_to_string(p12_2));
        printf("%s\n", RSSKS_hash_output_to_string(o12_2));

        if (o12_1 != o12_2)
        {
            printf("Failed! %u != %u. Exiting.\n", o12_1, o12_2);
            return 0;
        }
    }

    return 1;
}

int main () {
    RSSKS_status_t    status;
    RSSKS_cfg_t       cfg;
    RSSKS_key_t       keys[2];
    RSSKS_cnstrs_func cnstrs[3];

    RSSKS_cfg_init(&cfg);
    cfg.n_keys = 2;
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4_TCP);

    cnstrs[0] = &k1_cnstrs;
    cnstrs[1] = NULL;
    cnstrs[2] = &k1_k2_cnstrs;
    status    = RSSKS_find_keys(cfg, cnstrs, keys);

    validate(cfg, keys[0], keys[1]);
    
    printf("%s\n", RSSKS_cfg_to_string(cfg));
    printf("%s\n", RSSKS_status_to_string(status));

    if (status == RSSKS_STATUS_SUCCESS)
    {
        printf("result:\n%s\n", RSSKS_key_to_string(keys[0]));
        printf("result:\n%s\n", RSSKS_key_to_string(keys[1]));
    }

    RSSKS_cfg_delete(&cfg);
}