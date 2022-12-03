#include <r3s.h>

Z3_ast mk_p_cnstrs(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2) {

    // LAN => WAN
    if (p1.key_id == 0 && p2.key_id == 1)
        return NULL;

    // constraints for LAN and WAN devices exclusively,
    // constraints WAN => LAN
    Z3_ast p1_l3_src, p1_l3_dst;
    Z3_ast p2_l3_src, p2_l3_dst;

    Z3_ast p1_l4_src, p1_l4_dst;
    Z3_ast p2_l4_src, p2_l4_dst;

    R3S_packet_extract_pf(cfg, p1, R3S_PF_IPV4_SRC, &p1_l3_src);
    R3S_packet_extract_pf(cfg, p1, R3S_PF_IPV4_DST, &p1_l3_dst);

    R3S_packet_extract_pf(cfg, p2, R3S_PF_IPV4_SRC, &p2_l3_src);
    R3S_packet_extract_pf(cfg, p2, R3S_PF_IPV4_DST, &p2_l3_dst);

    if (p1.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4_TCP) {
        R3S_packet_extract_pf(cfg, p1, R3S_PF_TCP_SRC, &p1_l4_src);
        R3S_packet_extract_pf(cfg, p1, R3S_PF_TCP_DST, &p1_l4_dst);
    }

    else if (p1.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4_UDP) {
        R3S_packet_extract_pf(cfg, p1, R3S_PF_UDP_SRC, &p1_l4_src);
        R3S_packet_extract_pf(cfg, p1, R3S_PF_UDP_DST, &p1_l4_dst);
    }

    else {
        return NULL;
    }

    if (p2.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4_TCP) {
        R3S_packet_extract_pf(cfg, p2, R3S_PF_TCP_SRC, &p2_l4_src);
        R3S_packet_extract_pf(cfg, p2, R3S_PF_TCP_DST, &p2_l4_dst);
    }

    else if (p2.loaded_opt.opt == R3S_OPT_NON_FRAG_IPV4_UDP) {
        R3S_packet_extract_pf(cfg, p2, R3S_PF_UDP_SRC, &p2_l4_src);
        R3S_packet_extract_pf(cfg, p2, R3S_PF_UDP_DST, &p2_l4_dst);
    }

    else {
        return NULL;
    }

    Z3_ast final;

    if (p1.key_id == p2.key_id) {
        Z3_ast _and_args[4] = {
            Z3_mk_eq(cfg->ctx, p1_l3_src, p2_l3_src),
            Z3_mk_eq(cfg->ctx, p1_l3_dst, p2_l3_dst),
            Z3_mk_eq(cfg->ctx, p1_l4_src, p2_l4_src),
            Z3_mk_eq(cfg->ctx, p1_l4_dst, p2_l4_dst)
        };

        final = Z3_simplify(cfg->ctx, Z3_mk_and(cfg->ctx, 4, _and_args));
    }

    else {
        Z3_ast symmetric[4] = {
            Z3_mk_eq(cfg->ctx, p1_l3_src, p2_l3_dst),
            Z3_mk_eq(cfg->ctx, p1_l3_dst, p2_l3_src),
            Z3_mk_eq(cfg->ctx, p1_l4_src, p2_l4_dst),
            Z3_mk_eq(cfg->ctx, p1_l4_dst, p2_l4_src)
        };

        final = Z3_simplify(cfg->ctx, Z3_mk_and(cfg->ctx, 4, symmetric));
    }

    return final;
}

int validate(R3S_cfg_t cfg, R3S_key_t k1, R3S_key_t k2)
{
    R3S_packet_t p1_1, p1_2, p12_1, p12_2;
    R3S_key_hash_out_t o1_1, o1_2, o12_1, o12_2;
    R3S_packet_from_cnstrs_data_t data;

    for (int i = 0; i < 5; i++)
    {
        R3S_packet_rand(cfg, &p1_1);

        data.constraints = &mk_p_cnstrs;
        data.packet_in   = p1_1;
        data.key_id_in   = 0;
        data.key_id_out  = 0;

        R3S_packet_from_cnstrs(cfg, data, &p1_2);

        R3S_key_hash(cfg, k1, p1_1, &o1_1);
        R3S_key_hash(cfg, k1, p1_2, &o1_2);

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

        R3S_packet_rand(cfg, &p12_1);

        data.constraints = &mk_p_cnstrs;
        data.packet_in   = p12_1;
        data.key_id_in   = 1;
        data.key_id_out  = 0;

        R3S_packet_from_cnstrs(cfg, data, &p12_2);

        R3S_key_hash(cfg, k1, p12_1, &o12_1);
        R3S_key_hash(cfg, k2, p12_2, &o12_2);

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

int main() {
    R3S_cfg_t cfg;
    R3S_key_t keys[2];
    R3S_opt_t* opts;
    size_t opts_sz;
    R3S_status_t status;

    R3S_pf_t pfs[6] = {
        R3S_PF_IPV4_SRC,
        R3S_PF_IPV4_DST,
        R3S_PF_TCP_SRC,
        R3S_PF_TCP_DST,
        R3S_PF_UDP_SRC,
        R3S_PF_UDP_DST,
    };

    R3S_cfg_init(&cfg);
    R3S_cfg_set_number_of_keys(cfg, 2);
    R3S_cfg_set_skew_analysis(cfg, true);
    R3S_opts_from_pfs(pfs, 6, &opts, &opts_sz);

    for (size_t i = 0; i < opts_sz; i++)
        R3S_cfg_load_opt(cfg, opts[i]);

    printf("\nConfiguration:\n%s\n", R3S_cfg_to_string(cfg));

    status = R3S_keys_fit_cnstrs(cfg, &mk_p_cnstrs, keys);

    if (status != R3S_STATUS_SUCCESS) {
        printf("Status: %s\n", R3S_status_to_string(status));
        return 1;
    }

    printf("key 1:\n%s\n", R3S_key_to_string(keys[0]));
    printf("key 2:\n%s\n", R3S_key_to_string(keys[1]));

    validate(cfg, keys[0], keys[1]);

    R3S_cfg_delete(cfg);
}
