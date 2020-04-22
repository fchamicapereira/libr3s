#include "../include/r3s.h"

Z3_ast R3S_mk_symmetric_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    R3S_status_t status;
    Z3_ast       p1_ipv4_src, p1_ipv4_dst;
    Z3_ast       p2_ipv4_src, p2_ipv4_dst;
    Z3_ast       and_args[2];

    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p1, R3S_PF_IPV4_SRC, &p1_ipv4_src);
    if (status != R3S_STATUS_SUCCESS) return NULL;

    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p1, R3S_PF_IPV4_DST, &p1_ipv4_dst);
    if (status != R3S_STATUS_SUCCESS) return NULL;

    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p2, R3S_PF_IPV4_SRC, &p2_ipv4_src);
    if (status != R3S_STATUS_SUCCESS) return NULL;
    
    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p2, R3S_PF_IPV4_DST, &p2_ipv4_dst);
    if (status != R3S_STATUS_SUCCESS) return NULL;

    and_args[0] = Z3_mk_eq(ctx, p1_ipv4_src, p2_ipv4_dst);
    and_args[1] = Z3_mk_eq(ctx, p1_ipv4_dst, p2_ipv4_src);

    return Z3_mk_and(ctx, 2, and_args);
}

/**
 * @example
 */
Z3_ast R3S_mk_symmetric_tcp_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    R3S_status_t status;
    Z3_ast         p1_tcp_src, p1_tcp_dst;
    Z3_ast         p2_tcp_src, p2_tcp_dst;
    Z3_ast         and_args[2];

    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p1, R3S_PF_TCP_SRC, &p1_tcp_src);
    if (status != R3S_STATUS_SUCCESS) return NULL;

    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p1, R3S_PF_TCP_DST, &p1_tcp_dst);
    if (status != R3S_STATUS_SUCCESS) return NULL;

    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p2, R3S_PF_TCP_SRC, &p2_tcp_src);
    if (status != R3S_STATUS_SUCCESS) return NULL;
    
    status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p2, R3S_PF_TCP_DST, &p2_tcp_dst);
    if (status != R3S_STATUS_SUCCESS) return NULL;

    and_args[0] = Z3_mk_eq(ctx, p1_tcp_src, p2_tcp_dst);
    and_args[1] = Z3_mk_eq(ctx, p1_tcp_dst, p2_tcp_src);

    return Z3_mk_and(ctx, 2, and_args);
}

/**
 * @example
 */
Z3_ast R3S_mk_symmetric_tcp_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
{
    Z3_ast symmetric_ip;
    Z3_ast symmetric_tcp;
    Z3_ast and_args[2];

    symmetric_ip  = R3S_mk_symmetric_ip_cnstr(r3s_cfg, iopt, ctx, p1, p2);
    if (symmetric_ip == NULL)  return NULL;

    symmetric_tcp = R3S_mk_symmetric_tcp_cnstr(r3s_cfg, iopt, ctx, p1, p2);
    if (symmetric_tcp == NULL) return NULL;

    and_args[0] = symmetric_ip;
    and_args[1] = symmetric_tcp;

    return Z3_mk_and(ctx, 2, and_args);
}
