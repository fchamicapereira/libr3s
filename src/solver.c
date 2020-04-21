#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <sys/select.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <assert.h>

#include "solver.h"
#include "util.h"
#include "hash.h"
#include "printer.h"
#include "packet.h"
#include "config.h"

void exitf(const char *message)
{
    fprintf(stderr, "BUG: %s.\n", message);
    exit(0);
}

void error_handler(Z3_context c, Z3_error_code e)
{
    printf("Error code: %d\n", e);
    exitf("incorrect use of Z3");
}

Z3_context mk_context_custom(Z3_config cfg, Z3_error_handler err)
{
    Z3_context ctx;

    Z3_set_param_value(cfg, "model", "true");

    #if DEBUG
        Z3_set_param_value(cfg, "unsat_core", "true");
    #endif

    ctx = Z3_mk_context(cfg);

    Z3_set_error_handler(ctx, err);

    return ctx;
}

Z3_context mk_context()
{
    Z3_config  cfg;
    Z3_context ctx;

    cfg = Z3_mk_config();
    Z3_set_param_value(cfg, "MODEL", "true");

    ctx = mk_context_custom(cfg, error_handler);
    Z3_del_config(cfg);
    return ctx;
}

Z3_solver mk_solver(Z3_context ctx)
{
    Z3_solver s = Z3_mk_solver(ctx);
    Z3_solver_inc_ref(ctx, s);
    return s;
}

void del_solver(Z3_context ctx, Z3_solver s)
{
    Z3_solver_dec_ref(ctx, s);
}

Z3_ast mk_var(Z3_context ctx, const char *name, Z3_sort ty)
{
    Z3_symbol s = Z3_mk_string_symbol(ctx, name);
    return Z3_mk_const(ctx, s, ty);
}

void p_ast_to_hash_input(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p, R3S_in_t hi)
{
    /*
     *  I know what you're thinking. Getting the value of a bit vector
     *  by converting its string representation? Better call a priest
     *  and exorcise this code.
     *  Unfortunately, this was the only way that actually worked.
     *  I still feel that this is wrong, and I need a shower.
     */

    Z3_string    p_string;
    char         *divisor, *res;
    size_t       p_string_sz;
    unsigned     p_sz;

    int          digit1, digit2;

    p_sz        = r3s_cfg.loaded_opts[iopt].sz;
    p_string    = Z3_get_numeral_string(ctx, p);
    p_string_sz = strlen(p_string);
    divisor     = (char*) malloc(sizeof(char) * p_string_sz + 1);
    res         = (char*) malloc(sizeof(char) * p_string_sz + 1);
    
    sprintf(divisor, "%s", p_string);

    for (unsigned byte_idx = 0; byte_idx < p_sz / 8; byte_idx++)
    {
        digit1 = digit2 = 0;

        digit2 = str_long_int_div(divisor, 16, res);
        sprintf(divisor, "%s", res);

        digit1 = str_long_int_div(divisor, 16, res);
        sprintf(divisor, "%s", res);

        hi[p_sz / 8 - 1 - byte_idx] = digit1 * 16 + digit2;
    }

    free(divisor);
    free(res);
}

void k_ast_to_rss_key(Z3_context ctx, Z3_ast k, R3S_key_t rssk)
{
    /*
     *  I know what you're thinking. Getting the value of a bit vector
     *  by converting its string representation? Better call a priest
     *  and exorcise this code.
     *  Unfortunately, this was the only way that actually worked.
     *  I still feel that this is wrong, and I need a shower.
     */

    Z3_string    k_string;
    char         *divisor, *res;
    size_t       k_string_sz;

    int          digit1, digit2;

    k_string    = Z3_get_numeral_string(ctx, k);
    k_string_sz = strlen(k_string);
    divisor     = (char*) malloc(sizeof(char) * k_string_sz + 1);
    res         = (char*) malloc(sizeof(char) * k_string_sz + 1);
    
    sprintf(divisor, "%s", k_string);

    for (unsigned byte_idx = 0; byte_idx < KEY_SIZE; byte_idx++)
    {
        digit2 = str_long_int_div(divisor, 16, res);
        sprintf(divisor, "%s", res);

        digit1 = str_long_int_div(divisor, 16, res);
        sprintf(divisor, "%s", res);

        rssk[KEY_SIZE - 1 - byte_idx] = digit1 * 16 + digit2;
    }

    free(divisor);
    free(res);
}

Z3_ast mk_bvxor(Z3_context ctx, Z3_ast bv, unsigned sz)
{
    Z3_ast *el;
    Z3_ast *xored;
    Z3_ast result;

    el       = (Z3_ast *)malloc(sizeof(Z3_ast) * sz);
    xored    = (Z3_ast *)malloc(sizeof(Z3_ast) * sz);

    el[0]    = Z3_mk_extract(ctx, 0, 0, bv);
    xored[0] = el[0];

    for (unsigned idx = 1; idx < sz; idx++)
    {
        el[idx]    = Z3_mk_extract(ctx, idx, idx, bv);
        xored[idx] = Z3_mk_bvxor(ctx, el[idx], xored[idx - 1]);
    }

    result = xored[sz - 1];

    free(el);
    free(xored);

    return result;
}

Z3_ast mk_hash_func(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p, Z3_ast key, Z3_ast o)
{
    Z3_ast k;
    Z3_ast p_and_k;
    Z3_ast o_bit;
    Z3_ast p_and_k_xor;
    Z3_ast args[HASH_OUTPUT_SIZE_BITS];
    
    unsigned k_high, k_low;
    unsigned o_high, o_low;
    unsigned sz;

    sz = r3s_cfg.loaded_opts[iopt].sz;

    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k_high           = (KEY_SIZE_BITS - 1) - bit;
        k_low            = (KEY_SIZE_BITS - 1) - (bit + sz - 1);
        k                = Z3_mk_extract(ctx, k_high, k_low, key);

        p_and_k          = Z3_mk_bvand(ctx, k, p);
        p_and_k_xor      = mk_bvxor(ctx, p_and_k, sz);

        o_high           = HASH_OUTPUT_SIZE_BITS - bit - 1;
        o_low            = HASH_OUTPUT_SIZE_BITS - bit - 1;
        o_bit            = Z3_mk_extract(ctx, o_high, o_low, o);

        args[bit]        = Z3_mk_eq(ctx, p_and_k_xor, o_bit);
    }

    return Z3_mk_and(ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast mk_hash_eq(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast key, Z3_ast p1, Z3_ast p2)
{
    Z3_ast k;
    Z3_ast p1_and_k;
    Z3_ast p2_and_k;
    Z3_ast p1_and_k_xor;
    Z3_ast p2_and_k_xor;

    Z3_ast args[HASH_OUTPUT_SIZE_BITS];

    unsigned k_high, k_low;
    unsigned sz;

    sz = r3s_cfg.loaded_opts[iopt].sz;

    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k_high       = (KEY_SIZE_BITS - 1) - bit;
        k_low        = (KEY_SIZE_BITS - 1) - (bit + sz - 1);
        k            = Z3_mk_extract(ctx, k_high, k_low, key);

        p1_and_k     = Z3_mk_bvand(ctx, k, p1);
        p2_and_k     = Z3_mk_bvand(ctx, k, p2);

        p1_and_k_xor = mk_bvxor(ctx, p1_and_k, sz);
        p2_and_k_xor = mk_bvxor(ctx, p2_and_k, sz);

        args[bit]    = Z3_mk_eq(ctx, p1_and_k_xor, p2_and_k_xor);
    }

    return Z3_mk_and(ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast mk_hash_eq_two_keys(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast key1, Z3_ast p1, Z3_ast key2, Z3_ast p2)
{
    Z3_ast k1;
    Z3_ast k2;
    Z3_ast p1_and_k1;
    Z3_ast p2_and_k2;
    Z3_ast p1_and_k1_xor;
    Z3_ast p2_and_k2_xor;

    Z3_ast args[HASH_OUTPUT_SIZE_BITS];

    unsigned k1_high, k1_low;
    unsigned k2_high, k2_low;
    unsigned sz;

    sz = r3s_cfg.loaded_opts[iopt].sz;

    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k1_high       = (KEY_SIZE_BITS - 1) - bit;
        k1_low        = (KEY_SIZE_BITS - 1) - (bit + sz - 1);
        k1            = Z3_mk_extract(ctx, k1_high, k1_low, key1);

        k2_high       = (KEY_SIZE_BITS - 1) - bit;
        k2_low        = (KEY_SIZE_BITS - 1) - (bit + sz - 1);
        k2            = Z3_mk_extract(ctx, k2_high, k2_low, key2);

        p1_and_k1     = Z3_mk_bvand(ctx, k1, p1);
        p2_and_k2     = Z3_mk_bvand(ctx, k2, p2);

        p1_and_k1_xor = mk_bvxor(ctx, p1_and_k1, sz);
        p2_and_k2_xor = mk_bvxor(ctx, p2_and_k2, sz);

        args[bit]     = Z3_mk_eq(ctx, p1_and_k1_xor, p2_and_k2_xor);
    }

    return Z3_mk_and(ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast mk_d_const(R3S_cfg_t r3s_cfg, Z3_context ctx, Z3_ast input, R3S_packet_t p)
{
    Z3_ast         *pf_x, *pf_const;
    Z3_sort        byte_sort;
    Z3_ast         *and_args;
    Z3_ast         d_const;

    R3S_byte_t   *field;
    R3S_pf_t     pf;

    R3S_status_t status;
    unsigned       ipot;

    unsigned       offset, sz;
    unsigned       input_sz;
    unsigned       high, low;

    status = R3S_packet_to_in_opt(r3s_cfg, p, &ipot);

    if (status != R3S_STATUS_SUCCESS) assert(false);

    input_sz   = r3s_cfg.loaded_opts[ipot].sz / 8;

    pf_x       = (Z3_ast*) malloc(sizeof(Z3_ast) * input_sz);
    pf_const   = (Z3_ast*) malloc(sizeof(Z3_ast) * input_sz);
    and_args   = (Z3_ast*) malloc(sizeof(Z3_ast) * input_sz);

    byte_sort  = Z3_mk_bv_sort(ctx, 8);

    offset     = 0;
    sz         = 0;

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {
        pf = (R3S_pf_t) ipf;

        if (R3S_cfg_check_pf(r3s_cfg, ipot, pf) != R3S_STATUS_PF_LOADED)
            continue;

        field = R3S_packet_get_field(&p, pf);
        sz    = R3S_pf_sz(pf);

        for (unsigned byte = 0; byte < sz; byte++, field++)
        {
            high = (input_sz - (offset + byte)) * 8 - 1;
            low  = high - 7;

            pf_const[offset + byte] = Z3_mk_int(ctx, *field, byte_sort);
            pf_x[offset + byte]     = Z3_mk_extract(ctx, high, low, input);
            and_args[offset + byte] = Z3_mk_eq(ctx, pf_const[offset + byte], pf_x[offset + byte]);
        }
        
        offset += sz;
    }

    d_const = Z3_mk_and(ctx, input_sz, and_args);

    free(pf_x);
    free(pf_const);
    free(and_args);

    return d_const;
}

R3S_status_t R3S_extract_pf_from_p(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p, R3S_pf_t pf, out Z3_ast *output)
{
    R3S_pf_t     current_pf;
    R3S_status_t status;
    
    unsigned offset;
    unsigned input_sz, sz;
    unsigned high, low;
    
    input_sz = r3s_cfg.loaded_opts[iopt].sz;
    offset   = 0;
    sz       = 0;

    if (input_sz != Z3_get_bv_sort_size(ctx, Z3_get_sort(ctx, p)))
    {
        DEBUG_PLOG("[R3S_extract_pf_from_p] ERROR: input_sz (%u) != p_sz (%u)\n",
            input_sz, Z3_get_bv_sort_size(ctx, Z3_get_sort(ctx, p)));
        return R3S_STATUS_PF_NOT_LOADED;
    }

    status   = R3S_cfg_check_pf(r3s_cfg, iopt, pf);

    if (status != R3S_STATUS_PF_LOADED)
    {
        DEBUG_PLOG("[R3S_extract_pf_from_p] ERROR: %u\n", status);
        return status;
    }

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {
        current_pf = (R3S_pf_t) ipf;
        status     = R3S_cfg_check_pf(r3s_cfg, iopt, current_pf);

        if (status == R3S_STATUS_PF_UNKNOWN) return status;
        if (status != R3S_STATUS_PF_LOADED)  continue;

        sz = R3S_pf_sz_bits(current_pf);

        if (current_pf == pf)
        {
            high    = input_sz - 1 - offset;
            low     = high - sz + 1;
            *output = Z3_mk_extract(ctx, high, low, p);

            return R3S_STATUS_SUCCESS;
        }
        
        offset += sz;
    }

    return R3S_STATUS_PF_NOT_LOADED;
}

Z3_ast mk_key_byte_const(Z3_context ctx, Z3_ast key, unsigned byte, R3S_byte_t value)
{
    Z3_ast  value_const;
    Z3_ast  key_slice;
    Z3_sort byte_sort;

    byte_sort = Z3_mk_bv_sort(ctx, 8);

    value_const = Z3_mk_int(ctx, (int) value, byte_sort);
    key_slice   = Z3_mk_extract(ctx, byte * 8 + 7, byte * 8, key);

    return Z3_mk_eq(ctx, key_slice, value_const);
}

Z3_ast mk_key_const(Z3_context ctx, Z3_ast key, R3S_key_t k)
{
    Z3_ast  and_args[KEY_SIZE];

    for (int b = 0; b < KEY_SIZE; b++)
        and_args[b] = mk_key_byte_const(ctx, key, b, k[KEY_SIZE - b - 1]);

    return Z3_mk_and(ctx, KEY_SIZE, and_args);
}

R3S_status_t R3S_packet_from_cnstrs(R3S_cfg_t r3s_cfg, R3S_packet_t p_in, R3S_cnstrs_func mk_p_cnstrs, out R3S_packet_t *p_out)
{
    Z3_context     ctx;
    Z3_solver      s;
    Z3_lbool       result;
    Z3_model       m;

    Z3_symbol      p2_symbol;
    Z3_func_decl   p2_decl;

    Z3_sort        p_sort;
    Z3_ast         p1, p2, p2_model;
    
    Z3_ast         p_const;
    Z3_ast         stmt;

    R3S_in_t     hi2;

    R3S_status_t status;
    unsigned       iopt;

    status    = R3S_packet_to_in_opt(r3s_cfg, p_in, &iopt);

    if (status != R3S_STATUS_SUCCESS) return status;

    ctx       = mk_context();
    s         = mk_solver(ctx);
    
    p_sort    = Z3_mk_bv_sort(ctx, r3s_cfg.loaded_opts[iopt].sz);

    p1        = mk_var(ctx, "p1", p_sort);

    p2_symbol = Z3_mk_string_symbol(ctx, "p2"); 
    p2_decl   = Z3_mk_func_decl(ctx, p2_symbol, 0, 0, p_sort);
    p2        = Z3_mk_app(ctx, p2_decl, 0, 0);

    p_const   = mk_d_const(r3s_cfg, ctx, p1, p_in);
    stmt      = mk_p_cnstrs(r3s_cfg, iopt, ctx, p1, p2);

    Z3_solver_assert(ctx, s, p_const);
    Z3_solver_assert(ctx, s, stmt);

    result    = Z3_solver_check(ctx, s);

    switch (result)
    {
        case Z3_L_FALSE:
        case Z3_L_UNDEF: return R3S_STATUS_NO_SOLUTION;
        case Z3_L_TRUE:
            m = Z3_solver_get_model(ctx, s);
            
            if (!m)
            {
                del_solver(ctx, s);
                return R3S_STATUS_FAILURE;
            }
    }

    Z3_model_inc_ref(ctx, m);

    p2_model = Z3_model_get_const_interp(ctx, m, p2_decl);
    hi2      = (R3S_in_t) malloc(sizeof(R3S_byte_t) * r3s_cfg.loaded_opts[iopt].sz);

    p_ast_to_hash_input(r3s_cfg, iopt, ctx, p2_model, hi2);

    *p_out   = R3S_in_to_packet(r3s_cfg, iopt, hi2, p_in.cfg);
    
    free(hi2);
    Z3_model_dec_ref(ctx, m);
    del_solver(ctx, s);

    return R3S_STATUS_SUCCESS;
}

Z3_ast mk_key_bit_const(Z3_context ctx, Z3_ast key, unsigned bit, unsigned value)
{
    Z3_ast  key_slice;
    Z3_ast  key_const;
    Z3_sort bit_sort;

    bit_sort = Z3_mk_bv_sort(ctx, 1);

    key_const = Z3_mk_int(ctx, value, bit_sort);
    key_slice = Z3_mk_extract(ctx, bit, bit, key);

    return Z3_mk_eq(ctx, key_slice, key_const);
}

/*
 * Create a d sort.
 * //TODO: documentation missing
 */
Z3_sort mk_d_sort(R3S_cfg_t r3s_cfg, Z3_context ctx)
{
    unsigned max_sz;
    Z3_sort  d_sort;

    max_sz     = R3S_cfg_max_in_sz(r3s_cfg);
    d_sort     = Z3_mk_bv_sort(ctx, max_sz);

    return d_sort;
}

Z3_ast* mk_p(R3S_cfg_t r3s_cfg, Z3_context ctx, Z3_ast d)
{
    Z3_ast   *p;
    Z3_sort  d_sort;
    unsigned n_loaded_opts;
    unsigned input_sz;
    unsigned high, low;
    unsigned d_sort_sz;

    d_sort        = Z3_get_sort(ctx, d);
    d_sort_sz     = Z3_get_bv_sort_size(ctx, d_sort);
    
    n_loaded_opts = r3s_cfg.n_loaded_opts;
    p             = (Z3_ast*) malloc(sizeof(Z3_ast) * n_loaded_opts);
    
    for (unsigned iopt = 0; iopt < n_loaded_opts; iopt++)
    {
        input_sz    = r3s_cfg.loaded_opts[iopt].sz;
        
        assert(input_sz > 0); // TODO: improve this

        high        = d_sort_sz - 1;
        low         = high - input_sz + 1;

        p[iopt]  = Z3_mk_extract(ctx, high, low, d);
    }

    return p;
}

Z3_ast mk_rss_stmt(R3S_cfg_t r3s_cfg, Z3_context ctx, R3S_cnstrs_func *mk_p_cnstrs, Z3_ast *keys)
{
    Z3_sort    d_sort;
    Z3_ast     d1;
    Z3_ast     d2;

    Z3_ast     *p1;
    Z3_ast     *p2;
    Z3_ast     p_cnstrs;

    Z3_ast     left_implies;
    Z3_ast     right_implies;
    Z3_ast     *implies;
    Z3_ast     and_implies;

    Z3_app     vars[2];
    Z3_ast     forall;

    unsigned   n_key_pairs;
    unsigned   n_cnstrs;
    unsigned   cnstr;
    unsigned   n_implies;
    unsigned   n_loaded_opts;

    d_sort         = mk_d_sort(r3s_cfg, ctx);
           
    d1             = mk_var(ctx, "d1", d_sort);
    d2             = mk_var(ctx, "d2", d_sort);

    p1             = mk_p(r3s_cfg, ctx, d1);
    p2             = mk_p(r3s_cfg, ctx, d2);

    n_loaded_opts  = r3s_cfg.n_loaded_opts;
    n_key_pairs    = combinations(r3s_cfg.n_keys, 2);
    n_cnstrs       = (r3s_cfg.n_keys + n_key_pairs) * n_loaded_opts;
    n_implies      = 0;

    implies        = (Z3_ast*) malloc(sizeof(Z3_ast) * n_cnstrs);

    for (cnstr = 0; cnstr < r3s_cfg.n_keys; cnstr++)
    {
        if (mk_p_cnstrs[cnstr] == NULL)
            continue;
        
        for (unsigned iopt = 0; iopt < n_loaded_opts; iopt++)
        {
            p_cnstrs = mk_p_cnstrs[cnstr](r3s_cfg, iopt, ctx, p1[iopt], p2[iopt]);

            if (p_cnstrs == NULL) continue;

            left_implies       = p_cnstrs;
            right_implies      = mk_hash_eq(r3s_cfg, iopt, ctx, keys[cnstr], p1[iopt], p2[iopt]);
            implies[n_implies] = Z3_mk_implies(ctx, left_implies, right_implies);
            
            n_implies++;
        }
    }

    // make combinations
    for (unsigned k1 = 0; k1 < r3s_cfg.n_keys; k1++)
    {
        for (unsigned k2 = k1 + 1; k2 < r3s_cfg.n_keys; k2++)
        {
            if (mk_p_cnstrs[cnstr] == NULL) { cnstr++; continue; }

            for (unsigned iopt = 0; iopt < n_loaded_opts; iopt++)
            {
                p_cnstrs = mk_p_cnstrs[cnstr](r3s_cfg, iopt, ctx, p1[iopt], p2[iopt]);

                if (p_cnstrs == NULL) continue;

                left_implies       = p_cnstrs;
                right_implies      = mk_hash_eq_two_keys(r3s_cfg, iopt, ctx, keys[k1], p1[iopt], keys[k2], p2[iopt]);
                implies[n_implies] = Z3_mk_implies(ctx, left_implies, right_implies);
                
                cnstr++;
                n_implies++;
            }
        }
    }

    and_implies = Z3_mk_and(ctx, n_implies, implies);

    vars[0]     = Z3_to_app(ctx, d1);
    vars[1]     = Z3_to_app(ctx, d2);
 
    forall      = Z3_mk_forall_const(ctx, 0, 2, vars, 0, 0, and_implies);

    free(implies);
    free(p1);
    free(p2);

    return forall;
}

Z3_ast mk_fresh_bool_var(Z3_context ctx) 
{
    return Z3_mk_fresh_const(ctx, "k", Z3_mk_bool_sort(ctx));
}

Z3_ast * mk_fresh_bool_var_array(Z3_context ctx, unsigned num_vars) 
{
    Z3_ast * result = (Z3_ast *) malloc(sizeof(Z3_ast) * num_vars);
    unsigned i;
    for (i = 0; i < num_vars; i++) {
        result[i] = mk_fresh_bool_var(ctx);
    }
    return result;
}

Z3_ast mk_binary_or(Z3_context ctx, Z3_ast in_1, Z3_ast in_2) 
{
    Z3_ast args[2] = { in_1, in_2 };
    return Z3_mk_or(ctx, 2, args);
}

Z3_ast * assert_soft_constraints(Z3_context ctx, Z3_solver s, unsigned num_cnstrs, Z3_ast * cnstrs) 
{
    unsigned i;
    Z3_ast * aux_vars;
    aux_vars = mk_fresh_bool_var_array(ctx, num_cnstrs);
    for (i = 0; i < num_cnstrs; i++) {
        Z3_ast assumption = cnstrs[i];
        Z3_solver_assert(ctx, s, mk_binary_or(ctx, assumption, aux_vars[i]));
    }
    return aux_vars;
}

void check_unsat_core(Z3_context ctx, Z3_solver s, unsigned num_soft_cnstrs, Z3_ast * soft_cnstrs, bool *core_cnstrs)
{
    Z3_ast * aux_vars = assert_soft_constraints(ctx, s, num_soft_cnstrs, soft_cnstrs);
    Z3_ast * assumptions = (Z3_ast*) malloc(sizeof(Z3_ast) * num_soft_cnstrs);
    
    for (unsigned i = 0; i < num_soft_cnstrs; i++)
        assumptions[i] = Z3_mk_not(ctx, aux_vars[i]);
    Z3_lbool is_sat = Z3_solver_check_assumptions(ctx, s, num_soft_cnstrs, assumptions);

    if (is_sat != Z3_L_FALSE) {
        free(assumptions);
        free(aux_vars);
        return;
    }

    Z3_ast_vector core = Z3_solver_get_unsat_core(ctx, s);
    Z3_ast_vector_inc_ref(ctx, core);

    unsigned core_size = Z3_ast_vector_size(ctx, core);

    if (core_size == 0) exit(1);

    bool found;
    for (unsigned i = 0; i < num_soft_cnstrs; i++) {
        found = false;
        for (unsigned j = 0; j < core_size; j++) {
            if (assumptions[i] == Z3_ast_vector_get(ctx, core, j)) {
                found = true;
                break;
            }
        }

        core_cnstrs[i] = found;
    }

    Z3_ast_vector_dec_ref(ctx, core);

    free(assumptions);
    free(aux_vars);
}

void pseudo_partial_maxsat(Z3_context ctx, Z3_solver s, Z3_ast *keys, R3S_key_t *keys_proposals)
{
    Z3_ast       key_constr[KEY_SIZE_BITS];

    bool         core[KEY_SIZE_BITS];
    unsigned     num_soft_cnstrs;
    unsigned     num_soft_cnstrs_new;
    unsigned     unsat_core_sz;

    for (int bit = 0; bit < KEY_SIZE_BITS; bit++)
        key_constr[bit] = mk_key_bit_const(ctx, keys[0], KEY_SIZE_BITS - 1 - bit, BIT_FROM_KEY(bit, keys_proposals[0]));

    for (unsigned i = 0; i < KEY_SIZE_BITS; i++) core[i] = false;

    num_soft_cnstrs = KEY_SIZE_BITS;
    for (;;) {
        check_unsat_core(ctx, s, num_soft_cnstrs, key_constr, core);

        unsat_core_sz = 0;
        num_soft_cnstrs_new = 0;
        for (unsigned i = 0; i < num_soft_cnstrs; i++) {
            if (core[i]) {
                unsat_core_sz++;
                core[i] = false;
                continue;
            }
         
            key_constr[num_soft_cnstrs_new++] = key_constr[i];
        }

        num_soft_cnstrs = num_soft_cnstrs_new;
        
        if (unsat_core_sz == 0)
            return;
    }
}

Z3_ast key_not_zero_cnstr(R3S_cfg_t r3s_cfg, Z3_context ctx, Z3_ast key)
{
    Z3_ast   *const_key_slices;
    Z3_ast   zero_key_bytes;
    Z3_ast   not_zero_key_bytes;
    
    unsigned useful_bytes;
    unsigned last_bits;
    unsigned byte;

    useful_bytes     = R3S_cfg_max_in_sz(r3s_cfg) / 8 + 4;
    const_key_slices = (Z3_ast*) malloc(sizeof(Z3_ast) * (useful_bytes + 7));

    for (byte = 0; byte < useful_bytes - 1; byte++)
        const_key_slices[byte] = mk_key_byte_const(ctx, key, KEY_SIZE - byte - 1, 0);
    
    last_bits = 0;
    for (unsigned bit = byte * 8; bit < useful_bytes * 8 - 1; bit++)
    {
        const_key_slices[byte + last_bits] = mk_key_bit_const(ctx, key, KEY_SIZE_BITS - bit - 1, 0);
        last_bits++;
    }
    
    zero_key_bytes     = Z3_mk_and(ctx, useful_bytes - 1 + last_bits, const_key_slices);
    not_zero_key_bytes = Z3_mk_not(ctx, zero_key_bytes);

    free(const_key_slices);
    
    return not_zero_key_bytes;
}

typedef struct {
    Z3_context   ctx;
    Z3_func_decl *keys_decl;
    Z3_ast       *keys;
    Z3_solver    s;
} R3S_setup_t;

R3S_setup_t mk_setup(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_setup_t setup;
    Z3_sort       key_sort;
    Z3_symbol     *keys_symbol;
    Z3_ast        *not_zero_keys;
    Z3_ast        stmt;

    keys_symbol     = (Z3_symbol*)    malloc(sizeof(Z3_symbol)    * r3s_cfg.n_keys);
    setup.keys_decl = (Z3_func_decl*) malloc(sizeof(Z3_func_decl) * r3s_cfg.n_keys);
    setup.keys      = (Z3_ast*)       malloc(sizeof(Z3_ast)       * r3s_cfg.n_keys);
    not_zero_keys   = (Z3_ast*)       malloc(sizeof(Z3_ast)       * r3s_cfg.n_keys);

    setup.ctx       = mk_context();
    setup.s         = mk_solver(setup.ctx);

    key_sort        = Z3_mk_bv_sort(setup.ctx, KEY_SIZE_BITS);

    for (unsigned ikey = 0; ikey < r3s_cfg.n_keys; ikey++)
    {
        keys_symbol[ikey]     = Z3_mk_int_symbol(setup.ctx, ikey); 
        setup.keys_decl[ikey] = Z3_mk_func_decl(setup.ctx, keys_symbol[ikey], 0, 0, key_sort);
        setup.keys[ikey]      = Z3_mk_app(setup.ctx, setup.keys_decl[ikey], 0, 0);

        not_zero_keys[ikey]   = key_not_zero_cnstr(r3s_cfg, setup.ctx, setup.keys[ikey]);
        Z3_solver_assert(setup.ctx, setup.s, not_zero_keys[ikey]);
    }

    stmt = mk_rss_stmt(r3s_cfg, setup.ctx, mk_p_cnstrs, setup.keys);

    Z3_solver_assert(setup.ctx, setup.s, stmt);

    free(keys_symbol);
    free(not_zero_keys);

    return setup;
}

R3S_status_t adjust_keys_to_cnstrs(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs, R3S_key_t *keys_seeds)
{
    R3S_setup_t setup;
    Z3_model      m;
    Z3_ast        key_model;

    setup = mk_setup(r3s_cfg, mk_p_cnstrs);

    pseudo_partial_maxsat(setup.ctx, setup.s, setup.keys, keys_seeds);

    m = Z3_solver_get_model(setup.ctx, setup.s);

    for (unsigned ikey = 0; ikey < r3s_cfg.n_keys; ikey++)
    {
        key_model = Z3_model_get_const_interp(setup.ctx, m, setup.keys_decl[ikey]);
        k_ast_to_rss_key(setup.ctx, key_model, keys_seeds[ikey]);
    }
    
    del_solver(setup.ctx, setup.s);
    free(setup.keys_decl);
    free(setup.keys);

    return R3S_STATUS_SUCCESS;
}

R3S_status_t sat_checker(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_setup_t setup;

    setup = mk_setup(r3s_cfg, mk_p_cnstrs);

    DEBUG_PLOG("checking hard constraints\n");

    if (Z3_solver_check(setup.ctx, setup.s) == Z3_L_FALSE) {
        /*
         * It is not possible to make the formula satisfiable
         * even when ignoring all soft constraints.
        */
        del_solver(setup.ctx, setup.s);
        free(setup.keys_decl);
        free(setup.keys);
        
        return R3S_STATUS_NO_SOLUTION;
    }

    return R3S_STATUS_HAS_SOLUTION;
}

int wp;

void alarm_handler(int sig)
{
    R3S_key_t key;

    R3S_zero_key(key);
    write(wp, key, KEY_SIZE);

    DEBUG_PLOG("terminated (timeout)\n");

    exit(0);
}

void worker_key_adjuster(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_status_t status;
    R3S_key_t    *keys;
    
    keys = (R3S_key_t*) malloc(sizeof(R3S_key_t) * r3s_cfg.n_keys);

    DEBUG_PLOG("started\n");

    signal(SIGALRM, alarm_handler);
    alarm(SOLVER_TIMEOUT_SEC);

    for (unsigned ikey = 0; ikey < r3s_cfg.n_keys; ikey++)
        R3S_rand_key(r3s_cfg, keys[ikey]);

    status = adjust_keys_to_cnstrs(r3s_cfg, mk_p_cnstrs, keys);

    if (status == R3S_STATUS_NO_SOLUTION)
    {
        write(wp, &status, sizeof(R3S_status_t));
        free(keys);
        exit(0);
    }

    for (unsigned ikey = 0; ikey < r3s_cfg.n_keys; ikey++)
    {
        DEBUG_PLOG("testing key %u\n", ikey);

        if (!R3S_k_test_dist(r3s_cfg, keys[ikey]))
        {
            DEBUG_PLOG("test failed\n");

            status = R3S_STATUS_BAD_SOLUTION;
            write(wp, &status, sizeof(R3S_status_t));
            free(keys);
            exit(0);
        }
    }

    status = R3S_STATUS_SUCCESS;
    write(wp, &status, sizeof(R3S_status_t));

    for (unsigned ikey = 0; ikey < r3s_cfg.n_keys; ikey++)
        write(wp, keys[ikey], KEY_SIZE);

    DEBUG_PLOG("terminated\n");

    free(keys);
    exit(0);
}

void worker_sat_checker(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_status_t status;

    DEBUG_PLOG("started (sat checker)\n");

    status = sat_checker(r3s_cfg, mk_p_cnstrs);

    DEBUG_PLOG("%s\n", R3S_status_to_string(status));

    write(wp, &status, sizeof(R3S_status_t));
    exit(0);
}

void launch_worker(R3S_worker worker, R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs, int p, comm_t comm)
{
    int pid;

    if (!(pid = fork())) 
    {
        wp = comm.wpipe[p];
        worker(r3s_cfg, mk_p_cnstrs);
    }

    comm.pid[p] = pid;
}

R3S_status_t master(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs, int np, comm_t comm, R3S_key_t *keys)
{
    R3S_status_t status;
    int            wstatus;
    int            maxfd;
    fd_set         fds;

    launch_worker(&worker_sat_checker, r3s_cfg, mk_p_cnstrs, 0, comm);

    for (int p = 1; p < np; p++)
        launch_worker(&worker_key_adjuster, r3s_cfg, mk_p_cnstrs, p, comm);
    
    for (;;)
    {
        maxfd = -1;
        FD_ZERO(&fds);
        for (int p = 0; p < np; p++) {
            FD_SET(comm.rpipe[p], &fds);
            maxfd = comm.rpipe[p] > maxfd ? comm.rpipe[p] : maxfd;
        }

        while (!select(maxfd + 1, &fds, NULL, NULL, NULL));

        for (int p = 0; p < np; p++)
        {
            if (!FD_ISSET(comm.rpipe[p], &fds)) continue;
            
            read(comm.rpipe[p], &status, sizeof(R3S_status_t));

            switch (status)
            {
                case R3S_STATUS_NO_SOLUTION:
                    DEBUG_PLOG("unsat\n");
                    return status;

                case R3S_STATUS_HAS_SOLUTION:
                case R3S_STATUS_BAD_SOLUTION:
                    waitpid(comm.pid[p], &wstatus, 0);
                    comm.pid[p] = -1;
                    launch_worker(worker_key_adjuster, r3s_cfg, mk_p_cnstrs, p, comm);

                    break;

                case R3S_STATUS_SUCCESS:
                    for (unsigned ikey = 0; ikey < r3s_cfg.n_keys; ikey++)
                    {
                        read(comm.rpipe[p], keys[ikey], KEY_SIZE);
                        DEBUG_PLOG("received key %u\n%s\n", ikey, R3S_key_to_string(keys[ikey]));
                    }

                    for (p = 0; p < np; p++)
                    {
                        if (comm.pid[p] == -1) continue;
                        
                        kill(comm.pid[p], SIGTERM);
                        wait(&wstatus);
                    }

                    return status;

                default: break; // will never get here
            }

            break;
        }
    }
}

R3S_status_t R3S_find_keys(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs, out R3S_key_t *keys)
{
    int            nworkers;
    comm_t         comm;
    R3S_status_t status;

    nworkers   = r3s_cfg.n_procs <= 0 ? get_nprocs() : r3s_cfg.n_procs;

    comm.pid   = (int*) malloc(sizeof(int) * nworkers);
    comm.rpipe = (int*) malloc(sizeof(int) * nworkers);
    comm.wpipe = (int*) malloc(sizeof(int) * nworkers);

    for (int p = 0; p < nworkers; p++) {
        int pipefd[2];

        pipe(pipefd);

        comm.rpipe[p] = pipefd[0];
        comm.wpipe[p] = pipefd[1];
    }

    status = master(r3s_cfg,  mk_p_cnstrs, nworkers, comm, keys);

    free(comm.pid);
    free(comm.rpipe);
    free(comm.wpipe);

    return status;
}

/*
void R3S_check_p_cnstrs(R3S_cfg_t r3s_cfg, R3S_cnstrs_func mk_p_cnstrs, R3S_packet_t p1, R3S_packet_t p2)
{
    Z3_context ctx;
    Z3_solver  s;
    Z3_ast     d1, d2;

    Z3_sort    d_sort;
    Z3_ast     d1_const, d2_const;
    Z3_ast     d_constr;

    ctx           = mk_context();
    s             = mk_solver(ctx);

    d_sort       = Z3_mk_bv_sort(ctx, r3s_cfg.in_sz);
     
    d1            = mk_var(ctx, "d1", d_sort);
    d2            = mk_var(ctx, "d2", d_sort);
  
    d1_const      = mk_d_const(r3s_cfg, ctx, d1, p1);
    d2_const      = mk_d_const(r3s_cfg, ctx, d2, p2);

    d_constr      = mk_p_cnstrs(r3s_cfg, ctx, d1, d2);

    Z3_solver_assert(ctx, s, d1_const);
    Z3_solver_assert(ctx, s, d2_const);
    Z3_solver_assert(ctx, s, d_constr);

    #if DEBUG
        FILE *f_ast = fopen(CHECK_K_AST_FILE, "w");
        fprintf(f_ast, "%s", Z3_solver_to_string(ctx, s));
        fclose(f_ast);

        puts("\n==========================================\n");
        puts("               Z3 solver");
        puts("\n==========================================\n");
    #endif

    check(ctx, s);

    del_solver(ctx, s);
    Z3_del_context(ctx);
}
*/