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

void p_ast_to_hash_input(R3S_cfg_t cfg, R3S_packet_ast_t p_ast, R3S_key_hash_in_t hi)
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
    unsigned     ast_sz;

    int          digit1, digit2, remainder;

    p_sz        = p_ast.loaded_opt.sz;
    ast_sz      = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, p_ast.ast));
    p_string    = Z3_get_numeral_string(cfg.ctx, p_ast.ast);
    p_string_sz = strlen(p_string);

    divisor     = (char*) malloc(sizeof(char) * p_string_sz + 1);
    res         = (char*) malloc(sizeof(char) * p_string_sz + 1);
    
    snprintf(divisor, p_string_sz + 1, "%s", p_string);

    // ast size is always bigger than (or equal to) p size
    while (p_sz != ast_sz) {
        remainder = str_long_int_div(divisor, 16, res);
        assert(remainder == 0);
        sprintf(divisor, "%s", res);
        ast_sz -= 4;
    }

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

Z3_ast mk_hash_func(R3S_cfg_t cfg, unsigned iopt, Z3_ast p, Z3_ast key, Z3_ast o)
{
    Z3_ast k;
    Z3_ast p_and_k;
    Z3_ast o_bit;
    Z3_ast p_and_k_xor;
    Z3_ast args[HASH_OUTPUT_SIZE_BITS];
    
    unsigned k_high, k_low;
    unsigned o_high, o_low;
    unsigned sz;

    sz = cfg.loaded_opts[iopt].sz;

    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k_high           = (KEY_SIZE_BITS - 1) - bit;
        k_low            = (KEY_SIZE_BITS - 1) - (bit + sz - 1);
        k                = Z3_mk_extract(cfg.ctx, k_high, k_low, key);

        p_and_k          = Z3_mk_bvand(cfg.ctx, k, p);
        p_and_k_xor      = mk_bvxor(cfg.ctx, p_and_k, sz);

        o_high           = HASH_OUTPUT_SIZE_BITS - bit - 1;
        o_low            = HASH_OUTPUT_SIZE_BITS - bit - 1;
        o_bit            = Z3_mk_extract(cfg.ctx, o_high, o_low, o);

        args[bit]        = Z3_mk_eq(cfg.ctx, p_and_k_xor, o_bit);
    }

    return Z3_mk_and(cfg.ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast pad_ast(R3S_cfg_t cfg, Z3_ast ast, unsigned new_size) {
    unsigned size = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, ast));
    if (new_size <= size) return ast;

    unsigned pad_size = new_size - size;

    Z3_ast padded = Z3_mk_zero_ext(cfg.ctx, pad_size, ast);
    return Z3_mk_rotate_left(cfg.ctx, pad_size, padded);
}

Z3_ast mk_hash_eq(R3S_cfg_t cfg, Z3_ast key, R3S_packet_ast_t p1, R3S_packet_ast_t p2)
{
    Z3_ast k;
    Z3_ast p1_and_k;
    Z3_ast p2_and_k;
    Z3_ast p1_and_k_xor;
    Z3_ast p2_and_k_xor;

    Z3_ast args[HASH_OUTPUT_SIZE_BITS];

    unsigned k_high, k_low;
    unsigned p1_sz, p2_sz, sz;

    p1_sz = p1.loaded_opt.sz;
    p2_sz = p2.loaded_opt.sz;
    sz    = p1_sz > p2_sz ? p1_sz : p2_sz;

    p2.ast = pad_ast(cfg, p2.ast, sz);
    p1.ast = pad_ast(cfg, p1.ast, sz);

    // p1_sz is now equal to p2_sz
    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k_high       = (KEY_SIZE_BITS - 1) - bit;
        k_low        = (KEY_SIZE_BITS - 1) - (bit + sz - 1);
        k            = Z3_mk_extract(cfg.ctx, k_high, k_low, key);

        p1_and_k     = Z3_mk_bvand(cfg.ctx, k, p1.ast);
        p2_and_k     = Z3_mk_bvand(cfg.ctx, k, p2.ast);

        p1_and_k_xor = mk_bvxor(cfg.ctx, p1_and_k, sz);
        p2_and_k_xor = mk_bvxor(cfg.ctx, p2_and_k, sz);

        args[bit]    = Z3_mk_eq(cfg.ctx, p1_and_k_xor, p2_and_k_xor);
    }


    return Z3_mk_and(cfg.ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast mk_hash_eq_two_keys(R3S_cfg_t cfg, Z3_ast key1, Z3_ast key2, R3S_packet_ast_t p1, R3S_packet_ast_t p2)
{
    Z3_ast k1;
    Z3_ast k2;
    Z3_ast p1_and_k1;
    Z3_ast p2_and_k2;
    Z3_ast p1_and_k1_xor;
    Z3_ast p2_and_k2_xor;

    Z3_ast args[HASH_OUTPUT_SIZE_BITS];

    unsigned k_high, k_low;
    unsigned p1_sz, p2_sz, sz;

    p1_sz = p1.loaded_opt.sz;
    p2_sz = p2.loaded_opt.sz;

    if (p1_sz > p2_sz) {
        p2.ast = Z3_mk_zero_ext(cfg.ctx, p1_sz - p2_sz, p2.ast);
    } else if (p2_sz > p1_sz) {
        p1.ast = Z3_mk_zero_ext(cfg.ctx, p2_sz - p1_sz, p1.ast);
    }

    // p1_sz is now equal to p2_sz
    sz = p1_sz;

    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k_high        = (KEY_SIZE_BITS - 1) - bit;
        k_low         = (KEY_SIZE_BITS - 1) - (bit + sz - 1);

        k1            = Z3_mk_extract(cfg.ctx, k_high, k_low, key1);
        k2            = Z3_mk_extract(cfg.ctx, k_high, k_low, key2);

        p1_and_k1     = Z3_mk_bvand(cfg.ctx, k1, p1.ast);
        p2_and_k2     = Z3_mk_bvand(cfg.ctx, k2, p2.ast);

        p1_and_k1_xor = mk_bvxor(cfg.ctx, p1_and_k1, sz);
        p2_and_k2_xor = mk_bvxor(cfg.ctx, p2_and_k2, sz);

        args[bit]     = Z3_mk_eq(cfg.ctx, p1_and_k1_xor, p2_and_k2_xor);
    }

    return Z3_mk_and(cfg.ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast mk_d_const(R3S_cfg_t cfg, Z3_ast input, R3S_packet_t p)
{
    Z3_ast       *pf_x, *pf_const;
    Z3_sort      byte_sort;
    Z3_ast       *and_args;
    Z3_ast       d_const;

    R3S_byte_t   *field;
    R3S_pf_t     pf;

    R3S_status_t     status;
    R3S_loaded_opt_t opt;

    unsigned     offset, sz;
    unsigned     input_sz;
    unsigned     high, low;

    status = R3S_packet_to_loaded_opt(cfg, p, &opt);

    if (status != R3S_STATUS_SUCCESS) assert(false);

    input_sz   = opt.sz / 8;

    pf_x       = (Z3_ast*) malloc(sizeof(Z3_ast) * input_sz);
    pf_const   = (Z3_ast*) malloc(sizeof(Z3_ast) * input_sz);
    and_args   = (Z3_ast*) malloc(sizeof(Z3_ast) * input_sz);

    byte_sort  = Z3_mk_bv_sort(cfg.ctx, 8);

    offset     = 0;
    sz         = 0;

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {
        pf = (R3S_pf_t) ipf;

        if (R3S_cfg_check_pf(cfg, opt, pf) != R3S_STATUS_PF_LOADED)
            continue;

        field = R3S_packet_get_field(&p, pf);
        sz    = R3S_pf_sz(pf);

        for (unsigned byte = 0; byte < sz; byte++, field++)
        {
            high = (input_sz - (offset + byte)) * 8 - 1;
            low  = high - 7;

            pf_const[offset + byte] = Z3_mk_int(cfg.ctx, *field, byte_sort);
            pf_x[offset + byte]     = Z3_mk_extract(cfg.ctx, high, low, input);
            and_args[offset + byte] = Z3_mk_eq(cfg.ctx, pf_const[offset + byte], pf_x[offset + byte]);
        }
        
        offset += sz;
    }

    d_const = Z3_mk_and(cfg.ctx, input_sz, and_args);

    free(pf_x);
    free(pf_const);
    free(and_args);

    return d_const;
}

R3S_status_t R3S_packet_extract_pf(R3S_cfg_t cfg, R3S_packet_ast_t p, R3S_pf_t pf, out Z3_ast *output)
{
    R3S_pf_t     current_pf;
    R3S_status_t status;
    
    unsigned offset;
    unsigned input_sz, sz;
    unsigned high, low;
    
    input_sz = p.loaded_opt.sz;
    offset   = 0;
    sz       = 0;

    if (input_sz != Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, p.ast)))
    {
        DEBUG_PLOG("[R3S_packet_extract_pf] ERROR: opt input size (%u) != packet ast size (%u)\n",
            input_sz, Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, p.ast)));
        return R3S_STATUS_PF_NOT_LOADED;
    }

    status   = R3S_cfg_check_pf(cfg, p.loaded_opt, pf);

    if (status != R3S_STATUS_PF_LOADED)
    {
        DEBUG_PLOG("[R3S_packet_extract_pf] ERROR: %u\n", status);
        return status;
    }

    for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
    {
        current_pf = (R3S_pf_t) ipf;
        status     = R3S_cfg_check_pf(cfg, p.loaded_opt, current_pf);

        if (status == R3S_STATUS_PF_UNKNOWN) return status;
        if (status != R3S_STATUS_PF_LOADED)  continue;

        sz = R3S_pf_sz_bits(current_pf);

        if (current_pf == pf)
        {
            high    = input_sz - 1 - offset;
            low     = high - sz + 1;
            *output = Z3_mk_extract(cfg.ctx, high, low, p.ast);

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

    byte_sort   = Z3_mk_bv_sort(ctx, 8);

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
Z3_sort mk_d_sort(R3S_cfg_t cfg)
{
    unsigned max_sz;
    Z3_sort  d_sort;

    max_sz     = R3S_cfg_max_in_sz(cfg);
    d_sort     = Z3_mk_bv_sort(cfg.ctx, max_sz);

    return d_sort;
}

Z3_ast* mk_p(R3S_cfg_t cfg, Z3_ast d)
{
    Z3_ast   *p;
    Z3_sort  d_sort;
    unsigned n_loaded_opts;
    unsigned input_sz;
    unsigned high, low;
    unsigned d_sort_sz;

    d_sort        = Z3_get_sort(cfg.ctx, d);
    d_sort_sz     = Z3_get_bv_sort_size(cfg.ctx, d_sort);
    
    n_loaded_opts = cfg.n_loaded_opts;
    p             = (Z3_ast*) malloc(sizeof(Z3_ast) * n_loaded_opts);
    
    for (unsigned iopt = 0; iopt < n_loaded_opts; iopt++)
    {
        input_sz    = cfg.loaded_opts[iopt].sz;
        
        assert(input_sz > 0); // TODO: improve this

        high        = d_sort_sz - 1;
        low         = high - input_sz + 1;

        p[iopt]  = Z3_mk_extract(cfg.ctx, high, low, d);
    }

    return p;
}

Z3_ast mk_rss_stmt(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs, Z3_ast *keys)
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

    R3S_packet_ast_t p1_ast, p2_ast;

    unsigned   n_key_pairs;
    unsigned   n_cnstrs;
    unsigned   cnstr;
    unsigned   n_implies;
    unsigned   n_loaded_opts;

    d_sort         = mk_d_sort(cfg);
           
    d1             = mk_var(cfg.ctx, "d1", d_sort);
    d2             = mk_var(cfg.ctx, "d2", d_sort);

    p1             = mk_p(cfg, d1);
    p2             = mk_p(cfg, d2);

    n_loaded_opts  = cfg.n_loaded_opts;
    n_key_pairs    = combinations(cfg.n_keys, 2);
    n_cnstrs       = (cfg.n_keys + n_key_pairs) * (n_loaded_opts * n_loaded_opts);
    n_implies      = 0;

    implies        = (Z3_ast*) malloc(sizeof(Z3_ast) * n_cnstrs);

    for (cnstr = 0; cnstr < cfg.n_keys; cnstr++)
    {
        if (mk_p_cnstrs[cnstr] == NULL)
            continue;
        
        for (unsigned p1_iopt = 0; p1_iopt < n_loaded_opts; p1_iopt++)
        {
            p1_ast.loaded_opt = cfg.loaded_opts[p1_iopt];
            p1_ast.ast        = p1[p1_iopt];

            for (unsigned p2_iopt = 0; p2_iopt < n_loaded_opts; p2_iopt++)
            {
                p2_ast.loaded_opt = cfg.loaded_opts[p2_iopt];
                p2_ast.ast        = p2[p2_iopt];
                p_cnstrs = mk_p_cnstrs[cnstr](cfg, p1_ast, p2_ast);

                if (p_cnstrs == NULL) continue;

                left_implies       = p_cnstrs;
                right_implies      = mk_hash_eq(cfg, keys[cnstr], p1_ast, p2_ast);
                implies[n_implies] = Z3_mk_implies(cfg.ctx, left_implies, right_implies);
                
                n_implies++;
            }
        }
    }

    // make combinations
    for (unsigned k1 = 0; k1 < cfg.n_keys; k1++)
    {
        for (unsigned k2 = k1 + 1; k2 < cfg.n_keys; k2++)
        {
            if (mk_p_cnstrs[cnstr] == NULL) { cnstr++; continue; }

            for (unsigned p1_iopt = 0; p1_iopt < n_loaded_opts; p1_iopt++)
            {
                p1_ast.loaded_opt = cfg.loaded_opts[p1_iopt];
                p1_ast.ast        = p1[p1_iopt];

                for (unsigned p2_iopt = 0; p2_iopt < n_loaded_opts; p2_iopt++)
                {
                    p2_ast.loaded_opt = cfg.loaded_opts[p2_iopt];
                    p2_ast.ast        = p2[p2_iopt];

                    p_cnstrs = mk_p_cnstrs[cnstr](cfg, p1_ast, p2_ast);

                    if (p_cnstrs == NULL) continue;

                    left_implies       = p_cnstrs;
                    right_implies      = mk_hash_eq_two_keys(cfg, keys[k1], keys[k2], p1_ast, p2_ast);
                    implies[n_implies] = Z3_mk_implies(cfg.ctx, left_implies, right_implies);
                    
                    cnstr++;
                    n_implies++;
                }
            }
        }
    }

    and_implies = Z3_mk_and(cfg.ctx, n_implies, implies);

    vars[0]     = Z3_to_app(cfg.ctx, d1);
    vars[1]     = Z3_to_app(cfg.ctx, d2);
 
    forall      = Z3_mk_forall_const(cfg.ctx, 0, 2, vars, 0, 0, and_implies);

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

R3S_status_t R3S_packet_from_cnstrs(
    R3S_cfg_t        cfg,
    R3S_packet_t     p_in,
    R3S_cnstrs_func  mk_p_cnstrs,
    out R3S_packet_t *p_out
)
{
    Z3_solver      s;
    Z3_lbool       result;
    Z3_model       m;

    Z3_symbol      p2_symbol;
    Z3_func_decl   p2_decl;

    Z3_sort        p1_sort, p2_sort;
    Z3_ast         p1, p2, *p2_types, p2_model;
    
    Z3_ast         p_const;
    Z3_ast         stmt;

    R3S_key_hash_in_t hi2;

    R3S_status_t     status;
    R3S_loaded_opt_t loaded_opt;
    R3S_packet_ast_t *shuffled_packet_ast;
    R3S_packet_ast_t p1_ast, p2_ast, p2_model_ast;

    status     = R3S_packet_to_loaded_opt(cfg, p_in, &loaded_opt);

    if (status != R3S_STATUS_SUCCESS) return status;

    s          = mk_solver(cfg.ctx);
    
    p1_sort    = Z3_mk_bv_sort(cfg.ctx, loaded_opt.sz);
    p1         = mk_var(cfg.ctx, "p1", p1_sort);
    p_const    = mk_d_const(cfg, p1, p_in);

    p2_sort    = mk_d_sort(cfg);
    p2_symbol  = Z3_mk_string_symbol(cfg.ctx, "p2");
    p2_decl    = Z3_mk_func_decl(cfg.ctx, p2_symbol, 0, 0, p2_sort);
    
    p2         = Z3_mk_app(cfg.ctx, p2_decl, 0, 0);
    p2_types   = mk_p(cfg, p2);

    p1_ast.ast        = p1;
    p1_ast.loaded_opt = loaded_opt;

    // Now choosing a matching loaded option.
    // This can be done more efficiently, but honestly it doesnt really bother me
    // to leave it like this.
    shuffled_packet_ast = (R3S_packet_ast_t*) malloc(
        sizeof(R3S_packet_ast_t) * cfg.n_loaded_opts
    );

    for (unsigned iopt = 0; iopt < cfg.n_loaded_opts; iopt++) {
        shuffled_packet_ast[iopt].ast        = p2_types[iopt];
        shuffled_packet_ast[iopt].loaded_opt = cfg.loaded_opts[iopt];
    }

    shuffle(
        (void*) shuffled_packet_ast,
        cfg.n_loaded_opts,
        sizeof(R3S_packet_ast_t)
    );

    stmt = NULL;
    for (unsigned iopt = 0; iopt < cfg.n_loaded_opts; iopt++) {
        p2_ast = shuffled_packet_ast[iopt];
        stmt   = mk_p_cnstrs(cfg, p1_ast, p2_ast);

        if (stmt != NULL) break;
    }

    if (stmt == NULL) {
        assert(false && "No constraint matched for this packet.\n");
    }

    Z3_solver_assert(cfg.ctx, s, p_const);
    Z3_solver_assert(cfg.ctx, s, stmt);

    result = Z3_solver_check(cfg.ctx, s);

    switch (result)
    {
        case Z3_L_FALSE:
        case Z3_L_UNDEF: return R3S_STATUS_NO_SOLUTION;
        case Z3_L_TRUE:
            m = Z3_solver_get_model(cfg.ctx, s);
            
            if (!m)
            {
                del_solver(cfg.ctx, s);
                return R3S_STATUS_FAILURE;
            }
    }

    Z3_model_inc_ref(cfg.ctx, m);

    p2_model_ast.ast        = Z3_model_get_const_interp(cfg.ctx, m, p2_decl);
    p2_model_ast.loaded_opt = p2_ast.loaded_opt;

    hi2              = (R3S_key_hash_in_t) malloc(sizeof(R3S_byte_t) * loaded_opt.sz);

    p_ast_to_hash_input(cfg, p2_model_ast, hi2);

    *p_out   = R3S_key_hash_in_to_packet(cfg, p2_model_ast.loaded_opt, hi2);
    
    free(hi2);
    free(shuffled_packet_ast);
    free(p2_types);

    Z3_model_dec_ref(cfg.ctx, m);
    del_solver(cfg.ctx, s);

    return R3S_STATUS_SUCCESS;
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

    init_rand();

    for (int bit = 0; bit < KEY_SIZE_BITS; bit++)
        key_constr[bit] = mk_key_bit_const(ctx, keys[0], KEY_SIZE_BITS - 1 - bit, BIT_FROM_KEY(bit, keys_proposals[0]));

    for (unsigned i = 0; i < KEY_SIZE_BITS; i++) core[i] = false;

    num_soft_cnstrs = KEY_SIZE_BITS;
    for (;;) {
        check_unsat_core(ctx, s, num_soft_cnstrs, key_constr, core);

        unsat_core_sz = 0;
        num_soft_cnstrs_new = 0;
        for (unsigned i = 0; i < num_soft_cnstrs; i++) {

            // this assumption is in the unsat core
            if (core[i]) {
                unsat_core_sz++;
                core[i] = false;

                // randomly choose between removing and not removing this assumption
                if (rand() & 1) {
                    key_constr[num_soft_cnstrs_new++] = key_constr[i];
                }

                continue;
            }
         
            key_constr[num_soft_cnstrs_new++] = key_constr[i];
        }

        num_soft_cnstrs = num_soft_cnstrs_new;
        
        if (unsat_core_sz == 0)
            return;
    }
}

Z3_ast key_not_zero_cnstr(R3S_cfg_t cfg, Z3_ast key)
{
    Z3_ast   *const_key_slices;
    Z3_ast   zero_key_bytes;
    Z3_ast   not_zero_key_bytes;
    
    unsigned useful_bytes;
    unsigned last_bits;
    unsigned byte;

    useful_bytes     = R3S_cfg_max_in_sz(cfg) / 8 + 4;
    const_key_slices = (Z3_ast*) malloc(sizeof(Z3_ast) * (useful_bytes + 7));

    for (byte = 0; byte < useful_bytes - 1; byte++)
        const_key_slices[byte] = mk_key_byte_const(cfg.ctx, key, KEY_SIZE - byte - 1, 0);
    
    last_bits = 0;
    for (unsigned bit = byte * 8; bit < useful_bytes * 8 - 1; bit++)
    {
        const_key_slices[byte + last_bits] = mk_key_bit_const(cfg.ctx, key, KEY_SIZE_BITS - bit - 1, 0);
        last_bits++;
    }
    
    zero_key_bytes     = Z3_mk_and(cfg.ctx, useful_bytes - 1 + last_bits, const_key_slices);
    not_zero_key_bytes = Z3_mk_not(cfg.ctx, zero_key_bytes);

    free(const_key_slices);
    
    return not_zero_key_bytes;
}

typedef struct {
    Z3_func_decl *keys_decl;
    Z3_ast       *keys;
    Z3_solver    s;
} R3S_setup_t;

R3S_setup_t mk_setup(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_setup_t setup;
    Z3_sort     key_sort;
    Z3_symbol   *keys_symbol;
    Z3_ast      *not_zero_keys;
    Z3_ast      stmt;

    keys_symbol     = (Z3_symbol*)    malloc(sizeof(Z3_symbol)    * cfg.n_keys);
    setup.keys_decl = (Z3_func_decl*) malloc(sizeof(Z3_func_decl) * cfg.n_keys);
    setup.keys      = (Z3_ast*)       malloc(sizeof(Z3_ast)       * cfg.n_keys);
    not_zero_keys   = (Z3_ast*)       malloc(sizeof(Z3_ast)       * cfg.n_keys);

    setup.s         = mk_solver(cfg.ctx);
    key_sort        = Z3_mk_bv_sort(cfg.ctx, KEY_SIZE_BITS);

    for (unsigned ikey = 0; ikey < cfg.n_keys; ikey++)
    {
        keys_symbol[ikey]     = Z3_mk_int_symbol(cfg.ctx, ikey); 
        setup.keys_decl[ikey] = Z3_mk_func_decl(cfg.ctx, keys_symbol[ikey], 0, 0, key_sort);
        setup.keys[ikey]      = Z3_mk_app(cfg.ctx, setup.keys_decl[ikey], 0, 0);

        not_zero_keys[ikey]   = key_not_zero_cnstr(cfg, setup.keys[ikey]);
        Z3_solver_assert(cfg.ctx, setup.s, not_zero_keys[ikey]);
    }

    stmt = mk_rss_stmt(cfg, mk_p_cnstrs, setup.keys);

    Z3_solver_assert(cfg.ctx, setup.s, stmt);

    free(keys_symbol);
    free(not_zero_keys);

    return setup;
}

R3S_status_t adjust_keys_to_cnstrs(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs, R3S_key_t *keys_seeds)
{
    R3S_setup_t setup;
    Z3_model      m;
    Z3_ast        key_model;

    setup = mk_setup(cfg, mk_p_cnstrs);

    pseudo_partial_maxsat(cfg.ctx, setup.s, setup.keys, keys_seeds);

    m = Z3_solver_get_model(cfg.ctx, setup.s);

    for (unsigned ikey = 0; ikey < cfg.n_keys; ikey++)
    {
        key_model = Z3_model_get_const_interp(cfg.ctx, m, setup.keys_decl[ikey]);
        k_ast_to_rss_key(cfg.ctx, key_model, keys_seeds[ikey]);
    }
    
    del_solver(cfg.ctx, setup.s);
    free(setup.keys_decl);
    free(setup.keys);

    return R3S_STATUS_SUCCESS;
}

R3S_status_t sat_checker(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_setup_t setup;

    setup = mk_setup(cfg, mk_p_cnstrs);

    DEBUG_PLOG("checking hard constraints\n");

    if (Z3_solver_check(cfg.ctx, setup.s) == Z3_L_FALSE) {
        /*
         * It is not possible to make the formula satisfiable
         * even when ignoring all soft constraints.
        */
        del_solver(cfg.ctx, setup.s);
        free(setup.keys_decl);
        free(setup.keys);
        
        return R3S_STATUS_NO_SOLUTION;
    }

    del_solver(cfg.ctx, setup.s);
    free(setup.keys_decl);
    free(setup.keys);

    return R3S_STATUS_HAS_SOLUTION;
}

int wp;

void alarm_handler(int sig)
{
    R3S_key_t key;

    R3S_zero_key(key);
    if (write(wp, key, KEY_SIZE) == -1) {
        DEBUG_PLOG("IO ERROR: unable to communicate key to manager\n");
    }

    DEBUG_PLOG("terminated (timeout)\n");

    exit(0);
}

void worker_key_adjuster(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_status_t status;
    R3S_key_t    *keys;
    R3S_stats_t  stats;
    
    keys    = (R3S_key_t*) malloc(sizeof(R3S_key_t) * cfg.n_keys);

    DEBUG_PLOG("started\n");

    signal(SIGALRM, alarm_handler);
    alarm(SOLVER_TIMEOUT_SEC);

    for (unsigned ikey = 0; ikey < cfg.n_keys; ikey++)
        R3S_key_rand(cfg, keys[ikey]);

    status = adjust_keys_to_cnstrs(cfg, mk_p_cnstrs, keys);

    if (status == R3S_STATUS_NO_SOLUTION)
    {
        if (write(wp, &status, sizeof(R3S_status_t)) == -1) {
            DEBUG_PLOG("IO ERROR: unable to communicate status to manager\n");
        }
        
        free(keys);
        R3S_stats_delete(&stats);

        exit(0);
    }

    for (unsigned ikey = 0; ikey < cfg.n_keys; ikey++)
    {
        DEBUG_PLOG("testing key number %u\n", ikey);

        if (!R3S_stats_eval(cfg, keys[ikey], &stats))
        {
            DEBUG_PLOG("test failed\n");

            status = R3S_STATUS_BAD_SOLUTION;
            if (write(wp, &status, sizeof(R3S_status_t)) == -1) {
                DEBUG_PLOG("IO ERROR: unable to communicate status to manager\n");
            }

            free(keys);
            R3S_stats_delete(&stats);

            exit(0);
        }
    }

    status = R3S_STATUS_SUCCESS;
    if (write(wp, &status, sizeof(R3S_status_t)) == -1) {
        DEBUG_PLOG("IO ERROR: unable to communicate status to manager\n");   
    }

    for (unsigned ikey = 0; ikey < cfg.n_keys; ikey++)
        if (write(wp, keys[ikey], KEY_SIZE) == -1)
            DEBUG_PLOG("IO ERROR: unable to communicate key to manager\n");

    DEBUG_PLOG("terminated\n");

    free(keys);
    R3S_stats_delete(&stats);
    exit(0);
}

void worker_sat_checker(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs)
{
    R3S_status_t status;

    DEBUG_PLOG("started (sat checker)\n");

    status = sat_checker(cfg, mk_p_cnstrs);

    DEBUG_PLOG("%s\n", R3S_status_to_string(status));

    if (write(wp, &status, sizeof(R3S_status_t)) == -1)
        DEBUG_PLOG("IO ERROR: unable to communicate status to manager\n");

    exit(0);
}

void launch_worker(R3S_worker worker, R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs, int p, comm_t comm)
{
    int pid;

    if (!(pid = fork())) 
    {
        wp = comm.wpipe[p];
        worker(cfg, mk_p_cnstrs);
    }

    comm.pid[p] = pid;
}

R3S_status_t master(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs, int np, comm_t comm, R3S_key_t *keys)
{
    R3S_status_t status;
    int            wstatus;
    int            maxfd;
    fd_set         fds;

    launch_worker(&worker_sat_checker, cfg, mk_p_cnstrs, 0, comm);

    for (int p = 1; p < np; p++)
        launch_worker(&worker_key_adjuster, cfg, mk_p_cnstrs, p, comm);
    
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
            
            if (read(comm.rpipe[p], &status, sizeof(R3S_status_t)) == -1) {
                DEBUG_PLOG("IO ERROR: unable to read status from worker\n");
                continue; // FIXME: should I be reacting this way? Or should I retry?
            }

            switch (status)
            {
                case R3S_STATUS_NO_SOLUTION:
                    DEBUG_PLOG("unsat\n");
                    return status;

                case R3S_STATUS_HAS_SOLUTION:
                case R3S_STATUS_BAD_SOLUTION:
                    waitpid(comm.pid[p], &wstatus, 0);
                    comm.pid[p] = -1;
                    launch_worker(worker_key_adjuster, cfg, mk_p_cnstrs, p, comm);

                    break;

                case R3S_STATUS_SUCCESS:
                    for (unsigned ikey = 0; ikey < cfg.n_keys; ikey++)
                    {
                        if (read(comm.rpipe[p], keys[ikey], KEY_SIZE) == -1) {
                            DEBUG_PLOG("IO ERROR: unable to read status from worker\n");
                            continue; // FIXME: should I be reacting this way? Or should I retry?
                        }

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

R3S_status_t R3S_keys_fit_cnstrs(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs, out R3S_key_t *keys)
{
    int          nworkers;
    comm_t       comm;
    R3S_status_t status;

    nworkers   = cfg.n_procs <= 0 ? get_nprocs() : cfg.n_procs;

    comm.pid   = (int*) malloc(sizeof(int) * nworkers);
    comm.rpipe = (int*) malloc(sizeof(int) * nworkers);
    comm.wpipe = (int*) malloc(sizeof(int) * nworkers);

    for (int p = 0; p < nworkers; p++) {
        int pipefd[2];

        if (pipe(pipefd) == -1) {
            DEBUG_PLOG("IO ERROR: unable to create pipe\n");
            exit(1);
        }

        comm.rpipe[p] = pipefd[0];
        comm.wpipe[p] = pipefd[1];
    }

    status = master(cfg, mk_p_cnstrs, nworkers, comm, keys);

    free(comm.pid);
    free(comm.rpipe);
    free(comm.wpipe);

    return status;
}

R3S_status_t R3S_keys_test_cnstrs(R3S_cfg_t cfg, R3S_cnstrs_func *mk_p_cnstrs, out R3S_key_t *keys)
{
    R3S_setup_t setup;
    Z3_ast      key_const;

    setup = mk_setup(cfg, mk_p_cnstrs);

    for (unsigned ikey = 0; ikey < cfg.n_keys; ikey++)
    {
        key_const = mk_key_const(cfg.ctx, setup.keys[ikey], keys[ikey]);
        Z3_solver_assert(cfg.ctx, setup.s, key_const);
    }

    DEBUG_LOG("checking keys against constraints\n");

    if (Z3_solver_check(cfg.ctx, setup.s) == Z3_L_FALSE) {
        /*
         * It is not possible to make the formula satisfiable
         * even when ignoring all soft constraints.
        */
        del_solver(cfg.ctx, setup.s);
        free(setup.keys_decl);
        free(setup.keys);
        
        return R3S_STATUS_FAILURE;
    }

    del_solver(cfg.ctx, setup.s);
    free(setup.keys_decl);
    free(setup.keys);

    return R3S_STATUS_SUCCESS;
}
