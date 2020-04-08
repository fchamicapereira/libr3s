#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 

#include <sys/select.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include "solver.h"
#include "util.h"

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

void d_ast_to_hash_input(Z3_context ctx, Z3_ast d, RSSKS_in_t hi)
{
    /*
     *  I know what you're thinking. Getting the value of a bit vector
     *  by converting its string representation? Better call a priest
     *  and exorcise this code.
     *  Unfortunately, this was the only way that actually worked.
     *  I still feel that this is wrong, and I need a shower.
     */

    Z3_string    d_string;
    char         *divisor, *res;
    size_t       d_string_sz;

    int          digit1, digit2;

    d_string = Z3_get_numeral_string(ctx, d);

    d_string_sz = strlen(d_string);
    divisor     = (char*) malloc(sizeof(char) * d_string_sz + 1);
    res         = (char*) malloc(sizeof(char) * d_string_sz + 1);
    
    sprintf(divisor, "%s", d_string);

    for (unsigned byte_idx = 0; byte_idx < HASH_INPUT_SIZE; byte_idx++)
    {
        digit1 = digit2 = 0;

        digit2 = str_long_int_div(divisor, 16, res);
        sprintf(divisor, "%s", res);

        digit1 = str_long_int_div(divisor, 16, res);
        sprintf(divisor, "%s", res);

        hi[HASH_INPUT_SIZE - 1 - byte_idx] = digit1 * 16 + digit2;
    }

    free(divisor);
    free(res);
}

void k_ast_to_rss_key(Z3_context ctx, Z3_ast k, RSSKS_key_t rssk)
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

void check(Z3_context ctx, Z3_solver s)
{
    #if DEBUG
        Z3_ast_vector core;
        FILE *fcore;
    #endif

    Z3_model m = 0;
    Z3_lbool result = Z3_solver_check(ctx, s);

    switch (result)
    {
    case Z3_L_FALSE:
        printf("unsat\n");

        #if DEBUG
            core = Z3_solver_get_unsat_core(ctx, s);
            
            fcore = fopen(UNSAT_CORE_AST_FILE, "w");
            printf("unsat core size %u\n", Z3_ast_vector_size(ctx, core));
            for (unsigned i = 0; i < Z3_ast_vector_size(ctx, core); ++i) {
                fprintf(fcore, "%s\n", Z3_ast_to_string(ctx, Z3_ast_vector_get(ctx, core, i)));
                printf("%s\n", Z3_ast_to_string(ctx, Z3_ast_vector_get(ctx, core, i)));
            }
            fclose(fcore);            
        #endif
        break;
    case Z3_L_UNDEF:
        printf("unknown: %s\n", Z3_solver_get_reason_unknown(ctx, s));
        m = Z3_solver_get_model(ctx, s);
        if (m) {
            Z3_model_inc_ref(ctx, m);
            printf("potential model:\n%s\n", Z3_model_to_string(ctx, m));
        }
        break;
    case Z3_L_TRUE:
        m = Z3_solver_get_model(ctx, s);
        if (m)
            Z3_model_inc_ref(ctx, m);
        
        printf("sat\n%s\n", Z3_model_to_string(ctx, m));
        break;
    }

    if (m)
        Z3_model_dec_ref(ctx, m);
}

Z3_ast mk_bvxor(Z3_context ctx, Z3_ast bv, unsigned sz)
{
    Z3_ast *el    = (Z3_ast *)malloc(sizeof(Z3_ast) * sz);
    Z3_ast *xored = (Z3_ast *)malloc(sizeof(Z3_ast) * sz);
    Z3_ast result;

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

Z3_ast mk_hash_func(Z3_context ctx, Z3_ast d, Z3_ast key, Z3_ast o)
{
    Z3_ast k[HASH_OUTPUT_SIZE_BITS];
    Z3_ast d_and_k[HASH_OUTPUT_SIZE_BITS];
    Z3_ast o_bit[HASH_OUTPUT_SIZE_BITS];
    Z3_ast d_and_k_xor[HASH_OUTPUT_SIZE_BITS];
    Z3_ast args[HASH_OUTPUT_SIZE_BITS];
    
    unsigned k_high, k_low;
    unsigned o_high, o_low;

    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k_high           = (KEY_SIZE_BITS - 1) - bit;
        k_low            = (KEY_SIZE_BITS - 1) - (bit + HASH_INPUT_SIZE_BITS - 1);
        k[bit]           = Z3_mk_extract(ctx, k_high, k_low, key);

        d_and_k[bit]     = Z3_mk_bvand(ctx, k[bit], d);
        d_and_k_xor[bit] = mk_bvxor(ctx, d_and_k[bit], HASH_INPUT_SIZE_BITS);

        o_high           = HASH_OUTPUT_SIZE_BITS - bit - 1;
        o_low            = HASH_OUTPUT_SIZE_BITS - bit - 1;
        o_bit[bit]       = Z3_mk_extract(ctx, o_high, o_low, o);

        args[bit]        = Z3_mk_eq(ctx, d_and_k_xor[bit], o_bit[bit]);
    }

    return Z3_mk_and(ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast mk_hash_eq(Z3_context ctx, Z3_ast key, Z3_ast d1, Z3_ast d2)
{
    Z3_ast k[HASH_OUTPUT_SIZE_BITS];
    Z3_ast d1_and_k[HASH_OUTPUT_SIZE_BITS];
    Z3_ast d2_and_k[HASH_OUTPUT_SIZE_BITS];
    
    Z3_ast d1_and_k_xor[HASH_OUTPUT_SIZE_BITS];
    Z3_ast d2_and_k_xor[HASH_OUTPUT_SIZE_BITS];

    Z3_ast args[HASH_OUTPUT_SIZE_BITS];

    unsigned k_high, k_low;
    
    for (int bit = 0; bit < HASH_OUTPUT_SIZE_BITS; bit++)
    {
        k_high            = (KEY_SIZE_BITS - 1) - bit;
        k_low             = (KEY_SIZE_BITS - 1) - (bit + HASH_INPUT_SIZE_BITS - 1);
        k[bit]            = Z3_mk_extract(ctx, k_high, k_low, key);

        d1_and_k[bit]     = Z3_mk_bvand(ctx, k[bit], d1);
        d2_and_k[bit]     = Z3_mk_bvand(ctx, k[bit], d2);

        d1_and_k_xor[bit] = mk_bvxor(ctx, d1_and_k[bit], HASH_INPUT_SIZE_BITS);
        d2_and_k_xor[bit] = mk_bvxor(ctx, d2_and_k[bit], HASH_INPUT_SIZE_BITS);

        args[bit]         = Z3_mk_eq(ctx, d1_and_k_xor[bit], d2_and_k_xor[bit]);
    }

    return Z3_mk_and(ctx, HASH_OUTPUT_SIZE_BITS, args);
}

Z3_ast mk_d_const(Z3_context ctx, Z3_ast input, RSSKS_headers_t headers)
{
    Z3_ast src_ip, src_ip_const;
    Z3_ast dst_ip, dst_ip_const;
    Z3_ast src_port, src_port_const;
    Z3_ast dst_port, dst_port_const;
    Z3_ast protocol, protocol_const;

    Z3_sort ip_sort, port_sort, protocol_sort;
    Z3_ast and_args[5];

    unsigned src_ip_offset   = packet_field_offset_le_bits(SRC_IP);
    unsigned dst_ip_offset   = packet_field_offset_le_bits(DST_IP);
    unsigned src_port_offset = packet_field_offset_le_bits(SRC_PORT);
    unsigned dst_port_offset = packet_field_offset_le_bits(DST_PORT);
    unsigned protocol_offset = packet_field_offset_le_bits(PROTOCOL);

    unsigned ip_sz    = sizeof(RSSKS_ipv4_t) * 8;
    unsigned port_sz  = sizeof(RSSKS_port_t) * 8;
    unsigned proto_sz = sizeof(protocol_t) * 8; 

    ip_sort        = Z3_mk_bv_sort(ctx, 32);
    port_sort      = Z3_mk_bv_sort(ctx, 16);
    protocol_sort  = Z3_mk_bv_sort(ctx, 8);

    src_ip_const   = Z3_mk_int(ctx, headers.src_ip, ip_sort);
    src_ip         = Z3_mk_extract(ctx, src_ip_offset + ip_sz - 1, src_ip_offset, input);

    dst_ip_const   = Z3_mk_int(ctx, headers.dst_ip, ip_sort);
    dst_ip         = Z3_mk_extract(ctx, dst_ip_offset + ip_sz - 1, dst_ip_offset, input);

    src_port_const = Z3_mk_int(ctx, headers.src_port, port_sort);
    src_port       = Z3_mk_extract(ctx, src_port_offset + port_sz - 1, src_port_offset, input);
    
    dst_port_const = Z3_mk_int(ctx, headers.dst_port, port_sort);
    dst_port       = Z3_mk_extract(ctx, dst_port_offset + port_sz - 1, dst_port_offset, input);

    protocol_const = Z3_mk_int(ctx, headers.protocol, protocol_sort);
    protocol       = Z3_mk_extract(ctx, protocol_offset + proto_sz - 1, protocol_offset, input);

    and_args[0]    = Z3_mk_eq(ctx, src_ip_const, src_ip);
    and_args[1]    = Z3_mk_eq(ctx, dst_ip_const, dst_ip);
    and_args[2]    = Z3_mk_eq(ctx, src_port_const, src_port);
    and_args[3]    = Z3_mk_eq(ctx, dst_port_const, dst_port);
    and_args[4]    = Z3_mk_eq(ctx, protocol_const, protocol);

    return Z3_mk_and(ctx, 5, and_args);
}

Z3_ast mk_key_byte_const(Z3_context ctx, Z3_ast key, unsigned byte, RSSKS_byte_t value)
{
    Z3_ast  value_const;
    Z3_ast  key_slice;
    Z3_sort byte_sort;

    byte_sort = Z3_mk_bv_sort(ctx, 8);

    value_const = Z3_mk_int(ctx, (int) value, byte_sort);
    key_slice   = Z3_mk_extract(ctx, byte * 8 + 7, byte * 8, key);

    return Z3_mk_eq(ctx, key_slice, value_const);
}

Z3_ast mk_key_const(Z3_context ctx, Z3_ast key, RSSKS_key_t k)
{
    Z3_ast  and_args[KEY_SIZE];

    for (int b = 0; b < KEY_SIZE; b++)
        and_args[b] = mk_key_byte_const(ctx, key, b, k[KEY_SIZE - b - 1]);

    return Z3_mk_and(ctx, KEY_SIZE, and_args);
}

void z3_hash(RSSKS_key_t k, RSSKS_headers_t h)
{
    Z3_context ctx;
    Z3_solver  s;
    Z3_sort    d_sort, o_sort, key_sort;
    Z3_ast     d, o, key;
    Z3_ast     hash;
    Z3_ast     d_const, key_const;

    ctx            = mk_context();
    s              = mk_solver(ctx);
     
    d_sort         = Z3_mk_bv_sort(ctx, HASH_INPUT_SIZE_BITS);
    o_sort         = Z3_mk_bv_sort(ctx, HASH_OUTPUT_SIZE_BITS);
    key_sort       = Z3_mk_bv_sort(ctx, KEY_SIZE_BITS);
     
    d              = mk_var(ctx, "d", d_sort);
    o              = mk_var(ctx, "o", o_sort);
    key            = mk_var(ctx, "k", key_sort);
     
    hash           = mk_hash_func(ctx, d, key, o);
   
    key_const      = mk_key_const(ctx, key, k);
    d_const        = mk_d_const(ctx, d, h);

    Z3_solver_assert(ctx, s, hash);
    Z3_solver_assert(ctx, s, key_const);
    Z3_solver_assert(ctx, s, d_const);

    check(ctx, s);

    del_solver(ctx, s);
    Z3_del_context(ctx);
}

RSSKS_headers_t header_from_constraints(RSSKS_headers_t h)
{
    Z3_context   ctx;
    Z3_solver    s;
    Z3_lbool     result;
    Z3_model     m;

    Z3_symbol    d2_symbol;
    Z3_func_decl d2_decl;

    Z3_sort      d_sort;
    Z3_ast       d1, d2, d2_model;
    Z3_ast       stmt;

    RSSKS_headers_t    h2;
    RSSKS_in_t hi2;

    ctx       = mk_context();
    s         = mk_solver(ctx);
    
    d_sort    = Z3_mk_bv_sort(ctx, HASH_INPUT_SIZE_BITS);

    d1        = mk_var(ctx, "d1", d_sort);

    d2_symbol = Z3_mk_string_symbol(ctx, "d2"); 
    d2_decl   = Z3_mk_func_decl(ctx, d2_symbol, 0, 0, d_sort);
    d2        = Z3_mk_app(ctx, d2_decl, 0, 0);

    stmt      = mk_d_constraints(ctx, d1, d2);

    Z3_solver_assert(ctx, s, mk_d_const(ctx, d1, h));
    Z3_solver_assert(ctx, s, stmt);

    result = Z3_solver_check(ctx, s);

    switch (result)
    {
        case Z3_L_FALSE: break;
        case Z3_L_UNDEF:
            printf("unknown: %s\n", Z3_solver_get_reason_unknown(ctx, s));
            break;
        case Z3_L_TRUE:
            m = Z3_solver_get_model(ctx, s);
            if (m) Z3_model_inc_ref(ctx, m);
            break;
    }

    if (m) {
        d2_model = Z3_model_get_const_interp(ctx, m, d2_decl);
        hi2      = (RSSKS_in_t) malloc(HASH_INPUT_SIZE);

        d_ast_to_hash_input(ctx, d2_model, hi2);

        h2 = RSSKS_in_to_header(hi2);
        
        free(hi2);
        Z3_model_dec_ref(ctx, m);
    }
    
    del_solver(ctx, s);

    return h2;
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

Z3_ast mk_rss_stmt(Z3_context ctx, Z3_ast key)
{
    Z3_sort    d_sort;
    Z3_ast     d1;
    Z3_ast     d2;
    Z3_ast     left_implies;
    Z3_ast     right_implies;
    Z3_ast     implies;

    Z3_app     vars[2];
    Z3_ast     forall;

    d_sort               = Z3_mk_bv_sort(ctx, HASH_INPUT_SIZE_BITS);
           
    d1                   = mk_var(ctx, "d1", d_sort);
    d2                   = mk_var(ctx, "d2", d_sort);

    left_implies          = mk_d_constraints(ctx, d1, d2);
    right_implies         = mk_hash_eq(ctx, key, d1, d2);
  
    implies               = Z3_mk_implies(ctx, left_implies, right_implies);

    vars[0]              = Z3_to_app(ctx, d1);
    vars[1]              = Z3_to_app(ctx, d2);
 
    forall               = Z3_mk_forall_const(ctx, 0, 2, vars, 0, 0, implies);

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

void pseudo_partial_maxsat(Z3_context ctx, Z3_solver s, Z3_ast key, RSSKS_key_t key_proposal)
{
    Z3_ast       key_constr[KEY_SIZE_BITS];

    bool         core[KEY_SIZE_BITS];
    unsigned     num_soft_cnstrs;
    unsigned     num_soft_cnstrs_new;
    unsigned     unsat_core_sz;

    for (int bit = 0; bit < KEY_SIZE_BITS; bit++)
        key_constr[bit] = mk_key_bit_const(ctx, key, KEY_SIZE_BITS - 1 - bit, BIT_FROM_KEY(bit, key_proposal));

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

void adjust_key_to_cnstrs(RSSKS_key_t k)
{
    Z3_context   ctx;
    Z3_solver    s;
    Z3_model     m;

    Z3_symbol    key_symbol;
    Z3_func_decl key_decl;
    Z3_sort      key_sort;
    Z3_ast       key, key_model;

    Z3_ast       stmt;

    ctx         = mk_context();
    s           = mk_solver(ctx);

    key_sort    = Z3_mk_bv_sort(ctx, KEY_SIZE_BITS);

    key_symbol  = Z3_mk_string_symbol(ctx, "k"); 
    key_decl    = Z3_mk_func_decl(ctx, key_symbol, 0, 0, key_sort);
    key         = Z3_mk_app(ctx, key_decl, 0, 0);

    stmt        = mk_rss_stmt(ctx, key);

    Z3_solver_assert(ctx, s, stmt);

    pseudo_partial_maxsat(ctx, s, key, k);

    m           = Z3_solver_get_model(ctx, s);
    key_model   = Z3_model_get_const_interp(ctx, m, key_decl);

    k_ast_to_rss_key(ctx, key_model, k);
    
    del_solver(ctx, s);
}

typedef struct {
    int *pid;
    int *rpipe;
    int *wpipe;
} comm_t;

int wp;

void alarm_handler(int sig)
{
    RSSKS_key_t key;

    zero_key(key);
    write(wp, key, KEY_SIZE);

    DEBUG_PLOG("terminated (timeout)\n");

    exit(0);
}

void worker()
{
    RSSKS_key_t key;

    DEBUG_PLOG("started\n");

    signal(SIGALRM, alarm_handler);
    alarm(SOLVER_TIMEOUT_SEC);

    rand_key(key);
    adjust_key_to_cnstrs(key);

    DEBUG_PLOG("testing key\n");

    if (!k_test_dist(key))
        zero_key(key);

    write(wp, key, KEY_SIZE);

    DEBUG_PLOG("terminated\n");

    exit(0);
}

void launch_worker(int p, comm_t comm)
{
    int pid;

    if (!(pid = fork())) 
    {
        wp = comm.wpipe[p];
        worker();
    }

    comm.pid[p] = pid;
}

void master(int np, comm_t comm, RSSKS_key_t key)
{
    int       wstatus;
    int       maxfd;
    fd_set    fds;

    for (int p = 0; p < np; p++) launch_worker(p, comm);
    
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
            if (FD_ISSET(comm.rpipe[p], &fds))
            {
                read(comm.rpipe[p], key, KEY_SIZE);

                waitpid(comm.pid[p], &wstatus, 0);
                comm.pid[p] = -1;

                if (is_zero_key(key))
                {
                    launch_worker(p, comm);
                    break;
                }

                for (p = 0; p < np; p++)
                {
                    if (comm.pid[p] == -1) continue;
                    
                    kill(comm.pid[p], SIGTERM);
                    wait(&wstatus);
                }

                return;
            }
        }
    }
}

void find_k(RSSKS_key_t k)
{
    int    nworkers;
    comm_t comm;

    nworkers = get_nprocs();

    comm.pid   = (int*) malloc(sizeof(int) * nworkers);
    comm.rpipe = (int*) malloc(sizeof(int) * nworkers);
    comm.wpipe = (int*) malloc(sizeof(int) * nworkers);

    for (int p = 0; p < nworkers; p++) {
        int pipefd[2];

        pipe(pipefd);

        comm.rpipe[p] = pipefd[0];
        comm.wpipe[p] = pipefd[1];
    }

    master(nworkers, comm, k);

    free(comm.pid);
    free(comm.rpipe);
    free(comm.wpipe);
}

void check_d_constraints(RSSKS_headers_t h1, RSSKS_headers_t h2)
{
    Z3_context ctx;
    Z3_solver  s;
    Z3_ast     d1, d2;

    Z3_sort    d_sort;
    Z3_ast     d1_const, d2_const;
    Z3_ast     d_constr;

    ctx           = mk_context();
    s             = mk_solver(ctx);

    d_sort       = Z3_mk_bv_sort(ctx, HASH_INPUT_SIZE_BITS);
     
    d1            = mk_var(ctx, "d1", d_sort);
    d2            = mk_var(ctx, "d2", d_sort);
  
    d1_const      = mk_d_const(ctx, d1, h1);
    d2_const      = mk_d_const(ctx, d2, h2);

    d_constr      = mk_d_constraints(ctx, d1, d2);

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