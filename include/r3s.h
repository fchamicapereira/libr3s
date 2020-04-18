#ifndef __R3S_API_H__
#define __R3S_API_H__

#include <stdint.h>
#include <stdbool.h>

#include <z3.h>

/*
 * Used for documentation. It's an explicit indication
 * that the parameter prefixed with this keyword is
 * going to be used as an output parameter.
*/
#define out

#define HASH_OUTPUT_SIZE        4
#define KEY_SIZE                52

#define HASH_OUTPUT_SIZE_BITS   (HASH_OUTPUT_SIZE * 8)
#define KEY_SIZE_BITS           (KEY_SIZE * 8)

typedef unsigned char  R3S_byte_t;
typedef R3S_byte_t*  R3S_bytes_t;

typedef R3S_bytes_t  R3S_in_t;
typedef R3S_byte_t   R3S_key_t[KEY_SIZE];
typedef uint32_t     R3S_out_t;

typedef R3S_byte_t   R3S_ipv6_t[16];
typedef R3S_byte_t   R3S_ipv4_t[4];
typedef R3S_byte_t   R3S_v_tag_t[4];  // verification tag (SCTP)
typedef R3S_byte_t   R3S_vni_t[3];    // unique identifier for the individual VXLAN segment
typedef R3S_byte_t   R3S_port_t[2];
typedef R3S_byte_t   R3S_ethertype_t[1];

typedef unsigned     R3S_in_cfg_t;

typedef enum {
    
    R3S_IN_OPT_GENEVE_OAM,
    R3S_IN_OPT_VXLAN_GPE_OAM,

    R3S_IN_OPT_NON_FRAG_IPV4_TCP,
    R3S_IN_OPT_NON_FRAG_IPV4_UDP,
    R3S_IN_OPT_NON_FRAG_IPV4_SCTP,
    R3S_IN_OPT_NON_FRAG_IPV4,
    R3S_IN_OPT_FRAG_IPV4,

    R3S_IN_OPT_NON_FRAG_IPV6_TCP,
    R3S_IN_OPT_NON_FRAG_IPV6_UDP,
    R3S_IN_OPT_NON_FRAG_IPV6_SCTP,
    R3S_IN_OPT_NON_FRAG_IPV6,
    R3S_IN_OPT_FRAG_IPV6,

    R3S_IN_OPT_ETHERTYPE,

} R3S_in_opt_t;

// This is used for R3S_in_opt_t iteration
#define R3S_FIRST_IN_OPT R3S_IN_OPT_GENEVE_OAM
#define R3S_LAST_IN_OPT  R3S_IN_OPT_ETHERTYPE

/*
 * The order is important!
 * From top to bottom, if one field is enumerated first, then
 * it is placed first on the hash input.
 * 
 * Eg, if one configured the hash to accept ipv4 src and dst,
 * and tcp src and dst, then the hash input would be
 * { ipv4_src, ipv4_dst, tcp_src, tcp_dst }.
 */
typedef enum {

    R3S_PF_VXLAN_UDP_OUTER,
    R3S_PF_VXLAN_VNI,

    R3S_PF_IPV6_SRC,
    R3S_PF_IPV6_DST,

    R3S_PF_IPV4_SRC,
    R3S_PF_IPV4_DST,

    R3S_PF_TCP_SRC,
    R3S_PF_TCP_DST,

    R3S_PF_UDP_SRC,
    R3S_PF_UDP_DST,

    R3S_PF_SCTP_SRC,
    R3S_PF_SCTP_DST,
    R3S_PF_SCTP_V_TAG,

    R3S_PF_ETHERTYPE,

} R3S_pf_t;

// This is used for R3S_pf_t iteration
#define R3S_FIRST_PF R3S_PF_VXLAN_UDP_OUTER
#define R3S_LAST_PF  R3S_PF_ETHERTYPE

typedef enum {
    R3S_STATUS_SUCCESS,
    R3S_STATUS_NO_SOLUTION,
    R3S_STATUS_BAD_SOLUTION,
    R3S_STATUS_HAS_SOLUTION,
    
    R3S_STATUS_PF_UNKNOWN,
    R3S_STATUS_PF_LOADED,
    R3S_STATUS_PF_NOT_LOADED,
    R3S_STATUS_PF_INCOMPATIBLE,

    R3S_STATUS_OPT_UNKNOWN,
    
    R3S_STATUS_FAILURE
} R3S_status_t;

typedef unsigned R3S_packet_cfg_t;

typedef struct {
    R3S_ipv4_t src;
    R3S_ipv4_t dst;
} R3S_h_ipv4_t;

typedef struct {
    R3S_ipv6_t src;
    R3S_ipv6_t dst;
} R3S_h_ipv6_t;

typedef struct {
    R3S_port_t src;
    R3S_port_t dst;
} R3S_h_tcp_t;

typedef struct {
    R3S_port_t src;
    R3S_port_t dst;
} R3S_h_udp_t;

typedef struct {
    R3S_port_t  src;
    R3S_port_t  dst;
    R3S_v_tag_t tag;
} R3S_h_sctp_t;

typedef struct {
    R3S_port_t outer;
    R3S_vni_t  vni;
} R3S_h_vxlan_t;

typedef struct {
    R3S_packet_cfg_t cfg;

    union {
        R3S_ethertype_t ethertype;
    };

    union {
        R3S_h_ipv4_t ipv4;
        R3S_h_ipv6_t ipv6;
    };

    union {
        R3S_h_tcp_t  tcp;
        R3S_h_udp_t  udp;
        R3S_h_sctp_t sctp;
    };

    union {
        R3S_h_vxlan_t vxlan;
    };

} R3S_packet_t;

typedef struct {
    R3S_in_opt_t opt; /* Configuration option */
    R3S_in_cfg_t pfs; /* Hash input configuration (chosen packet fields) */
    unsigned       sz;  /* Size of the hash input */
} R3S_loaded_in_opt_t;

typedef struct {
    R3S_loaded_in_opt_t *loaded_opts;
    unsigned              n_loaded_opts;

    /*
     * Use #cores in find_k.
     * If cores <= 0, then find_k will use *all* cores.
    */
    int n_procs;

    /*
     * Number of keys to generate.
     * This is useful when there are constraints needed to be
     * considered between multiple NICs/ports in NICs.
    */
    unsigned n_keys;

} R3S_cfg_t;

typedef Z3_ast (*R3S_cnstrs_func)(R3S_cfg_t,unsigned,Z3_context,Z3_ast,Z3_ast);

typedef union {
    char key[KEY_SIZE * 3];
    char packet[700];
    char output[12];
    char status[40];
    char opt[35];
    char pf[30];
    char cfg[1000];
} R3S_string_t;

#define R3S_status_to_string(s)       __status_to_string((s)).status
#define R3S_key_to_string(k)          __key_to_string((k)).key
#define R3S_packet_to_string(p)       __packet_to_string((p)).packet
#define R3S_hash_output_to_string(o)  __hash_output_to_string((o)).output
#define R3S_in_opt_to_string(opt)     __in_opt_to_string((opt)).opt
#define R3S_pf_to_string(pf)          __pf_to_string((pf)).pf
#define R3S_cfg_to_string(cfg)        __cfg_to_string((cfg)).cfg

R3S_string_t __key_to_string(R3S_key_t k);
R3S_string_t __packet_to_string(R3S_packet_t p);
R3S_string_t __hash_output_to_string(R3S_out_t o);
R3S_string_t __status_to_string(R3S_status_t s);
R3S_string_t __in_opt_to_string(R3S_in_opt_t opt);
R3S_string_t __pf_to_string(R3S_pf_t pf);
R3S_string_t __cfg_to_string(R3S_cfg_t cfg);

void         R3S_packet_init(R3S_packet_t *p);
R3S_status_t R3S_packet_set_pf(R3S_pf_t pf, R3S_bytes_t v, R3S_packet_t *p);
R3S_status_t R3S_packet_set_ethertype(R3S_ethertype_t ethertype, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_ipv4(R3S_ipv4_t src, R3S_ipv4_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_ipv6(R3S_ipv6_t src, R3S_ipv6_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_tcp(R3S_port_t src, R3S_port_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_udp(R3S_port_t src, R3S_port_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_sctp(R3S_port_t src, R3S_port_t dst, R3S_v_tag_t tag, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_vxlan(R3S_port_t outer, R3S_vni_t vni, out R3S_packet_t *p);

void         R3S_cfg_init(out R3S_cfg_t *cfg);
void         R3S_cfg_reset(out R3S_cfg_t *cfg);
void         R3S_cfg_delete(out R3S_cfg_t *cfg);
R3S_status_t R3S_cfg_load_in_opt(out R3S_cfg_t *cfg, R3S_in_opt_t in_opt);

R3S_status_t R3S_rand_packet(R3S_cfg_t cfg, out R3S_packet_t *p);
R3S_status_t R3S_hash(R3S_cfg_t cfg, R3S_key_t k, R3S_packet_t h, out R3S_out_t *result);

//void       R3S_check_p_cnstrs(R3S_cfg_t r3s_cfg, R3S_cnstrs_func mk_p_cnstrs, R3S_packet_t h1, R3S_packet_t h2);
R3S_status_t R3S_packet_from_cnstrs(R3S_cfg_t r3s_cfg, R3S_packet_t p, R3S_cnstrs_func mk_p_cnstrs, out R3S_packet_t *result);
R3S_status_t R3S_extract_pf_from_p(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p, R3S_pf_t pf, out Z3_ast *result);

/*
 * Find keys that fit the given constraints, and insert them
 * in the parameter array R3S_key_t *keys.
 * 
 * The array *keys must be allocated beforehand, and its size
 * is specified in the R3S_cfg_t r3s_cfg input parameter, using
 * its n_keys field.
 * 
 * The constraints are represented using a function with the definition
 * R3S_cnstrs_func (check its documentation).
 * 
 * The first N = r3s_cfg.n_keys elements of mk_p_cnstrs relate to
 * constraints on each key independently, i.e.:
 * 
 *   mk_p_cnstrs[0]    => constraints on k[0],
 *   mk_p_cnstrs[1]    => constraints on k[1],
 *   ...
 *   mk_p_cnstrs[N-1]  => constraints on k[N-1]
 * 
 * Next, we have the constraints related to combinations of keys:
 * 
 *   mk_p_cnstrs[N]    => constraints between k[0] and k[1]
 *   mk_p_cnstrs[N+1]  => constraints between k[0] and k[2]
 *   ...
 *   mk_p_cnstrs[2N-1] => constraints between k[0] and k[N-1]
 *   mk_p_cnstrs[2N]   => constraints between k[1] and k[2]
 *   mk_p_cnstrs[2N+1] => constraints between k[1] and k[3]
 *   etc.
 * 
 * Considering C(N,M) as combinations of N, M by M, the size of
 * mk_p_cnstrs must be at least N + C(N,2). This condition is
 * checked within this function, and it fails if it isn't met.
 * 
 * For example, using cssks_cfg.n_keys = 3:
 *   mk_p_cnstrs[0]    => constraints on k[0]
 *   mk_p_cnstrs[1]    => constraints on k[1]
 *   mk_p_cnstrs[2]    => constraints on k[2]
 *   mk_p_cnstrs[3]    => constraints between k[0] and k[1]
 *   mk_p_cnstrs[4]    => constraints between k[0] and k[2]
 *   mk_p_cnstrs[5]    => constraints between k[1] and k[2]
 *  
*/
R3S_status_t R3S_find_keys(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs, out R3S_key_t *keys);

Z3_ast       R3S_mk_symmetric_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast       R3S_mk_symmetric_tcp_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast       R3S_mk_symmetric_tcp_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);

#endif