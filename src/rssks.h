#ifndef __RSSKS_H__
#define __RSSKS_H__

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

typedef unsigned char  RSSKS_byte_t;
typedef RSSKS_byte_t*  RSSKS_bytes_t;

typedef RSSKS_bytes_t  RSSKS_in_t;
typedef RSSKS_byte_t   RSSKS_key_t[KEY_SIZE];
typedef uint32_t       RSSKS_out_t;

typedef RSSKS_byte_t   RSSKS_ipv6_t[16];
typedef RSSKS_byte_t   RSSKS_ipv4_t[4];
typedef RSSKS_byte_t   RSSKS_v_tag_t[4];  // verification tag (SCTP)
typedef RSSKS_byte_t   RSSKS_vni_t[3];    // unique identifier for the individual VXLAN segment
typedef RSSKS_byte_t   RSSKS_port_t[2];
typedef RSSKS_byte_t   RSSKS_ethertype_t[1];

typedef unsigned       RSSKS_in_cfg_t;

typedef enum {
    
    RSSKS_IN_OPT_GENEVE_OAM,
    RSSKS_IN_OPT_VXLAN_GPE_OAM,

    RSSKS_IN_OPT_NON_FRAG_IPV4_TCP,
    RSSKS_IN_OPT_NON_FRAG_IPV4_UDP,
    RSSKS_IN_OPT_NON_FRAG_IPV4_SCTP,
    RSSKS_IN_OPT_NON_FRAG_IPV4,
    RSSKS_IN_OPT_FRAG_IPV4,

    RSSKS_IN_OPT_NON_FRAG_IPV6_TCP,
    RSSKS_IN_OPT_NON_FRAG_IPV6_UDP,
    RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP,
    RSSKS_IN_OPT_NON_FRAG_IPV6,
    RSSKS_IN_OPT_FRAG_IPV6,

    RSSKS_IN_OPT_ETHERTYPE,

} RSSKS_in_opt_t;

// This is used for RSSKS_in_opt_t iteration
#define RSSKS_FIRST_IN_OPT RSSKS_IN_OPT_GENEVE_OAM
#define RSSKS_LAST_IN_OPT  RSSKS_IN_OPT_ETHERTYPE

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

    RSSKS_PF_VXLAN_UDP_OUTER,
    RSSKS_PF_VXLAN_VNI,

    RSSKS_PF_IPV6_SRC,
    RSSKS_PF_IPV6_DST,

    RSSKS_PF_IPV4_SRC,
    RSSKS_PF_IPV4_DST,

    RSSKS_PF_TCP_SRC,
    RSSKS_PF_TCP_DST,

    RSSKS_PF_UDP_SRC,
    RSSKS_PF_UDP_DST,

    RSSKS_PF_SCTP_SRC,
    RSSKS_PF_SCTP_DST,
    RSSKS_PF_SCTP_V_TAG,

    RSSKS_PF_ETHERTYPE,

} RSSKS_pf_t;

// This is used for RSSKS_pf_t iteration
#define RSSKS_FIRST_PF RSSKS_PF_VXLAN_UDP_OUTER
#define RSSKS_LAST_PF  RSSKS_PF_ETHERTYPE

typedef enum {
    RSSKS_STATUS_SUCCESS,
    RSSKS_STATUS_NO_SOLUTION,
    RSSKS_STATUS_BAD_SOLUTION,
    RSSKS_STATUS_HAS_SOLUTION,
    
    RSSKS_STATUS_PF_UNKNOWN,
    RSSKS_STATUS_PF_LOADED,
    RSSKS_STATUS_PF_NOT_LOADED,
    RSSKS_STATUS_PF_INCOMPATIBLE,

    RSSKS_STATUS_OPT_UNKNOWN,
    
    RSSKS_STATUS_FAILURE
} RSSKS_status_t;

typedef unsigned RSSKS_packet_cfg_t;

typedef struct {
    RSSKS_ipv4_t src;
    RSSKS_ipv4_t dst;
} RSSKS_h_ipv4_t;

typedef struct {
    RSSKS_ipv6_t src;
    RSSKS_ipv6_t dst;
} RSSKS_h_ipv6_t;

typedef struct {
    RSSKS_port_t src;
    RSSKS_port_t dst;
} RSSKS_h_tcp_t;

typedef struct {
    RSSKS_port_t src;
    RSSKS_port_t dst;
} RSSKS_h_udp_t;

typedef struct {
    RSSKS_port_t  src;
    RSSKS_port_t  dst;
    RSSKS_v_tag_t tag;
} RSSKS_h_sctp_t;

typedef struct {
    RSSKS_port_t outer;
    RSSKS_vni_t  vni;
} RSSKS_h_vxlan_t;

typedef struct {
    RSSKS_packet_cfg_t cfg;

    union {
        RSSKS_ethertype_t ethertype;
    };

    union {
        RSSKS_h_ipv4_t ipv4;
        RSSKS_h_ipv6_t ipv6;
    };

    union {
        RSSKS_h_tcp_t  tcp;
        RSSKS_h_udp_t  udp;
        RSSKS_h_sctp_t sctp;
    };

    union {
        RSSKS_h_vxlan_t vxlan;
    };

} RSSKS_packet_t;

typedef struct {
    RSSKS_in_opt_t opt; /* Configuration option */
    RSSKS_in_cfg_t pfs; /* Hash input configuration (chosen packet fields) */
    unsigned       sz;  /* Size of the hash input */
} RSSKS_loaded_in_opt_t;

typedef struct {
    RSSKS_loaded_in_opt_t *loaded_opts;
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

} RSSKS_cfg_t;

typedef Z3_ast (*RSSKS_cnstrs_func)(RSSKS_cfg_t,unsigned,Z3_context,Z3_ast,Z3_ast);

typedef union {
    char key[KEY_SIZE * 3];
    char packet[700];
    char output[12];
    char status[40];
    char opt[35];
    char pf[30];
    char cfg[1000];
} RSSKS_string_t;

#define RSSKS_status_to_string(s)       __status_to_string((s)).status
#define RSSKS_key_to_string(k)          __key_to_string((k)).key
#define RSSKS_packet_to_string(p)       __packet_to_string((p)).packet
#define RSSKS_hash_output_to_string(o)  __hash_output_to_string((o)).output
#define RSSKS_in_opt_to_string(opt)     __in_opt_to_string((opt)).opt
#define RSSKS_pf_to_string(pf)          __pf_to_string((pf)).pf
#define RSSKS_cfg_to_string(cfg)        __cfg_to_string((cfg)).cfg

RSSKS_string_t __key_to_string(RSSKS_key_t k);
RSSKS_string_t __packet_to_string(RSSKS_packet_t p);
RSSKS_string_t __hash_output_to_string(RSSKS_out_t o);
RSSKS_string_t __status_to_string(RSSKS_status_t s);
RSSKS_string_t __in_opt_to_string(RSSKS_in_opt_t opt);
RSSKS_string_t __pf_to_string(RSSKS_pf_t pf);
RSSKS_string_t __cfg_to_string(RSSKS_cfg_t cfg);

void           RSSKS_packet_init(RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_pf(RSSKS_pf_t pf, RSSKS_bytes_t v, RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_ethertype(RSSKS_ethertype_t ethertype, out RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_ipv4(RSSKS_ipv4_t src, RSSKS_ipv4_t dst, out RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_ipv6(RSSKS_ipv6_t src, RSSKS_ipv6_t dst, out RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_tcp(RSSKS_port_t src, RSSKS_port_t dst, out RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_udp(RSSKS_port_t src, RSSKS_port_t dst, out RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_sctp(RSSKS_port_t src, RSSKS_port_t dst, RSSKS_v_tag_t tag, out RSSKS_packet_t *p);
RSSKS_status_t RSSKS_packet_set_vxlan(RSSKS_port_t outer, RSSKS_vni_t vni, out RSSKS_packet_t *p);

void           RSSKS_cfg_init(out RSSKS_cfg_t *cfg);
void           RSSKS_cfg_reset(out RSSKS_cfg_t *cfg);
void           RSSKS_cfg_delete(out RSSKS_cfg_t *cfg);
RSSKS_status_t RSSKS_cfg_load_in_opt(out RSSKS_cfg_t *cfg, RSSKS_in_opt_t in_opt);

RSSKS_status_t RSSKS_rand_packet(RSSKS_cfg_t cfg, out RSSKS_packet_t *p);
RSSKS_status_t RSSKS_hash(RSSKS_cfg_t cfg, RSSKS_key_t k, RSSKS_packet_t h, out RSSKS_out_t *result);

//void           RSSKS_check_p_cnstrs(RSSKS_cfg_t rssks_cfg, RSSKS_cnstrs_func mk_p_cnstrs, RSSKS_packet_t h1, RSSKS_packet_t h2);
RSSKS_status_t RSSKS_packet_from_cnstrs(RSSKS_cfg_t rssks_cfg, RSSKS_packet_t h, RSSKS_cnstrs_func mk_p_cnstrs, out RSSKS_packet_t *result);
RSSKS_status_t RSSKS_extract_pf_from_p(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast d, RSSKS_pf_t pf, out Z3_ast *result);

/*
 * Find keys that fit the given constraints, and insert them
 * in the parameter array RSSKS_key_t *keys.
 * 
 * The array *keys must be allocated beforehand, and its size
 * is specified in the RSSKS_cfg_t rssks_cfg input parameter, using
 * its n_keys field.
 * 
 * The constraints are represented using a function with the definition
 * RSSKS_cnstrs_func (check its documentation).
 * 
 * The first N = rssks_cfg.n_keys elements of mk_p_cnstrs relate to
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
RSSKS_status_t RSSKS_find_keys(RSSKS_cfg_t rssks_cfg, RSSKS_cnstrs_func *mk_p_cnstrs, out RSSKS_key_t *keys);

Z3_ast RSSKS_mk_symmetric_ip_cnstr(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast RSSKS_mk_symmetric_tcp_cnstr(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast RSSKS_mk_symmetric_tcp_ip_cnstr(RSSKS_cfg_t rssks_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);

#endif