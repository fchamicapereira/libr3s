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

    RSSKS_IN_OPT_L2_TYPE,

} RSSKS_in_opt_t;

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

    RSSKS_PF_IPV6_SRC,
    RSSKS_PF_IPV6_DST,

    RSSKS_PF_IPV4_SRC,
    RSSKS_PF_IPV4_DST,

    RSSKS_PF_UDP_OUTER,
    RSSKS_PF_VNI,

    RSSKS_PF_TCP_SRC,
    RSSKS_PF_TCP_DST,

    RSSKS_PF_UDP_SRC,
    RSSKS_PF_UDP_DST,

    RSSKS_PF_SCTP_SRC,
    RSSKS_PF_SCTP_DST,
    RSSKS_PF_SCTP_V_TAG,

    RSSKS_PF_L2_TYPE,

} RSSKS_pf_t;

// This is used for RSSKS_pf_t iteration
#define RSSKS_FIRST_PF RSSKS_PF_IPV6_SRC
#define RSSKS_LAST_PF  RSSKS_PF_L2_TYPE

typedef enum {
    RSSKS_STATUS_SUCCESS,
    RSSKS_STATUS_NO_SOLUTION,
    
    RSSKS_STATUS_PF_UNKNOWN,
    RSSKS_STATUS_PF_ALREADY_LOADED,
    RSSKS_STATUS_PF_NOT_LOADED,
    RSSKS_STATUS_PF_INCOMPATIBLE,

    RSSKS_STATUS_OPT_UNKNOWN,
    
    RSSKS_STATUS_FAILURE
} RSSKS_status_t;

typedef struct {
    RSSKS_port_t  udp_outer;
    RSSKS_vni_t   vni;

    RSSKS_ipv4_t  ipv4_src;
    RSSKS_ipv4_t  ipv4_dst;

    RSSKS_ipv6_t  ipv6_src;
    RSSKS_ipv6_t  ipv6_dst;

    RSSKS_port_t  tcp_src;
    RSSKS_port_t  tcp_dst;

    RSSKS_port_t  udp_src;
    RSSKS_port_t  udp_dst;

    RSSKS_port_t  sctp_src;
    RSSKS_port_t  sctp_dst;
    RSSKS_v_tag_t sctp_v_tag; // sctp verification tag

    // TODO: missing L2 ethertype
} RSSKS_headers_t;

typedef struct {
    RSSKS_in_cfg_t in_cfg;
    unsigned       in_sz;

    /*
     * Use #cores in find_k.
     * If cores <= 0, then find_k will use *all* cores.
    */
    int            n_cores;

    /*
     * Number of keys to generate.
     * This is useful when there are constraints needed to be
     * considered between multiple NICs/ports in NICs.
    */
    unsigned       n_keys;

} RSSKS_cfg_t;

typedef Z3_ast (*RSSKS_cnstrs_func)(RSSKS_cfg_t,Z3_context,Z3_ast,Z3_ast);

void            RSSKS_cfg_init(out RSSKS_cfg_t *cfg);
RSSKS_status_t  RSSKS_cfg_load_in_opt(RSSKS_cfg_t *cfg, RSSKS_in_opt_t in_opt);
RSSKS_status_t  RSSKS_cfg_load_pf(RSSKS_cfg_t *cfg, RSSKS_pf_t pf);
RSSKS_status_t  RSSKS_cfg_check_pf(RSSKS_cfg_t cfg, RSSKS_pf_t pf);

RSSKS_status_t  RSSKS_rand_headers(RSSKS_cfg_t cfg, out RSSKS_headers_t *h);
RSSKS_status_t  RSSKS_hash(RSSKS_cfg_t cfg, RSSKS_key_t k, RSSKS_headers_t h, out RSSKS_out_t *output);

void            RSSKS_check_d_cnstrs(RSSKS_cfg_t rssks_cfg, RSSKS_cnstrs_func  mk_d_cnstrs, RSSKS_headers_t h1, RSSKS_headers_t h2);
RSSKS_status_t  RSSKS_headers_from_cnstrs(RSSKS_cfg_t rssks_cfg, RSSKS_headers_t h, RSSKS_cnstrs_func  mk_d_cnstrs, out RSSKS_headers_t *output);
RSSKS_status_t  RSSKS_extract_pf_from_d(RSSKS_cfg_t rssks_cfg, Z3_context ctx, Z3_ast d, RSSKS_pf_t pf, out Z3_ast *output);

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
 * The first N = rssks_cfg.n_keys elements of mk_d_cnstrs relate to
 * constraints on each key independently, i.e.:
 * 
 *   mk_d_cnstrs[0]    => constraints on k[0],
 *   mk_d_cnstrs[1]    => constraints on k[1],
 *   ...
 *   mk_d_cnstrs[N-1]  => constraints on k[N-1]
 * 
 * Next, we have the constraints related to combinations of keys:
 * 
 *   mk_d_cnstrs[N]    => constraints between k[0] and k[1]
 *   mk_d_cnstrs[N+1]  => constraints between k[0] and k[2]
 *   ...
 *   mk_d_cnstrs[2N-1] => constraints between k[0] and k[N-1]
 *   mk_d_cnstrs[2N]   => constraints between k[1] and k[2]
 *   mk_d_cnstrs[2N+1] => constraints between k[1] and k[3]
 *   etc.
 * 
 * Considering C(N,M) as combinations of N, M by M, the size of
 * mk_d_cnstrs must be at least N + C(N,2). This condition is
 * checked within this function, and it fails if it isn't met.
 * 
 * For example, using cssks_cfg.n_keys = 3:
 *   mk_d_cnstrs[0]    => constraints on k[0]
 *   mk_d_cnstrs[1]    => constraints on k[1]
 *   mk_d_cnstrs[2]    => constraints on k[2]
 *   mk_d_cnstrs[3]    => constraints between k[0] and k[1]
 *   mk_d_cnstrs[4]    => constraints between k[0] and k[2]
 *   mk_d_cnstrs[5]    => constraints between k[1] and k[2]
 *  
*/
void            RSSKS_find_keys(RSSKS_cfg_t rssks_cfg, RSSKS_cnstrs_func *mk_d_cnstrs, out RSSKS_key_t *keys);

void            RSSKS_print_key(RSSKS_key_t k);
void            RSSKS_print_headers(RSSKS_cfg_t cfg, RSSKS_headers_t headers);
void            RSSKS_print_hash_output(RSSKS_out_t output);

#endif