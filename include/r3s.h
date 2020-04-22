#ifndef __R3S_API_H__
#define __R3S_API_H__

/** @file */ 

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

/**
 * \typedef R3S_in_cfg_t
 * Used to infer if a given packet field is loaded.
 * \see R3S_pf_t
 */
typedef unsigned     R3S_in_cfg_t;

/**
 * \enum R3S_in_opt_t
 * Input options typically associated with certains NICs.
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_GENEVE_OAM
 * \todo Which packets?
 * 
 * - ::R3S_PF_VXLAN_UDP_OUTER
 * - ::R3S_PF_VXLAN_VNI
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_VXLAN_GPE_OAM
 * \todo Which packets?
 * 
 * - ::R3S_PF_VXLAN_UDP_OUTER
 * - ::R3S_PF_VXLAN_VNI
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV4_TCP
 * Configures RSS to accept non fragmented TCP/IPv4 packets.
 * - ::R3S_PF_IPV4_SRC
 * - ::R3S_PF_IPV4_DST
 * - ::R3S_PF_TCP_SRC
 * - ::R3S_PF_TCP_DST
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV4_UDP
 * Configures RSS to accept non fragmented UDP/IPv4 packets.
 * - ::R3S_PF_IPV4_SRC
 * - ::R3S_PF_IPV4_DST
 * - ::R3S_PF_UDP_SRC
 * - ::R3S_PF_UDP_DST
 *
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV4_SCTP
 * Configures RSS to accept non fragmented SCTP/IPv4 packets.
 * - ::R3S_PF_IPV4_SRC
 * - ::R3S_PF_IPV4_DST
 * - ::R3S_PF_SCTP_SRC
 * - ::R3S_PF_SCTP_DST
 * - ::R3S_PF_SCTP_V_TAG
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV4
 * Configures RSS to accept fragmented IPv4 packets.
 * - ::R3S_PF_IPV4_SRC
 * - ::R3S_PF_IPV4_DST
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV6_TCP
 * Configures RSS to accept non fragmented TCP/IPv6 packets.
 * - ::R3S_PF_IPV6_SRC
 * - ::R3S_PF_IPV6_DST
 * - ::R3S_PF_TCP_SRC
 * - ::R3S_PF_TCP_DST
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV6_UDP
 * Configures RSS to accept non fragmented UDP/IPv6 packets.
 * - ::R3S_PF_IPV6_SRC
 * - ::R3S_PF_IPV6_DST
 * - ::R3S_PF_UDP_SRC
 * - ::R3S_PF_UDP_DST
 *
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV6_SCTP
 * Configures RSS to accept non fragmented SCTP/IPv6 packets.
 * - ::R3S_PF_IPV6_SRC
 * - ::R3S_PF_IPV6_DST
 * - ::R3S_PF_SCTP_SRC
 * - ::R3S_PF_SCTP_DST
 * - ::R3S_PF_SCTP_V_TAG
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_NON_FRAG_IPV6
 * Configures RSS to accept fragmented IPv6 packets.
 * - ::R3S_PF_IPV6_SRC
 * - ::R3S_PF_IPV6_DST
 * 
 * \var R3S_in_opt_t::R3S_IN_OPT_ETHERTYPE
 * Configures RSS to accept *all* packets.
 * - ::R3S_PF_ETHERTYPE
 */
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

/**
 * \enum R3S_pf_t
 * Packet fields loaded into the RSS configuration, i.e.,
 * the packet fields that will be given to the hash function.
 * 
 * The order is important!
 * From top to bottom, if one field is enumerated first, then
 * it is placed first on the hash input.
 * 
 * Eg, if one configured the hash to accept ipv4 src and dst,
 * and tcp src and dst, then the hash input would be
 * { ipv4_src, ipv4_dst, tcp_src, tcp_dst }.
 * 
 * \var R3S_pf_t::R3S_PF_VXLAN_UDP_OUTER
 * UDP outer used in the VXLAN protocol.
 * 
 * \var R3S_pf_t::R3S_PF_VXLAN_VNI
 * VXLAN network identifier used in the VXLAN protocol.
 * 
 * \var R3S_pf_t::R3S_PF_IPV6_SRC
 * IPv6 source address.
 * 
 * \var R3S_pf_t::R3S_PF_IPV6_DST
 * IPv6 destination address.
 * 
 * \var R3S_pf_t::R3S_PF_IPV4_SRC
 * IPv4 source address.
 * 
 * \var R3S_pf_t::R3S_PF_IPV4_DST
 * IPv4 destination address.
 * 
 * \var R3S_pf_t::R3S_PF_TCP_SRC
 * TCP source port.
 * 
 * \var R3S_pf_t::R3S_PF_TCP_DST
 * TCP destination port.
 * 
 * \var R3S_pf_t::R3S_PF_UDP_SRC
 * UDP destination port.
 * 
 * \var R3S_pf_t::R3S_PF_UDP_DST
 * UDP destination port.
 * 
 * \var R3S_pf_t::R3S_PF_SCTP_SRC
 * SCTP source port.
 * 
 * \var R3S_pf_t::R3S_PF_SCTP_DST
 * SCTP destination port.
 * 
 * \var R3S_pf_t::R3S_PF_SCTP_V_TAG
 * SCTP verification tag.
 * 
 * \var R3S_pf_t::R3S_PF_ETHERTYPE
 * Layer 2 protocol.
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

/**
 * \enum R3S_status_t
 * Status code used as return values.
 * 
 * \var R3S_status_t::R3S_STATUS_SUCCESS
 * Operation finished successefully.
 *
 * \var R3S_status_t::R3S_STATUS_NO_SOLUTION
 * No solution was found.
 * 
 * \var R3S_status_t::R3S_STATUS_BAD_SOLUTION
 * A solution was found, but it doesn't fill the requirements.
 * 
 * \var R3S_status_t::R3S_STATUS_HAS_SOLUTION
 * Confirmation that a solution exists.
 * 
 * \var R3S_status_t::R3S_STATUS_PF_UNKNOWN
 * Unknown packet field.
 * \see R3S_pf_t
 * 
 * \var R3S_status_t::R3S_STATUS_PF_LOADED
 * Packet field loaded into configuration.
 * \see R3S_pf_t
 * \see R3S_cfg_t
 * 
 * \var R3S_status_t::R3S_STATUS_PF_NOT_LOADED
 * Packet field not loaded into configuration.
 * \see R3S_pf_t
 * \see R3S_cfg_t
 * 
 * \var R3S_status_t::R3S_STATUS_PF_INCOMPATIBLE
 * Packet field incompatible with the current configuration.
 * \see R3S_pf_t
 * \see R3S_cfg_t
 * 
 * \var R3S_status_t::R3S_STATUS_OPT_UNKNOWN
 * Unknown configuration option.
 * \see R3S_in_opt_t
 * \see R3S_cfg_t
 * 
 * \var R3S_status_t::R3S_STATUS_OPT_LOADED
 * Option loaded into configuration.
 * \see R3S_in_opt_t
 * \see R3S_cfg_t
 * 
 * \var R3S_status_t::R3S_STATUS_OPT_NOT_LOADED
 * Option not loaded into configuration.
 * \see R3S_in_opt_t
 * \see R3S_cfg_t
 * 
 * \var R3S_status_t::R3S_STATUS_INVALID_IOPT
 * Invalid option index.
 * This is typically returned if an used option index 
 * is bigger than the number of loaded options in a configuration.
 * \see R3S_in_opt_t
 * \see R3S_cfg_t
 * 
 * \var R3S_status_t::R3S_STATUS_FAILURE
 * Operation failed.
 * 
 */
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
    R3S_STATUS_OPT_LOADED,
    R3S_STATUS_OPT_NOT_LOADED,
    R3S_STATUS_INVALID_IOPT,
    
    R3S_STATUS_FAILURE
} R3S_status_t;

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
    R3S_in_cfg_t cfg;

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

/**
 * \struct R3S_loaded_in_opt_t
 * \brief Information regarding loaded option and consequently the associated
 * packet fields and the size of the hash input.
 * 
 * \var R3S_loaded_in_opt_t::opt
 * Loaded option.
 * 
 * \var R3S_loaded_in_opt_t::pfs
 * Hash input configuration, i.e., chosen packet fields associated
 * with this option.
 * 
 * \var R3S_loaded_in_opt_t::sz
 * Size of the hash input.
 */
typedef struct {
    R3S_in_opt_t opt;
    R3S_in_cfg_t pfs;
    unsigned     sz; 
} R3S_loaded_in_opt_t;

/**
 * \struct R3S_cfg_t
 * \brief R3S configuration used to store information useful
 * throughout the API.
 * 
 * \var R3S_cfg_t::loaded_opts
 * Options loaded in this configuration.
 * \see R3S_in_opt_t
 * 
 * \var R3S_cfg_t::n_loaded_opts
 * Number of loaded configurations. Stores the size of
 * the R3S_cfg_t::loaded_opts array.
 * 
 * \var R3S_cfg_t::n_procs
 * Number of processes to be used by the R3S_find_keys().
 * If this value is <= 0, then the number of processes
 * used will be equal to the number of available cores.
 * 
 * \var R3S_cfg_t::n_keys
 * Number of keys to take into consideration.
 * This is useful when there are constraints needed to be
 * considered between multiple NICs/ports in NICs.
 */
typedef struct {
    R3S_loaded_in_opt_t *loaded_opts;
    unsigned            n_loaded_opts;
    int                 n_procs;
    unsigned            n_keys;
} R3S_cfg_t;

/**
 * \brief Definition of the function used to represent constraints between packets.
 * 
 * \param cfg R3S configuration
 * \param iopt Index of the option 
 * \see R3S_find_keys()
 * 
 * \code
 * Z3_ast R3S_mk_symmetric_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2)
 * {
 *     R3S_status_t status;
 *     Z3_ast       p1_ipv4_src, p1_ipv4_dst;
 *     Z3_ast       p2_ipv4_src, p2_ipv4_dst;
 *     Z3_ast       and_args[2];
 *     
 *     status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p1, R3S_PF_IPV4_SRC, &p1_ipv4_src);
 *     if (status != R3S_STATUS_SUCCESS) return NULL;
 *     
 *     status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p1, R3S_PF_IPV4_DST, &p1_ipv4_dst);
 *     if (status != R3S_STATUS_SUCCESS) return NULL;
 *     
 *     status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p2, R3S_PF_IPV4_SRC, &p2_ipv4_src);
 *     if (status != R3S_STATUS_SUCCESS) return NULL;
 *     
 *     status = R3S_extract_pf_from_p(r3s_cfg, iopt, ctx, p2, R3S_PF_IPV4_DST, &p2_ipv4_dst);
 *     if (status != R3S_STATUS_SUCCESS) return NULL;
 *     
 *     and_args[0] = Z3_mk_eq(ctx, p1_ipv4_src, p2_ipv4_dst);
 *     and_args[1] = Z3_mk_eq(ctx, p1_ipv4_dst, p2_ipv4_src);
 *     
 *     return Z3_mk_and(ctx, 2, and_args);
 * }
 * \endcode
 */
typedef Z3_ast (*R3S_cnstrs_func)(R3S_cfg_t cfg,unsigned iopt,Z3_context,Z3_ast,Z3_ast);

typedef union {
    char key[KEY_SIZE * 3];
    char packet[700];
    char output[12];
    char status[40];
    char opt[35];
    char pf[30];
    char cfg[1000];
} R3S_string_t;

/**
 * \def R3S_status_to_string(_s)
 * Gets a status' string representation.
 */
#define R3S_status_to_string(_s)      __status_to_string((_s)).status

/**
 * \def R3S_key_to_string(_k)
 * Gets a key's string representation.
 */
#define R3S_key_to_string(_k)         __key_to_string((_k)).key

/**
 * \def R3S_packet_to_string(_p)
 * Gets a packet's string representation.
 */
#define R3S_packet_to_string(_p)      __packet_to_string((_p)).packet


#define R3S_hash_output_to_string(_o) __hash_output_to_string((_o)).output
#define R3S_in_opt_to_string(_opt)    __in_opt_to_string((_opt)).opt
#define R3S_pf_to_string(_pf)         __pf_to_string((_pf)).pf
#define R3S_cfg_to_string(_cfg)       __cfg_to_string((_cfg)).cfg

R3S_string_t __key_to_string(R3S_key_t k);
R3S_string_t __packet_to_string(R3S_packet_t p);
R3S_string_t __hash_output_to_string(R3S_out_t o);
R3S_string_t __status_to_string(R3S_status_t s);
R3S_string_t __in_opt_to_string(R3S_in_opt_t opt);
R3S_string_t __pf_to_string(R3S_pf_t pf);
R3S_string_t __cfg_to_string(R3S_cfg_t cfg);

/**
 * Initialize packet.
 * 
 * @param p Packet.
 */
void         R3S_packet_init(R3S_packet_t *p);

/**
 * Set packet field in packet.
 * 
 * @param cfg R3S configuration.
 * @param pf Type of packet field to store.
 * @param v Value of the packet field.
 * @param p Pointer to a packet field with the value set.
 * 
 * \return ::R3S_STATUS_SUCCESS
 * Packet *p* with the packet field *pf* set with value *v*.
 * 
 * \return ::R3S_STATUS_PF_INCOMPATIBLE
 * Packet field isn't compatible with the current configuration. Packet *p* unchanged.
 */
R3S_status_t R3S_packet_set_pf(R3S_cfg_t cfg, R3S_pf_t pf, R3S_bytes_t v, R3S_packet_t *p);
R3S_status_t R3S_packet_set_ethertype(R3S_cfg_t cfg, R3S_ethertype_t ethertype, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_ipv4(R3S_cfg_t cfg, R3S_ipv4_t src, R3S_ipv4_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_ipv6(R3S_cfg_t cfg, R3S_ipv6_t src, R3S_ipv6_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_tcp(R3S_cfg_t cfg, R3S_port_t src, R3S_port_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_udp(R3S_cfg_t cfg, R3S_port_t src, R3S_port_t dst, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_sctp(R3S_cfg_t cfg, R3S_port_t src, R3S_port_t dst, R3S_v_tag_t tag, out R3S_packet_t *p);
R3S_status_t R3S_packet_set_vxlan(R3S_cfg_t cfg, R3S_port_t outer, R3S_vni_t vni, out R3S_packet_t *p);

void         R3S_cfg_init(out R3S_cfg_t *cfg);
void         R3S_cfg_reset(out R3S_cfg_t *cfg);
void         R3S_cfg_delete(out R3S_cfg_t *cfg);
R3S_status_t R3S_cfg_load_in_opt(out R3S_cfg_t *cfg, R3S_in_opt_t in_opt);

R3S_status_t R3S_rand_packet(R3S_cfg_t cfg, out R3S_packet_t *p);
R3S_status_t R3S_hash(R3S_cfg_t cfg, R3S_key_t k, R3S_packet_t h, out R3S_out_t *result);

//void       R3S_check_p_cnstrs(R3S_cfg_t r3s_cfg, R3S_cnstrs_func mk_p_cnstrs, R3S_packet_t h1, R3S_packet_t h2);
R3S_status_t R3S_packet_from_cnstrs(R3S_cfg_t r3s_cfg, R3S_packet_t p, R3S_cnstrs_func mk_p_cnstrs, out R3S_packet_t *result);
R3S_status_t R3S_extract_pf_from_p(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p, R3S_pf_t pf, out Z3_ast *result);

/**
 * \brief Find keys that fit the given constraints, and insert them
 * in the parameter array \p keys.
 * 
 * The array \p keys must be allocated beforehand, and its size
 * is specified in the R3S_cfg_t input parameter, using
 * its R3S_cfg_t::n_keys field.
 * 
 * The constraints are represented using a function with the definition
 * R3S_cnstrs_func (check its documentation).
 * 
 * The first n = r3s_cfg.n_keys elements of \p mk_p_cnstrs relate to
 * constraints on each key independently. The remaining elements
 * correspond to the constraints related to combinations of keys.
 * 
 *  index  | keys         | description
 * ------- | -------------|-------------
 *    0    | k[0]         | Constraints for the first key
 *    1    | k[1]         | Constraints for the second key
 *   ...   | ...          | ...
 *   n-1   | k[n-1]       | Constraints for the last key
 *    n    | k[0], k[1]   | Constraints for the first and second keys
 *   n+1   | k[0], k[2]   | Constraints for the first and third keys
 *   ...   | ...          | ...
 *  2n-1   | k[0], k[n-1] | Constraints for the first and last keys
 *   2n    | k[1], k[2]   | Constraints for the second and third keys
 *   ...   | ...          | ...
 *   
 * 
 * Considering C(N,M) as combinations of N, M by M, the size of
 * \p mk_p_cnstrs must be at least N + C(N,2). This condition is
 * checked within this function, and it fails if it isn't met.
 * 
 * For example, using r3s_cfg.n_keys = 3:
 *   - mk_p_cnstrs[0]    => constraints on k[0]
 * 
 *   - mk_p_cnstrs[1]    => constraints on k[1]
 * 
 *   - mk_p_cnstrs[2]    => constraints on k[2]
 * 
 *   - mk_p_cnstrs[3]    => constraints between k[0] and k[1]
 * 
 *   - mk_p_cnstrs[4]    => constraints between k[0] and k[2]
 * 
 *   - mk_p_cnstrs[5]    => constraints between k[1] and k[2]
 * 
 * 
 * \param r3s_cfg R3S configuration containing the number of keys to be used.
 * \param mk_p_cnstrs Function used to represent constraints between packets.
 * \param keys Array of generated keys that respect the constraints given.
 * 
 * \see R3S_cnstrs_func
 * 
 * \return Status code.
 */
R3S_status_t R3S_find_keys(R3S_cfg_t r3s_cfg, R3S_cnstrs_func *mk_p_cnstrs, out R3S_key_t *keys);
/** 
 * @example no_solution.c
 * Consider the following scenario:
 * *find an RSS key that for every pair of IPv4 packets p1 and p2,
 * if the IP source address of the packet p1 is equal to itself (i.e.,
 * always), then these two packets must have the same hash value*.
 * 
 * This example shows that there is no key that satisfied these
 * constraints.
 */
/** 
 * @example src_ip.c
 * \todo explanation
 */
/** 
 * @example symmetric_ip_and_symmetric_session.c
 * \todo explanation
 */
/** 
 * @example symmetric_ip.c
 * \todo explanation
 */
/** 
 * @example symmetric_session_2_cnstrs_diff_pf.c
 * \todo explanation
 */
/** 
 * @example symmetric_session_2_cnstrs_eq_pf.c
 * \todo explanation
 */
/** 
 * @example symmetric_session.c
 * \todo explanation
 */

Z3_ast       R3S_mk_symmetric_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast       R3S_mk_symmetric_tcp_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast       R3S_mk_symmetric_tcp_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);

R3S_status_t R3S_parse_packets(R3S_cfg_t cfg, char* filename, out R3S_packet_t **packets, int *n_packets);

#endif