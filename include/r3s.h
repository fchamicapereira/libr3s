#ifndef __R3S_API_H__
#define __R3S_API_H__

/** \file */ 

#include <stdint.h>
#include <stdbool.h>

#include <z3.h>

/**
 * \brief Used for documentation.
 * It's an explicit indication that the parameter
 * prefixed with this keyword is going to be used
 * as an output parameter.
*/
#define out

//! \brief RSS hash output in bytes
#define HASH_OUTPUT_SIZE        4

//! \brief RSS key size in bytes
#define KEY_SIZE        52

//! \brief RSS hash output size in bits
#define HASH_OUTPUT_SIZE_BITS   (HASH_OUTPUT_SIZE * 8)

//! \brief RSS key size in bits
#define KEY_SIZE_BITS   (KEY_SIZE * 8)

//! \brief Byte used all over this library.
typedef unsigned char R3S_byte_t;

//! \brief Array of bytes type.
typedef R3S_byte_t* R3S_bytes_t;

//! \brief RSS hash input type.
typedef R3S_bytes_t R3S_in_t;

//! \brief RSS key type.
typedef R3S_byte_t R3S_key_t[KEY_SIZE];

//! \brief RSS hash output type.
typedef uint32_t R3S_out_t;

//! \brief IPv6 packet field type.
typedef R3S_byte_t R3S_ipv6_t[16];

//! \brief IPv4 packet field type.
typedef R3S_byte_t R3S_ipv4_t[4];

//! \brief SCTP verification tag packet field type.
typedef R3S_byte_t R3S_v_tag_t[4];

//! \brief VXLAN segment's network identifier type.
typedef R3S_byte_t R3S_vni_t[3];

//! \brief L4 port type.
typedef R3S_byte_t R3S_port_t[2];

//! \brief L2 protocol type.
typedef R3S_byte_t R3S_ethertype_t[1];

/**
 * \typedef R3S_in_cfg_t
 * Used to infer if a given packet field is loaded.
 * \see R3S_pf_t
 */
typedef unsigned R3S_in_cfg_t;

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

// Undocumented and not really important
#ifndef DOXYGEN_SHOULD_SKIP_THIS
    #define R3S_FIRST_PF R3S_PF_VXLAN_UDP_OUTER
    #define R3S_LAST_PF  R3S_PF_ETHERTYPE

    #define R3S_FIRST_IN_OPT R3S_IN_OPT_GENEVE_OAM
    #define R3S_LAST_IN_OPT  R3S_IN_OPT_ETHERTYPE
#endif /* DOXYGEN_SHOULD_SKIP_THIS */

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

/**
 * \struct R3S_h_ipv4_t
 * \brief IPv4 header.
 * \see R3S_packet_t
 * 
 * \var R3S_h_ipv4_t::src
 * Source address.
 * 
 * \var R3S_h_ipv4_t::dst
 * Destination address.
 */
typedef struct {
    R3S_ipv4_t src;
    R3S_ipv4_t dst;
} R3S_h_ipv4_t;

/**
 * \struct R3S_h_ipv6_t
 * \brief IPv6 header.
 * \see R3S_packet_t
 * 
 * \var R3S_h_ipv6_t::src
 * Source address.
 * 
 * \var R3S_h_ipv6_t::dst
 * Destination address.
 */
typedef struct {
    R3S_ipv6_t src;
    R3S_ipv6_t dst;
} R3S_h_ipv6_t;

/**
 * \struct R3S_h_tcp_t
 * \brief TCP header.
 * \see R3S_packet_t
 * 
 * \var R3S_h_tcp_t::src
 * Source port.
 * 
 * \var R3S_h_tcp_t::dst
 * Destination port.
 */
typedef struct {
    R3S_port_t src;
    R3S_port_t dst;
} R3S_h_tcp_t;

/**
 * \struct R3S_h_udp_t
 * \brief UDP header.
 * \see R3S_packet_t
 * 
 * \var R3S_h_udp_t::src
 * Source port.
 * 
 * \var R3S_h_udp_t::dst
 * Destination port.
 */
typedef struct {
    R3S_port_t src;
    R3S_port_t dst;
} R3S_h_udp_t;

/**
 * \struct R3S_h_sctp_t
 * \brief SCTP header.
 * \see R3S_packet_t
 * 
 * \var R3S_h_sctp_t::src
 * Source port.
 * 
 * \var R3S_h_sctp_t::dst
 * Destination port.
 * 
 * \var R3S_h_sctp_t::tag
 * Verification tag.
 */
typedef struct {
    R3S_port_t  src;
    R3S_port_t  dst;
    R3S_v_tag_t tag;
} R3S_h_sctp_t;

/**
 * \struct R3S_h_vxlan_t
 * \brief VXLAN header.
 * \see R3S_packet_t
 * 
 * \var R3S_h_vxlan_t::outer
 * Outer UDP port.
 * 
 * \var R3S_h_vxlan_t::vni
 * VXLAN network identifier.
 */
typedef struct {
    R3S_port_t outer;
    R3S_vni_t  vni;
} R3S_h_vxlan_t;

/**
 * \struct R3S_packet_t
 * \brief Packet associated with an RSS configuration.
 * 
 * \var R3S_packet_t::cfg
 * Packet field configuration, i.e., which packet fields
 * are being used.
 * 
 * \var R3S_packet_t::ethertype
 * L2 protocol.
 * 
 * \var R3S_packet_t::ipv4
 * IPv4 header
 * 
 * \var R3S_packet_t::ipv6
 * IPv6 header
 * 
 * \var R3S_packet_t::tcp
 * TCP header
 * 
 * \var R3S_packet_t::udp
 * UDP header
 * 
 * \var R3S_packet_t::sctp
 * SCTP header
 * 
 * \var R3S_packet_t::vxlan
 * VXLAN header
 */
typedef struct {
    R3S_in_cfg_t cfg;

    union {
        //! \unnamed{union}
        R3S_ethertype_t ethertype;
    };

    union {
        //! \unnamed{union}
        R3S_h_ipv4_t ipv4;
        
        //! \unnamed{union}
        R3S_h_ipv6_t ipv6;
    };

    union {
        //! \unnamed{union}
        R3S_h_tcp_t  tcp;
        
        //! \unnamed{union}
        R3S_h_udp_t  udp;

        //! \unnamed{union}
        R3S_h_sctp_t sctp;
    };

    union {
        //! \unnamed{union}
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
    unsigned    n_loaded_opts;
    int         n_procs;
    unsigned    n_keys;
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


/**
 * \struct R3S_core_stats_t
 * \brief Number of packets redirected to a single core, and its percentage.
 * 
 * \var R3S_core_stats_t::n_packets
 * Total number of packets redirected to a single core.
 * 
 * \var R3S_core_stats_t::percentage
 * Percentage of the total number of packets that was redirected to a single core.
 */
typedef struct {
    unsigned n_packets;
    float percentage;
} R3S_core_stats_t;

/**
 * \struct R3S_key_stats_t
 * \brief Key statistics.
 * 
 * \var R3S_key_stats_t::cfg
 * R3S configuration.
 * 
 * \var R3S_key_stats_t::core_stats
 * Statistics related to each core.
 * 
 * \var R3S_key_stats_t::n_cores
 * Total number of cores to be considered.
 * 
 * \var R3S_key_stats_t::avg_dist
 * Average distribution of packets per core (in percentage).
 * 
 * \var R3S_key_stats_t::std_dev
 * Standard deviation of the distribution of packets per core (in percentage).
 */
typedef struct {
    R3S_cfg_t cfg;
    
    R3S_core_stats_t *core_stats;
    unsigned n_cores;

    float avg_dist;
    float std_dev;

} R3S_key_stats_t;



/**********************************************//**
 * \defgroup StringAPI String
 * Typical toString functions.
 * @{
 *************************************************/


/**
 * \brief R3S boilerplate string.
 * \note There is no need to worry about freeing memory when using this.
 */
typedef char* R3S_string_t;

/**
 * Get the string representation of a key.
 * 
 * \param k Key
 * \return ::R3S_string_t String representation of \p k.
 */
R3S_string_t R3S_key_to_string(R3S_key_t k);

/**
 * Get the string representation of a packet.
 * 
 * \param p Packet
 * \return ::R3S_string_t String representation of \p p.
 */
R3S_string_t R3S_packet_to_string(R3S_packet_t p);

/**
 * Get the string representation of a hash output.
 * 
 * \param o Hash output
 * \return ::R3S_string_t String representation of \p o.
 */
R3S_string_t R3S_hash_output_to_string(R3S_out_t o);

/**
 * Get the string representation of a status code.
 * 
 * \param s Status
 * \return ::R3S_string_t String representation of \p s.
 */
R3S_string_t R3S_status_to_string(R3S_status_t s);

/**
 * Get the string representation of a configuration option.
 * 
 * \param opt Option
 * \return ::R3S_string_t String representation of \p opt.
 */
R3S_string_t R3S_in_opt_to_string(R3S_in_opt_t opt);

/**
 * Get the string representation of a packet field.
 * 
 * \param pf Packet field
 * \return ::R3S_string_t String representation of \p pf.
 */
R3S_string_t R3S_pf_to_string(R3S_pf_t pf);

/**
 * Get the string representation of a configuration.
 * 
 * \param cfg Configuration
 * \return ::R3S_string_t String representation of \p cfg.
 */
R3S_string_t R3S_cfg_to_string(R3S_cfg_t cfg);

/**
 * Get the string representation of key statistics.
 * 
 * \param stats Statistics.
 * \return ::R3S_string_t String representation of \p stats.
 */
R3S_string_t R3S_key_stats_to_string(R3S_key_stats_t stats);


/**********************************************//**
 * @}
 * 
 * \defgroup ConfigAPI Config
 * Configuration related functions.
 * @{
 *************************************************/

/**
 * \brief Initialize a configuration.
 * \param cfg Configuration to initialize.
 */
void R3S_cfg_init(out R3S_cfg_t *cfg);

/**
 * \brief Reset a configuration.
 * \param cfg Configuration to reset.
 */
void R3S_cfg_reset(out R3S_cfg_t *cfg);

/**
 * \brief Delete a configuration.
 * \param cfg Configuration to delete.
 */
void R3S_cfg_delete(out R3S_cfg_t *cfg);

/**
 * \brief Load option into configuration.
 * \param cfg Configuration to modify.
 * \param in_opt Option to load.
 */
R3S_status_t R3S_cfg_load_in_opt(out R3S_cfg_t *cfg, R3S_in_opt_t in_opt);

/**********************************************//**
 * @}
 *
 * \defgroup PacketAPI Packet
 * Packet related functions.
 * @{
 *************************************************/

/**
 * Initialize packet.
 * 
 * \param p Packet.
 */
void R3S_packet_init(R3S_packet_t *p);

/**
 * Set packet field in packet.
 * 
 * \param cfg R3S configuration.
 * \param pf Type of packet field to store.
 * \param v Value of the packet field.
 * \param p Pointer to a packet field with the value set.
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

/**********************************************//**
 * @}
 *************************************************/


void R3S_rand_key(R3S_cfg_t cfg, R3S_key_t key);
R3S_status_t R3S_rand_packet(R3S_cfg_t cfg, out R3S_packet_t *p);
R3S_status_t R3S_rand_packets(R3S_cfg_t cfg, unsigned n_packets, out R3S_packet_t **p);
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
 *  index  | keys | description
 * ------- | -------------|-------------
 *    0    | k[0] | Constraints for the first key
 *    1    | k[1] | Constraints for the second key
 *   ...   | ...  | ...
 *   n-1   | k[n-1]       | Constraints for the last key
 *    n    | k[0], k[1]   | Constraints for the first and second keys
 *   n+1   | k[0], k[2]   | Constraints for the first and third keys
 *   ...   | ...  | ...
 *  2n-1   | k[0], k[n-1] | Constraints for the first and last keys
 *   2n    | k[1], k[2]   | Constraints for the second and third keys
 *   ...   | ...  | ...
 *   
 * 
 * Considering \f$ \binom{n}{m} \f$ as combinations of \f$ n \f$, \f$ m \f$
 * by \f$ m \f$, the size of \p mk_p_cnstrs must be at least
 * \f$ n + \binom{n}{2} \f$. This condition is
 * checked within this function, and it fails if it isn't met.
 * 
 * For example, using r3s_cfg.n_keys = 3, and knowing that
 * \f$ \binom{3}{2} = 3 \f$:
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
 * \example no_solution.c
 * Consider the following scenario:
 * *find an RSS key that for every pair of IPv4 packets p1 and p2,
 * if the IP source address of the packet p1 is equal to itself (i.e.,
 * always), then these two packets must have the same hash value*.
 * 
 * This example shows that there is no key that satisfied these
 * constraints.
 */
/** 
 * \example src_ip.c
 * \todo explanation
 */
/** 
 * \example symmetric_ip_and_symmetric_session.c
 * \todo explanation
 */
/** 
 * \example symmetric_ip.c
 * \todo explanation
 */
/** 
 * \example symmetric_session_2_cnstrs_diff_pf.c
 * \todo explanation
 */
/** 
 * \example symmetric_session_2_cnstrs_eq_pf.c
 * \todo explanation
 */
/** 
 * \example symmetric_session.c
 * \todo explanation
 */

Z3_ast R3S_mk_symmetric_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast R3S_mk_symmetric_tcp_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);
Z3_ast R3S_mk_symmetric_tcp_ip_cnstr(R3S_cfg_t r3s_cfg, unsigned iopt, Z3_context ctx, Z3_ast p1, Z3_ast p2);

void R3S_stats_init(R3S_cfg_t cfg, unsigned n_cores, out R3S_key_stats_t *stats);
void R3S_stats_reset(R3S_cfg_t cfg, unsigned n_cores, out R3S_key_stats_t *stats);
void R3S_stats_delete(out R3S_key_stats_t *stats);
R3S_status_t R3S_parse_packets(R3S_cfg_t cfg, char* filename, out R3S_packet_t **packets, int *n_packets);
R3S_status_t R3S_stats_from_packets(R3S_key_t key, R3S_packet_t *packets, int n_packets, out R3S_key_stats_t *stats);

#endif