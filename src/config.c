#include "../includes/r3s.h"
#include "../includes/util.h"
#include "../includes/hash.h"
#include "../includes/printer.h"
#include "../includes/packet.h"
#include "../includes/config.h"

#include <stdlib.h>

#define LOAD_PF_OR_RETURN(cfg, iopt, pf) ({             \
            R3S_status_t s;                           \
            s = R3S_cfg_load_pf((cfg), (iopt), (pf)); \
            if (s == R3S_STATUS_PF_UNKNOWN)           \
                return s;                               \
            })

#define MAX(x,y) ((x) >= (y) ? (x) : (y))

void R3S_cfg_init(R3S_cfg_t *cfg)
{
    cfg->loaded_opts   = NULL;
    cfg->n_loaded_opts = 0;
    cfg->n_procs       = 0;
    cfg->n_keys        = 1;
}

void R3S_cfg_reset(R3S_cfg_t *cfg)
{
    free(cfg->loaded_opts);
    R3S_cfg_init(cfg);
}

void R3S_cfg_delete(R3S_cfg_t *cfg)
{
    free(cfg->loaded_opts);
}

bool is_valid_in_opt(R3S_in_opt_t opt)
{
    switch (opt)
    {
        case R3S_IN_OPT_GENEVE_OAM:
        case R3S_IN_OPT_VXLAN_GPE_OAM:
        case R3S_IN_OPT_NON_FRAG_IPV4_TCP:
        case R3S_IN_OPT_NON_FRAG_IPV4_UDP:
        case R3S_IN_OPT_NON_FRAG_IPV4_SCTP:
        case R3S_IN_OPT_NON_FRAG_IPV4:
        case R3S_IN_OPT_FRAG_IPV4:
        case R3S_IN_OPT_NON_FRAG_IPV6_TCP:
        case R3S_IN_OPT_NON_FRAG_IPV6_UDP:
        case R3S_IN_OPT_NON_FRAG_IPV6_SCTP:
        case R3S_IN_OPT_NON_FRAG_IPV6:
        case R3S_IN_OPT_FRAG_IPV6:
        case R3S_IN_OPT_ETHERTYPE: return true;
    }

    return false;
}

R3S_status_t R3S_cfg_load_in_opt(R3S_cfg_t *cfg, R3S_in_opt_t opt)
{
    unsigned iopt;

    if (!is_valid_in_opt(opt)) return R3S_STATUS_OPT_UNKNOWN;

    iopt = cfg->n_loaded_opts;

    cfg->n_loaded_opts++;
    cfg->loaded_opts = (R3S_loaded_in_opt_t*) realloc(
        cfg->loaded_opts,
        sizeof(R3S_loaded_in_opt_t) * cfg->n_loaded_opts);
    
    cfg->loaded_opts[iopt].opt = opt;
    cfg->loaded_opts[iopt].pfs = 0;
    cfg->loaded_opts[iopt].sz  = 0;

    switch (opt)
    {
        case R3S_IN_OPT_GENEVE_OAM:
        case R3S_IN_OPT_VXLAN_GPE_OAM:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_VXLAN_UDP_OUTER);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_VXLAN_VNI);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV4_UDP:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_UDP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_UDP_DST);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV4_TCP:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_TCP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_TCP_DST);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV4_SCTP:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_SCTP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_SCTP_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_SCTP_V_TAG);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV4:
        case R3S_IN_OPT_FRAG_IPV4:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV4_DST);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV6_UDP:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_UDP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_UDP_DST);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV6_TCP:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_TCP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_TCP_DST);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV6_SCTP:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_SCTP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_SCTP_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_SCTP_V_TAG);
            break;
        case R3S_IN_OPT_NON_FRAG_IPV6:
        case R3S_IN_OPT_FRAG_IPV6:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_IPV6_DST);
            break;
        case R3S_IN_OPT_ETHERTYPE:
            LOAD_PF_OR_RETURN(cfg, iopt, R3S_PF_ETHERTYPE);
    }

    return R3S_STATUS_SUCCESS;
}

bool is_valid_pf(R3S_pf_t pf)
{
    return pf >= R3S_FIRST_PF && pf <= R3S_LAST_PF;
}

R3S_status_t R3S_cfg_load_pf(R3S_cfg_t *cfg, unsigned iopt, R3S_pf_t pf)
{
    R3S_status_t status;

    status = R3S_cfg_check_pf(*cfg, iopt, pf);

    if (status == R3S_STATUS_PF_NOT_LOADED)
    {
        cfg->loaded_opts[iopt].pfs |= (1 << pf);
        cfg->loaded_opts[iopt].sz  += R3S_pf_sz_bits(pf);

        return R3S_STATUS_SUCCESS;
    }

    return status;
}

R3S_status_t R3S_cfg_check_pf(R3S_cfg_t cfg, unsigned iopt, R3S_pf_t pf)
{
    if (!is_valid_pf(pf)) return R3S_STATUS_PF_UNKNOWN;

    return ((cfg.loaded_opts[iopt].pfs >> pf) & 1)
        ? R3S_STATUS_PF_LOADED
        : R3S_STATUS_PF_NOT_LOADED;
}

R3S_status_t R3S_cfg_packet_to_in_opt(R3S_cfg_t cfg, R3S_packet_t p, unsigned *ipot)
{
    R3S_pf_t pf;
    unsigned   n_opts;
    int        match;
    int        chosen_opt;
    int        max_match;

    max_match  = -1;
    chosen_opt = -1;
    n_opts     = cfg.n_loaded_opts;
    
    for (unsigned i = 0; i < n_opts; i++)
    {
        match = 0;

        for (int ipf = R3S_FIRST_PF; ipf <= R3S_LAST_PF; ipf++)
        {
            pf = (R3S_pf_t) ipf;

            if (!R3S_cfg_check_pf(cfg, i, pf)) continue;
            if (!R3S_packet_has_pf(p, pf))     break;

            match++;
        }

        if (match > max_match)
        {
            chosen_opt = i;
            max_match = match;
        }
    }

    if (chosen_opt == -1) return R3S_STATUS_NO_SOLUTION;
    
    *ipot = chosen_opt;
    return R3S_STATUS_SUCCESS;
}

unsigned R3S_cfg_max_in_sz(R3S_cfg_t cfg)
{
    unsigned max_sz;

    max_sz = 0;

    for (unsigned iopt = 0; iopt < cfg.n_loaded_opts; iopt++)
        max_sz = MAX(max_sz, cfg.loaded_opts[iopt].sz);
    
    return max_sz;
}
