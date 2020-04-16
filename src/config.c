#include "rssks.h"
#include "util.h"
#include "hash.h"
#include "string.h"
#include "packet.h"
#include "config.h"

#include <stdlib.h>

#define LOAD_PF_OR_RETURN(cfg, iopt, pf) ({             \
            RSSKS_status_t s;                           \
            s = RSSKS_cfg_load_pf((cfg), (iopt), (pf)); \
            if (s == RSSKS_STATUS_PF_UNKNOWN)           \
                return s;                               \
            })

#define MAX(x,y) ((x) >= (y) ? (x) : (y))

void RSSKS_cfg_init(RSSKS_cfg_t *cfg)
{
    cfg->loaded_opts   = NULL;
    cfg->n_loaded_opts = 0;
    cfg->n_cores       = 0;
    cfg->n_keys        = 1;
}

void RSSKS_cfg_reset(RSSKS_cfg_t *cfg)
{
    free(cfg->loaded_opts);
    RSSKS_cfg_init(cfg);
}

void RSSKS_cfg_delete(RSSKS_cfg_t *cfg)
{
    free(cfg->loaded_opts);
}

bool is_valid_in_opt(RSSKS_in_opt_t opt)
{
    switch (opt)
    {
        case RSSKS_IN_OPT_GENEVE_OAM:
        case RSSKS_IN_OPT_VXLAN_GPE_OAM:
        case RSSKS_IN_OPT_NON_FRAG_IPV4_TCP:
        case RSSKS_IN_OPT_NON_FRAG_IPV4_UDP:
        case RSSKS_IN_OPT_NON_FRAG_IPV4_SCTP:
        case RSSKS_IN_OPT_NON_FRAG_IPV4:
        case RSSKS_IN_OPT_FRAG_IPV4:
        case RSSKS_IN_OPT_NON_FRAG_IPV6_TCP:
        case RSSKS_IN_OPT_NON_FRAG_IPV6_UDP:
        case RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP:
        case RSSKS_IN_OPT_NON_FRAG_IPV6:
        case RSSKS_IN_OPT_FRAG_IPV6:
        case RSSKS_IN_OPT_ETHERTYPE: return true;
    }

    return false;
}

RSSKS_status_t RSSKS_cfg_load_in_opt(RSSKS_cfg_t *cfg, RSSKS_in_opt_t opt)
{
    unsigned iopt;

    if (!is_valid_in_opt(opt)) return RSSKS_STATUS_OPT_UNKNOWN;

    iopt = cfg->n_loaded_opts;

    cfg->n_loaded_opts++;
    cfg->loaded_opts = (RSSKS_loaded_in_opt_t*) realloc(
        cfg->loaded_opts,
        sizeof(RSSKS_loaded_in_opt_t) * cfg->n_loaded_opts);
    
    cfg->loaded_opts[iopt].opt = opt;
    cfg->loaded_opts[iopt].pfs = 0;
    cfg->loaded_opts[iopt].sz  = 0;

    switch (opt)
    {
        case RSSKS_IN_OPT_GENEVE_OAM:
        case RSSKS_IN_OPT_VXLAN_GPE_OAM:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_VXLAN_UDP_OUTER);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_VXLAN_VNI);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_UDP:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_UDP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_TCP:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_TCP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_SCTP:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_SCTP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_SCTP_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4:
        case RSSKS_IN_OPT_FRAG_IPV4:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV4_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_UDP:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_UDP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_TCP:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_TCP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_SCTP_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_SCTP_DST);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6:
        case RSSKS_IN_OPT_FRAG_IPV6:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_IPV6_DST);
            break;
        case RSSKS_IN_OPT_ETHERTYPE:
            LOAD_PF_OR_RETURN(cfg, iopt, RSSKS_PF_ETHERTYPE);
    }

    return RSSKS_STATUS_SUCCESS;
}

bool is_valid_pf(RSSKS_pf_t pf)
{
    return pf >= RSSKS_FIRST_PF && pf <= RSSKS_LAST_PF;
}

RSSKS_status_t RSSKS_cfg_load_pf(RSSKS_cfg_t *cfg, unsigned iopt, RSSKS_pf_t pf)
{
    RSSKS_status_t status;

    status = RSSKS_cfg_check_pf(*cfg, iopt, pf);

    if (status == RSSKS_STATUS_PF_NOT_LOADED)
    {
        cfg->loaded_opts[iopt].pfs |= (1 << pf);
        cfg->loaded_opts[iopt].sz  += RSSKS_pf_sz_bits(pf);

        return RSSKS_STATUS_SUCCESS;
    }

    return status;
}

RSSKS_status_t RSSKS_cfg_check_pf(RSSKS_cfg_t cfg, unsigned iopt, RSSKS_pf_t pf)
{
    if (!is_valid_pf(pf)) return RSSKS_STATUS_PF_UNKNOWN;

    return ((cfg.loaded_opts[iopt].pfs >> pf) & 1)
        ? RSSKS_STATUS_PF_LOADED
        : RSSKS_STATUS_PF_NOT_LOADED;
}

RSSKS_status_t RSSKS_cfg_packet_to_in_opt(RSSKS_cfg_t cfg, RSSKS_packet_t p, unsigned *ipot)
{
    RSSKS_pf_t pf;
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

        for (int ipf = RSSKS_FIRST_PF; ipf <= RSSKS_LAST_PF; ipf++)
        {
            pf = (RSSKS_pf_t) ipf;

            if (!RSSKS_cfg_check_pf(cfg, i, pf)) continue;
            if (!RSSKS_packet_has_pf(p, pf))     break;

            match++;
        }

        if (match > max_match)
        {
            chosen_opt = i;
            max_match = match;
        }
    }

    if (chosen_opt == -1) return RSSKS_STATUS_NO_SOLUTION;
    
    *ipot = chosen_opt;
    return RSSKS_STATUS_SUCCESS;
}

unsigned RSSKS_cfg_max_in_sz(RSSKS_cfg_t cfg)
{
    unsigned max_sz;

    max_sz = 0;

    for (unsigned iopt = 0; iopt < cfg.n_loaded_opts; iopt++)
        max_sz = MAX(max_sz, cfg.loaded_opts[iopt].sz);
    
    return max_sz;
}
