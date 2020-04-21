#include "../include/r3s.h"
#include "util.h"
#include "hash.h"
#include "printer.h"
#include "packet.h"
#include "config.h"

#include <stdlib.h>

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

R3S_status_t R3S_in_opt_to_pfs(R3S_in_opt_t opt, R3S_pf_t **pfs, unsigned *n_pfs)
{
    // TODO: check if is valid opt
    *n_pfs = 0;

    switch (opt)
    {
        case R3S_IN_OPT_GENEVE_OAM:
        case R3S_IN_OPT_VXLAN_GPE_OAM:
            *n_pfs    = 2;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_VXLAN_UDP_OUTER;
            (*pfs)[1] = R3S_PF_VXLAN_VNI;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV4_UDP:
            *n_pfs    = 4;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV4_SRC;
            (*pfs)[1] = R3S_PF_IPV4_DST;
            (*pfs)[2] = R3S_PF_UDP_SRC;
            (*pfs)[3] = R3S_PF_UDP_DST;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV4_TCP:
            *n_pfs    = 4;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV4_SRC;
            (*pfs)[1] = R3S_PF_IPV4_DST;
            (*pfs)[2] = R3S_PF_TCP_SRC;
            (*pfs)[3] = R3S_PF_TCP_DST;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV4_SCTP:
            *n_pfs    = 5;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV4_SRC;
            (*pfs)[1] = R3S_PF_IPV4_DST;
            (*pfs)[2] = R3S_PF_SCTP_SRC;
            (*pfs)[3] = R3S_PF_SCTP_DST;
            (*pfs)[3] = R3S_PF_SCTP_V_TAG;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV4:
        case R3S_IN_OPT_FRAG_IPV4:
            *n_pfs    = 2;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV4_SRC;
            (*pfs)[1] = R3S_PF_IPV4_DST;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV6_UDP:
            *n_pfs    = 4;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV6_SRC;
            (*pfs)[1] = R3S_PF_IPV6_DST;
            (*pfs)[2] = R3S_PF_UDP_SRC;
            (*pfs)[3] = R3S_PF_UDP_DST;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV6_TCP:
            *n_pfs    = 4;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV6_SRC;
            (*pfs)[1] = R3S_PF_IPV6_DST;
            (*pfs)[2] = R3S_PF_TCP_SRC;
            (*pfs)[3] = R3S_PF_TCP_DST;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV6_SCTP:
            *n_pfs    = 5;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV6_SRC;
            (*pfs)[1] = R3S_PF_IPV6_DST;
            (*pfs)[2] = R3S_PF_SCTP_SRC;
            (*pfs)[3] = R3S_PF_SCTP_DST;
            (*pfs)[3] = R3S_PF_SCTP_V_TAG;

            break;
        case R3S_IN_OPT_NON_FRAG_IPV6:
        case R3S_IN_OPT_FRAG_IPV6:
            *n_pfs    = 2;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_IPV6_SRC;
            (*pfs)[1] = R3S_PF_IPV6_DST;
            
            break;
        case R3S_IN_OPT_ETHERTYPE:
            *n_pfs    = 1;
            *pfs      = (R3S_pf_t*) malloc(sizeof(R3S_pf_t) * (*n_pfs));

            (*pfs)[0] = R3S_PF_ETHERTYPE;
    }

    return R3S_STATUS_SUCCESS;
}

bool R3S_cfg_are_compatible_pfs(R3S_cfg_t cfg, R3S_in_cfg_t pfs)
{
    for (unsigned iopt = 0; iopt < cfg.n_loaded_opts; iopt++) {
        if ((pfs & cfg.loaded_opts[iopt].pfs) != 0) return true;
    }
    return false;
}

R3S_status_t R3S_cfg_load_in_opt(R3S_cfg_t *cfg, R3S_in_opt_t opt)
{
    R3S_status_t s;
    R3S_pf_t     *pfs;
    unsigned     n_pfs;
    unsigned     iopt;

    if (!is_valid_in_opt(opt)) return R3S_STATUS_OPT_UNKNOWN;

    iopt = cfg->n_loaded_opts;

    cfg->n_loaded_opts++;
    cfg->loaded_opts = (R3S_loaded_in_opt_t*) realloc(
        cfg->loaded_opts,
        sizeof(R3S_loaded_in_opt_t) * cfg->n_loaded_opts);
    
    cfg->loaded_opts[iopt].opt = opt;
    cfg->loaded_opts[iopt].pfs = 0;
    cfg->loaded_opts[iopt].sz  = 0;

    s = R3S_in_opt_to_pfs(opt, &pfs, &n_pfs);
    if (s != R3S_STATUS_SUCCESS) return s;

    for (unsigned i = 0; i < n_pfs; i++)
    {
        s = R3S_cfg_load_pf(cfg, iopt, pfs[i]);
        if (s == R3S_STATUS_PF_UNKNOWN) 
        {
            free(pfs);
            return s;
        }
    }

    free(pfs);

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
    if (!is_valid_pf(pf))         return R3S_STATUS_PF_UNKNOWN;
    if (iopt > cfg.n_loaded_opts) return R3S_STATUS_INVALID_IOPT;
    
    return ((cfg.loaded_opts[iopt].pfs >> pf) & 1)
        ? R3S_STATUS_PF_LOADED
        : R3S_STATUS_PF_NOT_LOADED;
}

unsigned R3S_cfg_max_in_sz(R3S_cfg_t cfg)
{
    unsigned max_sz;

    max_sz = 0;

    for (unsigned iopt = 0; iopt < cfg.n_loaded_opts; iopt++)
        max_sz = MAX(max_sz, cfg.loaded_opts[iopt].sz);
    
    return max_sz;
}
