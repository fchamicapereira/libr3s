#include "rssks.h"
#include "util.h"
#include "hash.h"
#include "debug.h"

#define LOAD_PF_OR_RETURN(cfg, pf) ({                           \
            RSSKS_status_t s = RSSKS_cfg_load_pf((cfg), (pf));  \
            if (s != RSSKS_STATUS_SUCCESS)                      \
                return s;                                       \
            })

void RSSKS_cfg_init(RSSKS_cfg_t *cfg)
{
    cfg->in_cfg  = 0;
    cfg->in_sz   = 0;
    cfg->n_cores = 0;
}

RSSKS_status_t RSSKS_cfg_load_in_opt(RSSKS_cfg_t *cfg, RSSKS_in_opt_t in_opt)
{
    switch (in_opt)
    {
        case RSSKS_IN_OPT_GENEVE_OAM:
        case RSSKS_IN_OPT_VXLAN_GPE_OAM:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_UDP_OUTER);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_VNI);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_UDP:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_UDP_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_TCP:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_TCP_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_SCTP:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_SCTP_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_SCTP_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4:
        case RSSKS_IN_OPT_FRAG_IPV4:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV4_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_UDP:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_UDP_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_TCP:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_TCP_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_SCTP_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_SCTP_DST);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6:
        case RSSKS_IN_OPT_FRAG_IPV6:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_SRC);
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_IPV6_DST);
            break;
        case RSSKS_IN_OPT_L2_TYPE:
            LOAD_PF_OR_RETURN(cfg, RSSKS_PF_L2_TYPE);
        default:
            return RSSKS_STATUS_OPT_UNKNOWN;
    }

    return RSSKS_STATUS_SUCCESS;
}

bool is_valid_pf(RSSKS_pf_t pf)
{
    return pf >= RSSKS_FIRST_PF && pf <= RSSKS_LAST_PF;
}

RSSKS_status_t RSSKS_cfg_load_pf(RSSKS_cfg_t *cfg, RSSKS_pf_t pf)
{
    RSSKS_status_t status;

    status = RSSKS_cfg_check_pf(*cfg, pf);

    // TODO: check incompatible packet fields (eg TCP + UDP)

    if (status == RSSKS_STATUS_PF_NOT_LOADED)
    {
        cfg->in_cfg |= (1 << pf);
        cfg->in_sz  += pf_sz_bits(pf);

        return RSSKS_STATUS_SUCCESS;
    }

    return status;
}

RSSKS_status_t RSSKS_cfg_check_pf(RSSKS_cfg_t cfg, RSSKS_pf_t pf)
{
    if (!is_valid_pf(pf)) return RSSKS_STATUS_PF_UNKNOWN;

    return ((cfg.in_cfg >> pf) & 1)
        ? RSSKS_STATUS_PF_ALREADY_LOADED
        : RSSKS_STATUS_PF_NOT_LOADED;
}
