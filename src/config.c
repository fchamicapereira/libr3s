#include <assert.h>

#include "rssks.h"
#include "util.h"
#include "hash.h"
#include "debug.h"

RSSKS_cfg_t RSSKS_cfg_init()
{
    RSSKS_cfg_t cfg = {
        .in_cfg      = 0,
        .in_sz       = 0,
        .cores       = 0
    };

    return cfg;
}

void RSSKS_cfg_load_in_opt(RSSKS_cfg_t *cfg, RSSKS_in_opt_t in_opt)
{
    switch (in_opt)
    {
        case RSSKS_IN_OPT_GENEVE_OAM:
        case RSSKS_IN_OPT_VXLAN_GPE_OAM:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_OUTER);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_VNI);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_UDP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_TCP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4_SCTP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV4:
        case RSSKS_IN_OPT_FRAG_IPV4:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV4_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_UDP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_UDP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_TCP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_TCP_DST);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6_SCTP:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_DST);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_SCTP_V_TAG);
            break;
        case RSSKS_IN_OPT_NON_FRAG_IPV6:
        case RSSKS_IN_OPT_FRAG_IPV6:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_SRC);
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_IPV6_DST);
            break;
        case RSSKS_IN_OPT_L2_TYPE:
            RSSKS_cfg_load_pf(cfg, RSSKS_PF_L2_TYPE);
        default:
            DEBUG_LOG("Input option unknown: %d\n", in_opt);
            assert(false);
    }
}

void RSSKS_cfg_load_pf(RSSKS_cfg_t *cfg, RSSKS_pf_t pf)
{
    if (RSSKS_cfg_check_pf(*cfg, pf)) return;

    // TODO: check incompatible packet fields (eg TCP + UDP)

    cfg->in_cfg      = cfg->in_cfg | (1 << pf);
    cfg->in_sz      += pf_sz_bits(pf);
}

bool RSSKS_cfg_check_pf(RSSKS_cfg_t cfg, RSSKS_pf_t pf)
{
    return (cfg.in_cfg >> pf) & 1;
}
