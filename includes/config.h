#ifndef __RSSKS_CONFIG_H__
#define __RSSKS_CONFIG_H__

#include "rssks.h"

RSSKS_status_t RSSKS_cfg_load_pf(out RSSKS_cfg_t *cfg, unsigned iopt, RSSKS_pf_t pf);
RSSKS_status_t RSSKS_cfg_check_pf(RSSKS_cfg_t cfg, unsigned iopt, RSSKS_pf_t pf);
RSSKS_status_t RSSKS_cfg_packet_to_in_opt(RSSKS_cfg_t cfg, RSSKS_packet_t p, out unsigned *ipot);
unsigned       RSSKS_cfg_max_in_sz(RSSKS_cfg_t cfg);

#endif