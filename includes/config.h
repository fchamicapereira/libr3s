#ifndef __R3S_CONFIG_H__
#define __R3S_CONFIG_H__

#include "r3s.h"

R3S_status_t R3S_cfg_load_pf(out R3S_cfg_t *cfg, unsigned iopt, R3S_pf_t pf);
R3S_status_t R3S_cfg_check_pf(R3S_cfg_t cfg, unsigned iopt, R3S_pf_t pf);
R3S_status_t R3S_cfg_packet_to_in_opt(R3S_cfg_t cfg, R3S_packet_t p, out unsigned *ipot);
unsigned       R3S_cfg_max_in_sz(R3S_cfg_t cfg);

#endif