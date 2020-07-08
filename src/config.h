#ifndef __R3S_CONFIG_H__
#define __R3S_CONFIG_H__

#include "../include/r3s.h"

R3S_status_t R3S_cfg_load_pf(out R3S_cfg_t cfg, unsigned iopt, R3S_pf_t pf);
R3S_status_t R3S_loaded_opt_check_pf(R3S_loaded_opt_t loaded_opt, R3S_pf_t pf);
unsigned     R3S_cfg_max_in_sz(R3S_cfg_t cfg);
R3S_status_t R3S_opt_to_pfs(R3S_opt_t opt, R3S_pf_t **pfs, unsigned *n_pfs);
bool         R3S_cfg_are_compatible_pfs(R3S_cfg_t cfg, R3S_in_cfg_t pfs);

#endif
