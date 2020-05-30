#ifndef __R3S_PACKET_H__
#define __R3S_PACKET_H__

#include "../include/r3s.h"
#include <stdbool.h>

#define R3S_pf_sz(pf)   (R3S_pf_sz_bits((pf)) < 1 ? 8 : R3S_pf_sz_bits((pf)) / 8)

size_t        R3S_pf_sz_bits(R3S_pf_t pf);
bool          R3S_packet_has_pf(R3S_packet_t p, R3S_pf_t pf);
R3S_bytes_t   R3S_packet_get_field(R3S_packet_t *p, R3S_pf_t pf);
R3S_status_t  R3S_packet_to_loaded_opt(R3S_cfg_t cfg, R3S_packet_t p, out R3S_loaded_opt_t *opt);

#endif