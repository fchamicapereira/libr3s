#ifndef __PACKET_H__
#define __PACKET_H__

#include "rssks.h"
#include <stdbool.h>

#define RSSKS_pf_sz(pf)   (RSSKS_pf_sz_bits((pf)) < 1 ? 8 : RSSKS_pf_sz_bits((pf)) / 8)

size_t        RSSKS_pf_sz_bits(RSSKS_pf_t pf);
bool          RSSKS_packet_has_pf(RSSKS_packet_t p, RSSKS_pf_t pf);
RSSKS_bytes_t RSSKS_field_from_packet(RSSKS_packet_t *p, RSSKS_pf_t pf);

#endif