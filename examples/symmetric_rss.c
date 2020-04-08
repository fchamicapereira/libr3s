#include <stdio.h>
#include <rssks.h>

int main () {
    RSSKS_cfg_t     cfg;
    RSSKS_out_t     o;
    RSSKS_headers_t h;
    RSSKS_key_t     k;

    cfg = RSSKS_cfg_init();
    
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4_TCP);
}