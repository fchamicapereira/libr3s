#include <rssks.h>

int main () {
    RSSKS_status_t    status;
    RSSKS_cfg_t       cfg;
    RSSKS_key_t       k;
    RSSKS_cnstrs_func cnstrs[1];

    RSSKS_cfg_init(&cfg);
    RSSKS_cfg_load_in_opt(&cfg, RSSKS_IN_OPT_NON_FRAG_IPV4);

    cnstrs[0] = &RSSKS_mk_symmetric_ip_cnstr;
    status    = RSSKS_find_keys(cfg, cnstrs, &k);
    
    printf("%s\n", RSSKS_cfg_to_string(cfg));
    printf("%s\n", RSSKS_status_to_string(status));

    if (status == RSSKS_STATUS_SUCCESS)
        printf("result:\n%s\n", RSSKS_key_to_string(k));

    RSSKS_cfg_delete(&cfg);
}