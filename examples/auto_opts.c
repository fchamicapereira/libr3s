#include <r3s.h>
#include <stdlib.h>

int main() {
    R3S_opt_t *opts;
    size_t     opts_sz;
    R3S_pf_t   pfs[10] = {
        R3S_PF_SCTP_V_TAG,
        R3S_PF_ETHERTYPE,
        R3S_PF_IPV4_SRC
    };

    R3S_opts_from_pfs(pfs, 3, &opts, &opts_sz);

    printf("Resulting options:\n");
    for (unsigned i = 0; i < opts_sz; i++)
        printf("%s\n", R3S_opt_to_string(opts[i]));

    free(opts);
}