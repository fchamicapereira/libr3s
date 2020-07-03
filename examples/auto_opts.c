#include <r3s.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    R3S_opt_t *opts;
    size_t     opts_sz;
    R3S_pf_t   pfs[10] = {
        R3S_PF_IPV4_SRC,
        R3S_PF_IPV4_DST,
        R3S_PF_TCP_SRC,
        R3S_PF_TCP_DST,
        R3S_PF_UDP_SRC,
        R3S_PF_UDP_DST
    };

    R3S_opts_from_pfs(pfs, 6, &opts, &opts_sz);

    printf("Resulting options:\n");
    for (unsigned i = 0; i < opts_sz; i++)
        printf("%s\n", R3S_opt_to_string(opts[i]));

    free(opts);
}
