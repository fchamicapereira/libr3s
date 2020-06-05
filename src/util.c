#include "util.h"
#include "printer.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int str_long_int_div(const char* n, int divisor, char* res)
{
    int remainder;
    int idx = 0;
    int tmp = n[idx] - '0';

    res[0] = '\0';

    if (!strcmp(n, "0"))
    {
        sprintf(res, "0");
        return 0;
    }

    while (tmp < divisor)
        tmp = tmp * 10 + (n[++idx] - '0');
    
    while ((int) strlen(n) > idx)
    {
        sprintf(res + strlen(res), "%d", tmp / divisor);
        remainder = tmp % divisor;
        tmp = remainder * 10 + n[++idx] - '0';
    }

    if (!strlen(res)) { remainder = atoi(n); sprintf(res, "0"); }

    return remainder;
}

void init_rand()
{
    FILE*     urandom;
    unsigned  seed;
    int       pid;

    pid     = getpid();
    urandom = fopen("/dev/urandom", "r");

    if (fread(&seed, sizeof(int), 1, urandom) <= 0) {
        DEBUG_PLOG("IO ERROR: unable to read from urandom\n");
        return;
    }

    fclose(urandom);

    seed    += pid;

    srand(seed);
}

unsigned factorial(unsigned n)
{
    unsigned f = 1;
    while (n > 1) f *= n--;
    return f;
}

unsigned combinations(unsigned n, unsigned r)
{
    unsigned f_n;
    unsigned f_r;
    unsigned f_d;

    if (r > n) return 0;

    f_n = factorial(n);
    f_r = factorial(r);
    f_d = factorial(n - r);

    return f_n / (f_r * f_d);
}

void shuffle(void *arr, unsigned arr_sz, unsigned el_sz) {
    unsigned j;
    void     *tmp;

    tmp = malloc(el_sz);

    if (arr_sz == 0) return;

    init_rand();

    for (unsigned i = 0; i < arr_sz; i++) {
        j = rand() % arr_sz;

        memcpy(tmp, arr + el_sz * j, el_sz);
        memcpy(arr + el_sz * j, arr + el_sz * i, el_sz);
        memcpy(arr + el_sz * i, tmp, el_sz);
    }

    free(tmp);
}

bool arr_eq(void *a1, size_t a1_sz, void *a2, size_t a2_sz, size_t el_sz) {
    if (a1_sz != a2_sz) return false;
    for (unsigned i = 0; i < a1_sz; i++)
        if (memcmp(a1 + el_sz * i, a2 + el_sz * i, el_sz) != 0)
            return false;
    return true;
}

bool find(void* el, void *arr, size_t arr_sz, size_t el_sz) {
    for (unsigned i = 0; i < arr_sz; i++)
        if (memcmp(arr + el_sz * i, el, el_sz) == 0)
            return true;
    return false;
}

void remove_dup(void **arr, size_t *arr_sz, size_t el_sz) {
    void *el1;
    void *el2;
    void *tail;
    void *tmp;

    tmp = malloc(el_sz);

    for (unsigned i = 0; i < *arr_sz - 1; i++) {
        el1 = (*arr) + el_sz * i;

        unsigned j = i + 1;
        while (j < *arr_sz) {
            el2 = (*arr) + el_sz * j;

            if (memcmp(el1, el2, el_sz) == 0) {
                tail = (*arr) + el_sz * ((*arr_sz) - 1);

                memcpy(tmp, tail, el_sz);
                memcpy(tail, el2, el_sz);
                memcpy(el2, tmp, el_sz);

                (*arr_sz)--;
            } else {
                j++;
            }

        }
    }

    free(tmp);
}
