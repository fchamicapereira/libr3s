#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>

#include "util.h"

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

    fread(&seed, sizeof(int), 1, urandom);
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
