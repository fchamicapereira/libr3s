#include <string.h>

#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>

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
