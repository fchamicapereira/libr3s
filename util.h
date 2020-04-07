#ifndef __SOLVER_HASH_H__
#define __SOLVER_HASH_H__

#include <stdlib.h>

#ifndef DEBUG
    #define DEBUG false
#endif

#if DEBUG
    #define DEBUG_LOG(f_, ...)      !DEBUG || printf((f_), ##__VA_ARGS__)
    #define DEBUG_PLOG(f_, ...)      !DEBUG || \
        ( printf("[%d] ", getpid()) && \
          printf((f_), ##__VA_ARGS__) )
#else
    #define DEBUG_LOG(f_, ...)
    #define DEBUG_PLOG(f_, ...)
#endif

#define _32_LSB(bytes) ( \
    ( (((uint32_t) bytes[0]) << 24) & 0xff000000 ) + \
    ( (((uint32_t) bytes[1]) << 16) & 0xff0000   ) + \
    ( (((uint32_t) bytes[2]) <<  8) & 0xff00     ) + \
    ( (((uint32_t) bytes[3]) <<  0) & 0xff       ) \
)

int str_long_int_div(const char* n, int divisor, char* res);
void init_rand();

#endif