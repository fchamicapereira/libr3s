#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdint.h>

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

#define CORES                   8
#define HASH_TO_CORE(hash)      (hash % CORES)

#define BYTE_FROM_BYTES(bb, b)  ((bb)[b] & 0xff)
#define BIT_FROM_BYTE(b, i)     (((b) >> (i)) & 1)
#define BIT_FROM_KEY(b, k)      (BIT_FROM_BYTE(k[(b) / 8], 7 - ((b) % 8)))

#define _4_RSSKS_BYTE_T_TO_UINT32_T(v) ((uint32_t) (\
    ((BYTE_FROM_BYTES((v), 0)) << 24) + ((BYTE_FROM_BYTES((v), 1)) << 16) + \
    ((BYTE_FROM_BYTES((v), 2)) <<  8) + ((BYTE_FROM_BYTES((v), 3)) <<  0) ))

#define _3_RSSKS_BYTE_T_TO_UINT32_T(v) ((uint32_t) (\
    ((BYTE_FROM_BYTES((v), 0)) << 16) + ((BYTE_FROM_BYTES((v), 1)) <<  8) + \
    ((BYTE_FROM_BYTES((v), 2)) <<  0) ))

#define _2_RSSKS_BYTE_T_TO_UINT32_T(v) ((uint16_t) (\
    ((BYTE_FROM_BYTES((v), 0)) <<  8) + ((BYTE_FROM_BYTES((v), 1)) <<  0) ))

#endif