#ifndef __R3S_PRINTER_H__
#define __R3S_PRINTER_H__

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#ifndef DEBUG
    #define DEBUG false
#endif

#if DEBUG
    #define DEBUG_LOG(f_, ...)       !DEBUG || printf((f_), ##__VA_ARGS__)
    #define DEBUG_PLOG(f_, ...)      !DEBUG || \
        ( printf("[%d] ", getpid()) &&         \
          printf((f_), ##__VA_ARGS__) )
#else
    #define DEBUG_LOG(f_, ...)
    #define DEBUG_PLOG(f_, ...)
#endif

#define CORES                   8
#define HASH_TO_CORE(hash)      ((hash) % CORES)

#define BYTE_FROM_BYTES(bb, b)  ((bb)[(b)] & 0xff)
#define BIT_FROM_BYTE(b, i)     (((b) >> (i)) & 1)
#define BIT_FROM_KEY(b, k)      (BIT_FROM_BYTE((k)[(b) / 8], 7 - ((b) % 8)))

#define R3S_STRING_SZ           1000

#endif