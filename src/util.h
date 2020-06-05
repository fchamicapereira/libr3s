#ifndef __R3S_UTIL_H__
#define __R3S_UTIL_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define _32_LSB(bytes) ( \
    ( (((uint32_t) bytes[0]) << 24) & 0xff000000 ) + \
    ( (((uint32_t) bytes[1]) << 16) & 0xff0000   ) + \
    ( (((uint32_t) bytes[2]) <<  8) & 0xff00     ) + \
    ( (((uint32_t) bytes[3]) <<  0) & 0xff       ) \
)

int      str_long_int_div(const char* n, int divisor, char* res);
void     init_rand();
unsigned combinations(unsigned n, unsigned r);
void     shuffle(void *arr, unsigned arr_sz, unsigned el_sz);
bool     find(void* el, void *arr, size_t arr_sz, size_t el_sz);
bool     arr_eq(void *a1, size_t a1_sz, void *a2, size_t a2_sz, size_t el_sz);
void     remove_dup(void **arr, size_t *arr_sz, size_t el_sz);

#endif
