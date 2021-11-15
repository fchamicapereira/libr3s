#ifndef __R3S_SOLVER_H__
#define __R3S_SOLVER_H__

#include "../include/r3s.h"

#define SOLVER_TIMEOUT_SEC      (60 * 60 * 3) // 3 hours

typedef struct {
    int *pid;
    int *rpipe;
    int *wpipe;
} comm_t;

typedef void (*R3S_worker)(R3S_cfg_t,R3S_cnstrs_func);

#endif
