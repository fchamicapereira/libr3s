#ifndef __RSSKS_SOLVER_H__
#define __RSSKS_SOLVER_H__

#include "rssks.h"

#define SOLVER_TIMEOUT_SEC      (60 * 60) // 1 hour

typedef struct {
    int *pid;
    int *rpipe;
    int *wpipe;
} comm_t;

typedef void (*RSSKS_worker)(RSSKS_cfg_t,RSSKS_cnstrs_func*);

#endif