#ifndef __SOLVER_H__
#define __SOLVER_H__

#include "rssks.h"

#define FIND_K_AST_FILE         "./find_k.smt2"
#define CHECK_K_AST_FILE        "./check_k.smt2"
#define UNSAT_CORE_AST_FILE     "./unsat-core.txt"

#define SOLVER_TIMEOUT_SEC      (60 * 60) // 1 hour

typedef struct {
    int *pid;
    int *rpipe;
    int *wpipe;
} comm_t;

typedef void (*RSSKS_worker)(RSSKS_cfg_t,RSSKS_cnstrs_func*);

#endif