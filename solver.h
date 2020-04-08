#ifndef __SOLVER_H__
#define __SOLVER_H__

#include "rssks.h"
#include "hash.h"

#include <stdint.h>
#include <stdarg.h>
#include <memory.h>
#include <setjmp.h>

#define FIND_K_AST_FILE         "./find_k.smt2"
#define CHECK_K_AST_FILE        "./check_k.smt2"
#define UNSAT_CORE_AST_FILE     "./unsat-core.txt"

#define SOLVER_TIMEOUT_SEC      (60 * 10) // 10 minutes

RSSKS_in_t header_to_hash_input(RSSKS_headers_t headers);
RSSKS_headers_t RSSKS_in_to_header(RSSKS_in_t hi);

#endif