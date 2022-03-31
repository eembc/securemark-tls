/*
 * Copyright (C) EEMBC(R). All Rights Reserved
 *
 * All EEMBC Benchmark Software are products of EEMBC and are provided under the
 * terms of the EEMBC Benchmark License Agreements. The EEMBC Benchmark Software
 * are proprietary intellectual properties of EEMBC and its Members and is
 * protected under all applicable laws, including all applicable copyright laws.
 *
 * If you received this EEMBC Benchmark Software without having a currently
 * effective EEMBC Benchmark License Agreement, you must discontinue use.
 */

#ifndef __EE_BENCH_H
#define __EE_BENCH_H

#include "ee_main.h"
#include "ee_aes.h"
#include "ee_chachapoly.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_rsa.h"
#include "ee_sha.h"
#include "ee_variations.h"
#include "ee_util.h"

void ee_bench_sha(ee_sha_size_t size, uint_fast32_t n, uint_fast32_t i, bool verify);

void ee_bench_aes(ee_aes_mode_t mode,
               ee_aes_func_t    func,
               uint_fast32_t     keylen,
               uint_fast32_t     n,
               uint_fast32_t     i,
               bool              verify);

void ee_bench_chachapoly(ee_chachapoly_func_t func, int n, int i, bool verify);

void ee_bench_ecdh(ee_ecdh_group_t g, uint_fast32_t i, bool verify);

void ee_bench_ecdsa(ee_ecdh_group_t     g,
                 ee_ecdsa_func_t func,
                 uint_fast32_t    n,
                 uint_fast32_t    i,
                 bool             verify);

void ee_bench_rsa(ee_rsa_id_t       id,
               ee_rsa_function_t func,
               unsigned int      n,
               unsigned int      i,
               bool              verify);

arg_claimed_t ee_bench_parse(char *p_command, bool verify);

#endif /* __EE_BENCH_H */
