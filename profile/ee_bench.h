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
#include "ee_sha.h"
#include "ee_variations.h"
#include "ee_util.h"

void bench_aes(aes_cipher_mode_t mode,
               aes_function_t    func,
               uint_fast32_t     keylen,
               uint_fast32_t     n,
               uint_fast32_t     i,
               bool              verify);

void bench_sha(sha_size_t size, uint_fast32_t n, uint_fast32_t i, bool verify);
void bench_ecdh(ecdh_group_t g, uint_fast32_t i, bool verify);

arg_claimed_t ee_bench_parse(char *p_command, bool verify);

#endif /* __EE_BENCH_H */
