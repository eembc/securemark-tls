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

#ifndef __EE_VARIATIONS_H
#define __EE_VARIATIONS_H

#include "th_libc.h"
#include "ee_aes.h"
#include "ee_sha.h"
#include "ee_util.h"

#define VAR001_SESSION_LEN 1495u
#define VAR001_AES_LEN     16u

/**
 * @brief This primitive combines several AES and SHA contexts, similar to
 * what is seen in the TLS handshake. This provides a more complex scenario
 * for crypto accelerators.
 *
 * @param iter - Number of iterations to perform.
 * @return uint32_t - Execution time in microseconds
 */

uint32_t ee_variation_001(uint32_t iter);

#endif
