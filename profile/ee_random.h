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

#ifndef __EE_RANDOM_H
#define __EE_RANDOM_H

#include "ee_main.h"

#include <stddef.h>
#include <stdint.h>

/**
 * Query random values of length len and 
 * place them into the buffer output.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */

int ee_random( void *rng_state,
               unsigned char *output,
               size_t len );

#endif /* __EE_RANDOM_H */