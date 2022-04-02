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

#ifndef __TH_UTIL_H
#define __TH_UTIL_H

#include <ee_main.h>
#include <stddef.h>
#include <stdint.h>

#define BUFFER_SIZE (1024 * 8)

/**
 * @brief Most init can happen prior to ee_main(), but if necessary, this
 * function provides a way to initialize within the ee_* initialization. It is
 * called from: ee_main() > ee_profile_init() > th_profile_init().
 *
 * @return ee_status_t
 */
ee_status_t th_profile_initialize(void);

/**
 * @brief Perform any power-reducing opportinuties before entering a compute-
 * intensive loop.
 */
void th_pre(void);

/**
 * @brief Undo any power-reducing opportinuties set with `th_pre()`.
 */
void th_post(void);

/**
 * @brief If memory is located somewhere other than a heap, it needs to be
 * content addressible with `[]` operator. This may need to be deprecated,
 * as it has never been used.
 *
 */
void th_buffer_initialize(void);

/**
 * @brief If non-heap memory is used, return a `[]` addressible pointer.
 *
 * @return uint8_t* - Pointer to the start of the generic buffer.
 */
uint8_t *th_buffer_address(void);

/**
 * @brief Returns the size of the buffer.
 *
 * @return uint_fast32_t - The size of the buffer.
 */
uint_fast32_t th_buffer_size(void);

#endif /* __TH_UTIL_H */
