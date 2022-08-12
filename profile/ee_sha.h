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

#ifndef __EE_SHA_H
#define __EE_SHA_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

/* Dual purpose enum: is also the number of bits in the SHA */
typedef enum ee_sha_size_t
{
    EE_SHA256 = 256,
    EE_SHA384 = 384,
    /* SHA_512 = 512 ... future expansion */
} ee_sha_size_t;

/**
 * @brief Perform a number of SHA operations on an input buffer.
 *
 * @param size - See the `ee_sha_size_t` enum.
 * @param p_in - The input buffer
 * @param len - Length of the input buffer
 * @param p_out - Output buffer (must be large enough to hold the digest)
 * @param iter - Number of iterations to perform
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_sha(ee_sha_size_t  size,
                const uint8_t *p_in,
                uint32_t  len,
                uint8_t *      p_out,
                uint32_t  iter);

/**
 * @brief Perform a number of SHA operations on a set of input buffers.
 *
 * @param size - See the `ee_sha_size_t` enum.
 * @param pp_in - The input buffers
 * @param p_len - Length of each input buffer
 * @param pp_out - Output buffers (must be large enough to hold the digest)
 * @param count - Number of entries in the in/len/out buffers
 * @param iter - Number of iterations to perform
 * @return uint32_t - Execution time in microseconds
 */
uint32_t
ee_sha_multi(ee_sha_size_t  size,
       uint8_t       *pp_in[],
       uint32_t  p_len[],
       uint8_t       *pp_out[],
       uint32_t  count,
       uint32_t  iter);

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @param size - See the `ee_sha_size_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_sha_create(void **pp_context, ee_sha_size_t size);

/**
 * @brief Initialize the context.
 *
 * @param p_context - The context from the `create` function
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_sha_init(void *p_context);

/**
 * @brief Add more data to the running digest (also called update).
 *
 * @param p_context - The context from the `create` function
 * @param p_in - The input buffer
 * @param len - Length of the input buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_sha_process(void *         p_context,
                           const uint8_t *p_in,
                           uint32_t  len);

/**
 * @brief Complete the digest and populate the result. The result buffer must
 * be large enough to hold the digest.
 *
 * @param p_context - The context from the `create` function
 * @param p_out - The output digest buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_sha_done(void *p_context, uint8_t *p_out);

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 */
void th_sha_destroy(void *p_context);

#endif /* __EE_SHA_H */
