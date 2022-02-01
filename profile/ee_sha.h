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

typedef enum sha_size_t
{
    EE_SHA256 = 256,
    EE_SHA384 = 384,
    // SHA_512 = 512 // future expansion
} sha_size_t;

// Fixed test API

void ee_sha(sha_size_t     size,      // input: SHA algorithm size
            const uint8_t *p_in,      // input: bytes to hash
            uint_fast32_t  len,       // input: length of input in bytes
            uint8_t *      p_result,  // output: resulting digest
            uint_fast32_t  iterations // input: # of test iterations
);

// Implementation API

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_sha_create(void **    p_context, // output: portable context
                          sha_size_t size       // input: SHA algorithm size
);

/**
 * Initialize the context prior to a hash operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_sha_init(void *     p_context, // input: portable context
                        sha_size_t size       // input: SHA algorithm size
);

/**
 * Process the hash
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_sha_process(void *         p_context, // input: portable context
                           sha_size_t     size, // input: SHA algorithm size
                           const uint8_t *p_in, // input: data to hash
                           uint_fast32_t  len // input: length of data in bytes
);

/**
 * Compute the digest.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_sha_done(void *     p_context, // input: portable context
                        sha_size_t size,      // input: SHA algorithm size
                        uint8_t *  p_result   // output: digest, SHA_SIZE bytes
);

/**
 * Destroy the context created earlier.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
void th_sha_destroy(void *     p_context, // input: portable context
                    sha_size_t size       // input: SHA algorithm size
);

#endif // __EE_SHA_H
