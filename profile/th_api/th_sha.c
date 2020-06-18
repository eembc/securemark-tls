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

#include "ee_sha.h"

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_sha256_create(
    void **p_context // output: portable context
)
{
    #warning "th_sha256_create not implemented"
    return EE_STATUS_OK;
}

/**
 * Initialize the context prior to a hash operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_sha256_init(
    void *p_context // input: portable context
)
{
    #warning "th_sha256_init not implemented"
    return EE_STATUS_OK;
}

/**
 * Process the hash
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_sha256_process(
    void                *p_context, // input: portable context
    const unsigned char *p_in,      // input: data to hash    
    unsigned int         len        // input: length of data in bytes
)
{
    #warning "th_sha256_process not implemented"
    return EE_STATUS_OK;
}

/**
 * Compute the digest.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_sha256_done(
    void          *p_context,   // input: portable context
    unsigned char *p_result     // output: digest, SHA_SIZE bytes
)
{
    #warning "th_sha256_done not implemented"
    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
void
th_sha256_destroy(
    void *p_context // input: portable context
)
{
    #warning "th_sha256_destroy not implemented"
}
