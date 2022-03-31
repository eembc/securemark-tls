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

#include "ee_ecdh.h"

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_create(void **      p_context, // output: portable context
               ee_ecdh_group_t group      // input: see `ee_ecdh_group_t` for options
)
{
#warning "th_ecdh_create not implemented"
    return EE_STATUS_OK;
}

/**
 * Initialize to a group (must be in the EE_ enum)
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_init(void *        p_context, // input: portable context
             ee_ecdh_group_t  group,     // input: see `ee_ecdh_group_t` for options
             uint8_t *     p_private, // input: private key, from host
             uint_fast32_t prilen,    // input: private key length in bytes
             uint8_t *     p_public,  // input: peer public key, from host
             uint_fast32_t publen     // input: peer public key length in bytes
)
{
#warning "th_ecdh_init not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform ECDH mixing.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_calc_secret(
    void *        p_context, // input: portable context
    ee_ecdh_group_t  group,     // input: curve group
    uint8_t *     p_secret,  // output: shared secret
    uint_fast32_t slen       // input: length of shared buffer in bytes
)
{
#warning "th_ecdh_calc_secret not implemented"
    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdh_destroy(void *p_context // input: portable context
)
{
#warning "th_ecdh_destroy not implemented"
}
