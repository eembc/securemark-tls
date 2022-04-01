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

#ifndef __EE_ECDSA_H
#define __EE_ECDSA_H

#include "ee_main.h"
#include "ee_ecdh.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum ee_ecdsa_func_t
{
    EE_ECDSA_SIGN = 0,
    EE_ECDSA_VERIFY
} ee_ecdsa_func_t;

/**
 * @brief Performs an ECDSA sign or verify operation some number of iterations.
 *
 * @param group The ECC curve to use (non-Edwards)
 * @param func The operation enum to perform
 * @param p_msg Pointer to the message octet buffer to sign
 * @param mlen Length of the message buffer
 * @param p_sig Pointer to a buffer for the signature
 * @param p_slen As input, size of the buffer; as output, octets used
 * @param p_private The private key for the context (public will be generated)
 * @param plen Length of private key
 * @param iter Number of iterations
 */
void ee_ecdsa(ee_ecdh_group_t group,
              ee_ecdsa_func_t func,
              uint8_t *       p_msg,
              uint_fast32_t   mlen,
              uint8_t *       p_sig,
              uint_fast32_t * p_slen,
              uint8_t *       p_private,
              uint_fast32_t   plen,
              uint_fast32_t   iter);

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ecdsa_create(
    void **         p_context, // output: portable context
    ee_ecdh_group_t group      // input: see `ee_ecdh_group_t` for options
);

/**
 * Initialize to a group (must be in the EE_ enum) with a predefined
 * private key.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ecdsa_init(
    void *          p_context, // input: portable context
    ee_ecdh_group_t group,     // input: see `ee_ecdh_group_t` for options
    uint8_t *       p_private, // input: private key from host
    uint_fast32_t   plen       // input: length of private key in bytes
);

/**
 * Create a signature using the specified hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ecdsa_sign(
    void *          p_context, // input: portable context
    ee_ecdh_group_t group,     // input: see `ee_ecdh_group_t` for options
    uint8_t *       p_hash,    // input: sha256 digest
    uint_fast32_t   hlen,      // input: length of digest in bytes
    uint8_t *       p_sig,     // output: signature
    uint_fast32_t * p_slen     // in/out: input=MAX slen, output=resultant
);

/**
 * Create a signature using SHA256 hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ecdsa_verify(
    void *          p_context, // input: portable context
    ee_ecdh_group_t group,     // input: see `ee_ecdh_group_t` for options
    uint8_t *       p_hash,    // input: sha256 digest
    uint_fast32_t   hlen,      // input: length of digest in bytes
    uint8_t *       p_sig,     // output: signature
    uint_fast32_t   slen       // input: length of signature in bytes
);

/**
 * Destroy the context created earlier.
 */
void th_ecdsa_destroy(
    void *          p_context, // portable context
    ee_ecdh_group_t group      // input: see `ee_ecdh_group_t` for options
);

#endif // __EE_ECDSA_H
