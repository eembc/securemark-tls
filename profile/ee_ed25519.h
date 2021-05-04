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

#ifndef __EE_ED25519_H
#define __EE_ED25519_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

// Fixed test API

/**
 * Perform an EdDSA sign a given number of times.
 */
void ee_ed25519_sign(
    uint8_t *      p_hash,    // input: digest
    uint_fast32_t  hlen,      // input: length of digest in bytes
    uint8_t *      p_sig,     // output: signature
    uint_fast32_t *p_slen,    // in/out: input=MAX slen, output=resultant
    uint8_t *      p_private, // input: private key (from host)
    uint_fast32_t  plen,      // input: private key length in bytes
    uint_fast32_t  iterations // input: # of test iterations
);

/**
 * Perform an EdDSA verify a given number of times.
 */
void ee_ed25519_verify(
    uint8_t *     p_hash,    // input: digest
    uint_fast32_t hlen,      // input: length of digest in bytes
    uint8_t *     p_sig,     // input: signature
    uint_fast32_t slen,      // input: length of signature in bytes
    uint8_t *     p_private, // input: private key (from host)
    uint_fast32_t plen,      // input: private key length in bytes
    uint_fast32_t iterations // input: # of test iterations
);

// Implementation API

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ed25519_create(void **p_context // output: portable context
);

/**
 * Initialize to a group (must be in the EE_ enum) with a predefined
 * private key.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ed25519_init(
    void *        p_context, // input: portable context
    uint8_t *     p_private, // input: private key from host
    uint_fast32_t plen       // input: length of private key in bytes
);

/**
 * Create a signature using the specified hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ed25519_sign(
    void *         p_context, // input: portable context
    uint8_t *      p_hash,    // input: digest
    uint_fast32_t  hlen,      // input: length of digest in bytes
    uint8_t *      p_sig,     // output: signature
    uint_fast32_t *p_slen     // inout: input=MAX slen, output=resultant
);

/**
 * Verify a signature and digest.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ed25519_verify(
    void *        p_context, // input: portable context
    uint8_t *     p_hash,    // input: sha256 digest
    uint_fast32_t hlen,      // input: length of digest in bytes
    uint8_t *     p_sig,     // output: signature
    uint_fast32_t slen       // input: length of signature in bytes
);

/**
 * Destroy the context created earlier.
 */
void th_ed25519_destroy(void *p_context // portable context
);

#endif // __EE_ED25519_H
