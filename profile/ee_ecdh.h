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

#ifndef __EE_ECDH_H
#define __EE_ECDH_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum
{
    EE_P256R1 = 0
} ecdh_group_t;

#define HMAC_SIZE 32 // expected HMAC size (using sha256)
#define ECC_QSIZE 64 // public key size
#define ECC_DSIZE 32 // private key size
#define ECDH_SIZE 32 // secret size

// Fixed test API

void ee_ecdh(uint8_t *     p_public,  // input: peer public key, from host
             uint_fast32_t publen,    // input: peer public key length in bytes
             uint8_t *     p_private, // input: private key, from host
             uint_fast32_t prilen,    // input: private key length in bytes
             uint8_t *     p_secret,  // output: shared secret
             uint_fast32_t seclen, // input: size of buffer for secret, in bytes
             uint_fast32_t iterations // input: # of test iterations
);

// Implementation API

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ecdh_create(void **p_context // output: portable context
);

/**
 * Initialize to a group (must be in the EE_ enum)
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ecdh_init(
    void *        p_context, // input: portable context
    ecdh_group_t  group,     // input: see `ecdh_group_t` for options
    uint8_t *     p_private, // input: private key, from host
    uint_fast32_t prilen,    // input: private key length in bytes
    uint8_t *     p_public,  // input: peer public key, from host
    uint_fast32_t publen     // input: peer public key length in bytes
);

/**
 * Perform ECDH mixing.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_ecdh_calc_secret(
    void *        p_context, // input: portable context
    uint8_t *     p_secret,  // output: shared secret
    uint_fast32_t slen       // input: length of shared buffer in bytes
);

/**
 * Destroy the context created earlier.
 */
void th_ecdh_destroy(void *p_context // input: portable context
);

#endif // __EE_ECDH_H
