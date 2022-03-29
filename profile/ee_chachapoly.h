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

#ifndef __EE_CHACHAPOLY_H
#define __EE_CHACHAPOLY_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum
{
    EE_CHACHAPOLY_ENC = 0,
    EE_CHACHAPOLY_DEC
} chachapoly_func_t;

#define EE_CHACHAPOLY_KEYSIZE 32u
#define EE_CHACHAPOLY_IVSIZE  12u
#define EE_CHACHAPOLY_TAGSIZE 16u

// Fixed test API

void ee_chachapoly(
    chachapoly_func_t func,      // input: CHACHAPOLY_(ENC|DEC)
    uint8_t *         p_key,     // input: key
    const uint8_t *   p_add,     // input: additional authentication data
    uint_fast32_t     addlen,    // input: length of AAD in bytes
    uint8_t *         p_iv,      // input: initialization vector
    uint8_t *         p_in,      // input: pointer to source input (pt or ct)
    uint_fast32_t     len,       // input: length of input in bytes
    uint8_t *         p_tag,     // inout: output in encrypt, input on decrypt
    uint8_t *         p_out,     // output: pointer to output buffer
    uint_fast32_t     iterations // input: # of test iterations
);

// Implementation API

/**
 * Create a context.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_chachapoly_create(void **pp_context); // output: portable context

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_chachapoly_init(
    void *            p_context, // input: portable context
    const uint8_t *   p_key,     // input: key
    uint_fast32_t     keylen,    // input: length of key in bytes
    chachapoly_func_t func       // input: CHACHAPOLY_(ENC|DEC)
);

/**
 * Perform any cleanup required by init, but don't destroy the context.
 */
void th_chachapoly_deinit(void *p_context,       // input: portable context
                          chachapoly_func_t func // input: CHACHAPOLY_(ENC|DEC)
);

/**
 * Perform a ChaCha-Poly encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_chachapoly_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_add,     // input: additional authentication data
    uint_fast32_t  addlen,    // input: length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output_ ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
);

/**
 * Perform a ChaCha-decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_chachapoly_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_add,     // input: additional authentication data
    uint_fast32_t  addlen,    // input: length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output_ plaintext
    uint8_t *      p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
);

/**
 * Clean up the context created.
 */
void th_chachapoly_destroy(void *p_context); // input: portable context

#endif // __EE_CHACHAPOLY_H
