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

#include "ee_chachapoly.h"

/**
 * Create a context.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_create(void **pp_context // output: portable context
)
{
#warning "th_chachapoly_create not implemented"
    return EE_STATUS_OK;
}

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_init(void *            p_context, // input: portable context
                   const uint8_t *   p_key,     // input: key
                   uint_fast32_t     keylen,    // input: length of key in bytes
                   ee_chachapoly_func_t func       // input: CHACHAPOLY_(ENC|DEC)
)
{
#warning "th_chachapoly_init not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 */
void
th_chachapoly_deinit(void *            p_context, // input: portable context
                     ee_chachapoly_func_t func       // input: CHACHAPOLY_(ENC|DEC)
) {
#warning "th_chachapoly_deinit not implemented"
}

/**
 * Perform a ChaCha-Poly encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_chachapoly_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: Additional Authentication Data
    uint_fast32_t  aadlen,    // input: Length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output_ ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
#warning "th_chachapoly_encrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform a ChaCha-decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: Additional Authentication Data
    uint_fast32_t  aadlen,    // input: Length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output_ plaintext
    uint8_t *      p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
#warning "th_chachapoly_decrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Clean up the context created.
 */
void
th_chachapoly_destroy(void *p_context // input: portable context
)
{
#warning "th_chachapoly_destroy not implemented"
}
