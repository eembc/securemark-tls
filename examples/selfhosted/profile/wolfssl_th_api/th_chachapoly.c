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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#include "ee_chachapoly.h"

// Set during our init call since there's no portable context for enc/dec
uint8_t g_localKey[CHACHA20_POLY1305_AEAD_KEYSIZE];

/**
 * Create a context.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_create(void **pp_context // output: portable context
)
{
    // wolfCrypt creates uses a local context in its chachapoly functions
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
                   chachapoly_func_t func       // input: CHACHAPOLY_(ENC|DEC)
)
{
    if (keylen != CHACHA20_POLY1305_AEAD_KEYSIZE)
    {
        th_printf("e-[wolfSSL expects a %d-byte tag for ChaChaPoly\r\n", CHACHA20_POLY1305_AEAD_KEYSIZE);
    }
    th_memcpy(g_localKey, p_key, CHACHA20_POLY1305_AEAD_KEYSIZE);
    // wolfCrypt creates uses a local context in its chachapoly functions
    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 */
void
th_chachapoly_deinit(void *            p_context, // input: portable context
                     chachapoly_func_t func       // input: CHACHAPOLY_(ENC|DEC)
)
{
    // wolfCrypt creates uses a local context in its chachapoly functions
}

/**
 * Perform a ChaCha-Poly encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_encrypt(
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
    return wc_ChaCha20Poly1305_Encrypt(
        g_localKey,
        p_iv,
        p_aad,
        aadlen,
        p_pt,
        ptlen,
        p_ct,
        p_tag) == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
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
    return wc_ChaCha20Poly1305_Decrypt(
        g_localKey,
        p_iv,
        p_aad,
        aadlen,
        p_ct,
        ctlen,
        p_tag,
        p_pt) == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * Clean up the context created.
 */
void
th_chachapoly_destroy(void *p_context // input: portable context
)
{
    // wolfCrypt creates uses a local context in its chachapoly functions
}
