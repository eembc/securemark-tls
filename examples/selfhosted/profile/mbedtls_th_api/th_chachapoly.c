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

#include "mbedtls/chachapoly.h"
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
    *pp_context = (mbedtls_chachapoly_context *)th_malloc(
        sizeof(mbedtls_chachapoly_context));
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
                   uint_fast32_t     keylen    // input: length of key in bytes
)
{
    // mbedtls doesn't use func_t on init.
    int                         ret;
    mbedtls_chachapoly_context *context
        = (mbedtls_chachapoly_context *)p_context;
    mbedtls_chachapoly_init(context);
    ret = mbedtls_chachapoly_setkey(p_context, p_key);
    if (ret != 0)
    {
        th_printf("e-[mbedtls failed to set ChaChaPoly key: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 */
void
th_chachapoly_deinit(void *            p_context) // input: portable context
{
    // mbedtls doesn't care about enc/dec on deinit
    // TODO: Can we remove func_t?
    mbedtls_chachapoly_free((mbedtls_chachapoly_context *)p_context);
}

/**
 * Perform a ChaCha-Poly encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_chachapoly_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output_ ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return mbedtls_chachapoly_encrypt_and_tag(
               (mbedtls_chachapoly_context *)p_context,
               ptlen,
               p_iv,
               NULL,
               0,
               p_pt,
               p_ct,
               p_tag)
                   == 0
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
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output_ plaintext
    uint8_t *      p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return mbedtls_chachapoly_auth_decrypt(
               (mbedtls_chachapoly_context *)p_context,
               ctlen,
               p_iv,
               NULL,
               0,
               p_tag,
               p_ct,
               p_pt)
                   == 0
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
    mbedtls_chachapoly_free((mbedtls_chachapoly_context *)p_context);
    th_free(p_context);
}
