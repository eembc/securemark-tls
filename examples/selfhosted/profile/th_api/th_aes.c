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

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/gcm.h"
#include "ee_aes.h"

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_create(
    void              **p_context,  // output: portable context
    aes_cipher_mode_t   mode        // input: AES_ENC or AES_DEC
)
{
    if (mode == AES_ECB)
    {
        *p_context = 
            (mbedtls_aes_context *)th_malloc(sizeof(mbedtls_aes_context));
    }
    else if (mode == AES_CCM)
    {
        *p_context = 
            (mbedtls_ccm_context *)th_malloc(sizeof(mbedtls_ccm_context));
    }
    else if (mode == AES_GCM)
    {
        *p_context = 
            (mbedtls_gcm_context *)th_malloc(sizeof(mbedtls_gcm_context));
    }
    else
    {
        th_printf("e-[Unknown mode in th_aes128_create\r\n");
        return EE_STATUS_ERROR;        
    }

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_aes128_create\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_init(void *            p_context, // input: portable context
               const uint8_t *   p_key,     // input: key
               uint_fast32_t     keylen,    // input: length of key in bytes
               uint_fast32_t     rounds,    // input: number of AES rounds
               aes_function_t    func,      // input: AES_ENC or AES_DEC
               aes_cipher_mode_t mode       // input: AES_ECB|CCM|GCM
)
{
    int                  ret;
    int                  keybits;
    mbedtls_aes_context *p_ecb;
    mbedtls_ccm_context *p_ccm;
    mbedtls_gcm_context *p_gcm;

    keybits = keylen    * 8;
    
    if (mode == AES_ECB)
    { 
        p_ecb = (mbedtls_aes_context *)p_context;
        mbedtls_aes_init(p_ecb);
        if (func == AES_ENC)
        {
            ret = mbedtls_aes_setkey_enc(p_ecb, p_key, keybits);
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB ENC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        }
        else if (func == AES_DEC)
        {
            ret = mbedtls_aes_setkey_dec(p_ecb, p_key, keybits);
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB DEC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        } 
    }
    else if (mode == AES_CCM)
    {
        p_ccm = (mbedtls_ccm_context *)p_context;
        mbedtls_ccm_init(p_ccm);
        ret = mbedtls_ccm_setkey(p_ccm, MBEDTLS_CIPHER_ID_AES, p_key, keybits);
        if (ret != 0)
        {
            th_printf("e-[Failed to set CCM key: -0x%04x]\r\n", -ret);
            return EE_STATUS_ERROR;
        }
    }
    else if (mode == AES_GCM)
    {
        p_gcm = (mbedtls_gcm_context *)p_context;
        mbedtls_gcm_init(p_gcm);
        ret = mbedtls_gcm_setkey(p_gcm, MBEDTLS_CIPHER_ID_AES, p_key, keybits);
        if (ret != 0)
        {
            th_printf("e-[Failed to set GCM key: -0x%04x]\r\n", -ret);
            return EE_STATUS_ERROR;
        }
    }
    else
    {
        th_printf("e-[Unknown mode in th_aes128_init\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 *
 * Some implementations of AES perform allocations on init and require a
 * de-init before initializing again, without destroying the context.
 */
void
th_aes128_deinit(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB|CCM|GCM
)
{
    if (mode == AES_CCM)
    {
        mbedtls_ccm_free((mbedtls_ccm_context *)p_context);
    }
    else if (mode == AES_GCM)
    {
        mbedtls_gcm_free((mbedtls_gcm_context *)p_context);
    }
}

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes128_ecb_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext (AES_BLOCKSIZE bytes)
    uint8_t *      p_ct       // output: ciphertext (AES_BLOCKSIZE bytes)
)
{
    return mbedtls_aes_crypt_ecb((mbedtls_aes_context *)p_context,
        MBEDTLS_AES_ENCRYPT, p_pt, p_ct) == 0 ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ecb_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext (AES_BLOCKSIZE bytes)
    uint8_t *      p_pt       // output: plaintext (AES_BLOCKSIZE bytes)
)
{
    return mbedtls_aes_crypt_ecb((mbedtls_aes_context *)p_context,
                                 MBEDTLS_AES_DECRYPT,
                                 p_ct,
                                 p_pt)
      == 0 ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ccm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return mbedtls_ccm_encrypt_and_tag(
        (mbedtls_ccm_context *)p_context,      // CCM context
        ptlen,      // length of the input data in bytes
        p_iv,       // nonce (initialization vector)
        ivlen,      // length of IV in bytes
        NULL,       // additional data
        0,          // length of additional data in bytes
        p_pt,       // buffer holding the input data
        p_ct,       // buffer holding the output data
        p_tag,      // buffer holding the tag
        taglen      // length of the tag to generate in bytes
    ) == 0 ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ccm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output: plaintext
    uint8_t *      p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return mbedtls_ccm_auth_decrypt(
        (mbedtls_ccm_context *)p_context,      // CCM context 
        ctlen,      // length of the input data, 
        p_iv,       // nonce (initialization vector)
        ivlen,      // length of IV in bytes
        p_aad,      // additional data
        aadlen,     // length of additional data in bytes
        p_ct,       // buffer holding the input data
        p_pt,       // buffer holding the output data
        p_tag,      // buffer holding the tag
        taglen      // length of the tag to generate in bytes
    ) == 0 ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Perform an AES/GCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_gcm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return mbedtls_gcm_crypt_and_tag(
        (mbedtls_gcm_context *)p_context,      // GCM context
        MBEDTLS_GCM_ENCRYPT,
        ptlen,      // length of the input data in bytes
        p_iv,       // nonce (initialization vector)
        ivlen,      // length of IV in bytes
        p_aad,      // additional data
        aadlen,     // length of additional data in bytes
        p_pt,       // buffer holding the input data
        p_ct,       // buffer holding the output data
        taglen,     // length of the tag to generate in bytes
        p_tag       // buffer holding the tag
    ) == 0 ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Perform an AES/GCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_gcm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of plaintext in bytes
    uint8_t *      p_pt,      // output: plaintext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return mbedtls_gcm_auth_decrypt(
        (mbedtls_gcm_context *)p_context,      // GCM context 
        ctlen,      // length of the input data, 
        p_iv,       // nonce (initialization vector)
        ivlen,      // length of IV in bytes
        p_aad,      // additional data
        aadlen,     // length of additional data in bytes
        p_tag,      // buffer holding the tag
        taglen,     // length of the tag to generate in bytes
        p_ct,       // buffer holding the input data
        p_pt        // buffer holding the output data
    ) == 0 ? EE_STATUS_OK : EE_STATUS_ERROR;
}

/**
 * Clean up the context created.
 * 
 * Indicate the mode that was used for _create()
 */
void
th_aes128_destroy(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB|CCM|GCM
)
{
    if (mode == AES_CCM)
    {
        mbedtls_ccm_free((mbedtls_ccm_context *)p_context);
    }
    else if (mode == AES_GCM)
    {
        mbedtls_gcm_free((mbedtls_gcm_context *)p_context);
    }
    th_free(p_context);
}
