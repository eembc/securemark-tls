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
#include <wolfssl/wolfcrypt/aes.h>

#include "ee_aes.h"

/* can be set for static memory use */
#define HEAP_HINT NULL

/* used with crypto callbacks and async */
#define DEVID -1

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
    *p_context = (Aes*)th_malloc(sizeof(Aes));
    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail\r\n");
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
th_aes128_init(
    void                *p_context, // input: portable context
    const unsigned char *p_key,     // input: key
    unsigned int         keylen,    // input: length of key in bytes
    unsigned int         rounds,    // input: number of AES rounds
    aes_function_t       func,      // input: AES_ENC or AES_DEC
    aes_cipher_mode_t    mode       // input: AES_ECB or AES_CCM
)
{
    int  ret = -1, dir = 0;
    Aes* aes;

    if (p_context == NULL) {
        th_printf("e-[Failed to input was NULL]\r\n");
        return EE_STATUS_ERROR;
    }

    aes = (Aes*)p_context;
    ret = wc_AesInit(aes, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[Failed to initialize AES key: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    if (mode == AES_ECB)
    {
        if (func == AES_ENC)
        {
            dir = AES_ENCRYPTION;
        }
        else if (func == AES_DEC)
        {
            /* NOTE: CTR modes also use ENCRYPTION for the decrypt side */
            dir = AES_DECRYPTION;
        }

        ret = wc_AesSetKey(aes, p_key, keylen, NULL, dir);
    }

    /* AEAD versions of AES */
    if (mode == AES_CCM)
    {
        ret = wc_AesCcmSetKey(aes, p_key, keylen);
    }

    if (mode == AES_GCM)
    {
        ret = wc_AesGcmSetKey(aes, p_key, keylen);
    }

    if (ret != 0)
    {
        th_printf("e-[Failed to set AES key: -0x%04x]\r\n", -ret);
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
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
)
{
    wc_AesFree((Aes*)p_context);
}

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ecb_encrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_pt,      // input: plaintext (AES_BLOCKSIZE bytes)
    unsigned char       *p_ct       // output: ciphertext (AES_BLOCKSIZE bytes)
)
{
    int ret;

    ret = wc_AesEcbEncrypt((Aes*)p_context, p_ct, p_pt, AES_BLOCK_SIZE);
    if (ret == 0)
    {
        return EE_STATUS_OK;
    }
    return EE_STATUS_ERROR;
}

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ecb_decrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_ct,      // input: ciphertext (AES_BLOCKSIZE bytes)
    unsigned char       *p_pt       // output: plaintext (AES_BLOCKSIZE bytes)
)
{
    int ret;

    ret = wc_AesEcbDecrypt((Aes*)p_context, p_pt, p_ct, AES_BLOCK_SIZE);
    if (ret == 0)
    {
        return EE_STATUS_OK;
    }
    return EE_STATUS_ERROR;
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
    int ret;

    ret = wc_AesCcmEncrypt((Aes*)p_context, p_ct, p_pt, ptlen, p_iv, ivlen,
                           p_tag, taglen, NULL, 0);
    if (ret != 0)
    {
        th_printf("e-[Failed perform CCM encrypt: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
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
    int ret;

    ret = wc_AesCcmDecrypt((Aes*)p_context, p_pt, p_ct, ctlen, p_iv, ivlen,
                           p_tag, taglen, NULL, 0);
    if (ret != 0)
    {
        th_printf("e-[Failed perform CCM decrypt: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
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
    return wc_AesGcmEncrypt(
        (Aes*)p_context, // GCM context
        p_ct,   // buffer holding the output data
        p_pt,   // buffer holding the input data
        ptlen,  // length of the input data in bytes
        p_iv,   // nonce (initialization vector)
        ivlen,  // length of IV in bytes
        p_tag,  // buffer holding the tag
        taglen, // length of the tag to generate in bytes
        p_aad,  // additional data
        aadlen // length of additional data in bytes
        ) == 0
        ? EE_STATUS_OK
        : EE_STATUS_ERROR;
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
    return wc_AesGcmDecrypt(
        (Aes*)p_context, // GCM context
        p_pt,   // buffer holding the input data
        p_ct,   // buffer holding the output data
        ctlen,  // length of the input data in bytes
        p_iv,   // nonce (initialization vector)
        ivlen,  // length of IV in bytes
        p_tag,  // buffer holding the tag
        taglen, // length of the tag to generate in bytes
        p_aad,  // additional data
        aadlen // length of additional data in bytes
        ) == 0
        ? EE_STATUS_OK
        : EE_STATUS_ERROR;
}

/**
 * Clean up the context created.
 * 
 * Indicate the mode that was used for _create()
 */
void
th_aes128_destroy(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
)
{
    th_free(p_context);
}
