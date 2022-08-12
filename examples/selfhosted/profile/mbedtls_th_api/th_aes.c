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

typedef struct {
    ee_aes_mode_t aes_mode;
    union {
        mbedtls_aes_context aes_ctx;
        mbedtls_ccm_context ccm_ctx;
        mbedtls_gcm_context gcm_ctx;
    } ctx;
    union {
        struct {
            unsigned char nonce_counter[16];
            unsigned char stream_block[16];
            size_t nc_off;
        } aes_ctr;
    } additional_ctx;
} th_mbedtls_aes_context_t;

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_create(void **           p_context, // output: portable context
              ee_aes_mode_t mode       // input: EE_AES_ENC or EE_AES_DEC
)
{
    *p_context
            = (th_mbedtls_aes_context_t *)th_malloc(sizeof(th_mbedtls_aes_context_t));
    if (mode == EE_AES_ECB ||
        mode == EE_AES_CTR ||
        mode == EE_AES_CCM ||
        mode == EE_AES_GCM)
    {
        ((th_mbedtls_aes_context_t *)(*p_context))->aes_mode = mode;
    }
    else
    {
        th_free(*p_context);
        th_printf("e-[Unknown mode in th_aes128_create]\r\n");
        return EE_STATUS_ERROR;
    }

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_aes128_create]\r\n");
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
th_aes_init(void *            p_context, // input: portable context
            const uint8_t *   p_key,     // input: key
            uint32_t     keylen,    // input: length of key in bytes
            const uint8_t *   iv,        // input: IV buffer
            ee_aes_func_t     func,      // input: EE_AES_ENC or EE_AES_DEC
            ee_aes_mode_t     mode       // input: EE_AES_ECB|CCM|GCM
)
{
    (void) iv;
    int                  ret;
    int                  keybits;
    mbedtls_aes_context *p_ecb;
    mbedtls_ccm_context *p_ccm;
    mbedtls_gcm_context *p_gcm;

    keybits = keylen * 8;

    if (mode != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    if (mode == EE_AES_ECB || mode == EE_AES_CTR)
    {
        p_ecb = &((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx;
        mbedtls_aes_init(p_ecb);
        if (func == EE_AES_ENC)
        {
            ret = mbedtls_aes_setkey_enc(p_ecb, p_key, keybits);
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB ENC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        }
        else if (func == EE_AES_DEC)
        {
            ret = mbedtls_aes_setkey_dec(p_ecb, p_key, keybits);
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB DEC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        }
        if (mode == EE_AES_CTR) {
            th_memcpy(((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.nonce_counter, iv, EE_AES_CTR_IVLEN);
            th_memset(((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.stream_block, 0, 16);
            ((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.nc_off = 0;
        }
    }
    else if (mode == EE_AES_CCM)
    {
        p_ccm = &((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx;
        mbedtls_ccm_init(p_ccm);
        ret = mbedtls_ccm_setkey(p_ccm, MBEDTLS_CIPHER_ID_AES, p_key, keybits);
        if (ret != 0)
        {
            th_printf("e-[Failed to set CCM key: -0x%04x]\r\n", -ret);
            return EE_STATUS_ERROR;
        }
    }
    else if (mode == EE_AES_GCM)
    {
        p_gcm = &((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx;
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
        th_printf("e-[Unknown mode in th_aes128_init]\r\n");
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
th_aes_deinit(void *            p_context, // input: portable context
              ee_aes_mode_t     mode       // input: EE_AES_ECB|CCM|GCM
)
{
    if (mode == EE_AES_CCM)
    {
        mbedtls_ccm_free(&((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx);
    }
    else if (mode == EE_AES_GCM)
    {
        mbedtls_gcm_free(&((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx);
    }
}

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ecb_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext (AES_BLOCKSIZE bytes)
    uint8_t *      p_ct       // output: ciphertext (AES_BLOCKSIZE bytes)
)
{
    if (EE_AES_ECB != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_aes_crypt_ecb(&((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
                                 MBEDTLS_AES_ENCRYPT,
                                 p_pt,
                                 p_ct)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ecb_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext (AES_BLOCKSIZE bytes)
    uint8_t *      p_pt       // output: plaintext (AES_BLOCKSIZE bytes)
)
{
    if (EE_AES_ECB != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_aes_crypt_ecb(&((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
                                 MBEDTLS_AES_DECRYPT,
                                 p_ct,
                                 p_pt)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * @brief Perform an AES CTR encryption.
 *
 * @param p_context - The context from the `create` function
 * @param p_pt - Plaintext buffer
 * @param ptlen - Length of the plaintext buffer
 * @param p_ct - Ciphertext buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ctr_encrypt(void *         p_context,
                               const uint8_t *p_pt,
                               uint32_t  ptlen,
                               uint8_t *      p_ct)
{
    if (EE_AES_CTR != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_aes_crypt_ctr(&((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
                                 ptlen,
                                 &((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.nc_off,
                                 ((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.nonce_counter,
                                 ((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.stream_block,
                                 p_pt,
                                 p_ct)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * @brief Perform an AES CTR decryption.
 *
 * @param p_context - The context from the `create` function
 * @param p_ct - Ciphertext buffer
 * @param ctlen - Length of the ciphertext buffer
 * @param p_pt - Plaintext buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ctr_decrypt(void *         p_context,
                               const uint8_t *p_ct,
                               uint32_t  ctlen,
                               uint8_t *      p_pt)
{
    if (EE_AES_CTR != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_aes_crypt_ctr(&((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
                                 ctlen,
                                 &((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.nc_off,
                                 ((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.nonce_counter,
                                 ((th_mbedtls_aes_context_t *)p_context)->additional_ctx.aes_ctr.stream_block,
                                 p_ct,
                                 p_pt)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ccm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint32_t  ivlen      // input: IV length in bytes
)
{
    if (EE_AES_CCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_ccm_encrypt_and_tag(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx, // CCM context
               ptlen, // length of the input data in bytes
               p_iv,  // nonce (initialization vector)
               ivlen, // length of IV in bytes
               NULL,  // additional data
               0,     // length of additional data in bytes
               p_pt,  // buffer holding the input data
               p_ct,  // buffer holding the output data
               p_tag, // buffer holding the tag
               taglen // length of the tag to generate in bytes
               ) == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ccm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // input: tag
    uint32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint32_t  ivlen      // input: IV length in bytes
)
{
    if (EE_AES_CCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_ccm_auth_decrypt(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx, // CCM context
               ctlen,                            // length of the input data,
               p_iv,   // nonce (initialization vector)
               ivlen,  // length of IV in bytes
               NULL,  // additional data
               0, // length of additional data in bytes
               p_ct,   // buffer holding the input data
               p_pt,   // buffer holding the output data
               p_tag,  // buffer holding the tag
               taglen  // length of the tag to generate in bytes
               ) == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * Perform an AES/GCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_gcm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint32_t  ivlen      // input: IV length in bytes
)
{
    if (EE_AES_GCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_gcm_crypt_and_tag(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx, // GCM context
               MBEDTLS_GCM_ENCRYPT,
               ptlen,  // length of the input data in bytes
               p_iv,   // nonce (initialization vector)
               ivlen,  // length of IV in bytes
               NULL,  // additional data
               0, // length of additional data in bytes
               p_pt,   // buffer holding the input data
               p_ct,   // buffer holding the output data
               taglen, // length of the tag to generate in bytes
               p_tag   // buffer holding the tag
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
th_aes_gcm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint32_t  ctlen,     // input: length of plaintext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // output: tag
    uint32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint32_t  ivlen      // input: IV length in bytes
)
{
    if (EE_AES_GCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_gcm_auth_decrypt(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx, // GCM context
               ctlen,                            // length of the input data,
               p_iv,   // nonce (initialization vector)
               ivlen,  // length of IV in bytes
               NULL,  // additional data
               0, // length of additional data in bytes
               p_tag,  // buffer holding the tag
               taglen, // length of the tag to generate in bytes
               p_ct,   // buffer holding the input data
               p_pt    // buffer holding the output data
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
th_aes_destroy(void *p_context // input: portable context
)
{
    ee_aes_mode_t mode = ((th_mbedtls_aes_context_t *)p_context)->aes_mode;
    if (mode == EE_AES_CCM || mode == EE_AES_CTR)
    {
        mbedtls_aes_free(&((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx);
    }
    else if (mode == EE_AES_CCM)
    {
        mbedtls_ccm_free(&((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx);
    }
    else if (mode == EE_AES_GCM)
    {
        mbedtls_gcm_free(&((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx);
    }
    th_free(p_context);
}
