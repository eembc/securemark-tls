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

ee_status_t
th_aes_create(void **           p_context, // output: portable context
              ee_aes_mode_t mode       // input: EE_AES_ENC or EE_AES_DEC
)
{
    *p_context = (Aes *)th_malloc(sizeof(Aes));
    if (*p_context == NULL)
    {
        th_printf("e-[th_aes_create malloc() fail]\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_init(void *            p_context, // input: portable context
            const uint8_t *   p_key,     // input: key
            uint_fast32_t     keylen,    // input: length of key in bytes
            const uint8_t *   iv,        // input: IV if CTR mode, or NULL
            ee_aes_func_t    func,      // input: EE_AES_ENC or EE_AES_DEC
            ee_aes_mode_t mode       // input: see ee_aes_mode_t
)
{
    int  ret = -1;
    int  dir = 0;
    Aes *aes;

    aes = (Aes *)p_context;
    ret = wc_AesInit(aes, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[wc_AesInit: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    if (mode == EE_AES_ECB)
    {
        dir = (func == EE_AES_ENC) ? AES_ENCRYPTION : AES_DECRYPTION;
        ret = wc_AesSetKey(aes, p_key, keylen, NULL, dir);
    }
    else if (mode == EE_AES_CTR)
    {
        /* NOTE: CTR modes also use ENCRYPTION for the decrypt side */
        dir = AES_ENCRYPTION;
        ret = wc_AesSetKey(aes, p_key, keylen, iv, dir);
    }
    else if (mode == EE_AES_CCM)
    {
        ret = wc_AesCcmSetKey(aes, p_key, keylen);
    }
    else if (mode == EE_AES_GCM)
    {
        ret = wc_AesGcmSetKey(aes, p_key, keylen);
    }
    else
    {
        th_printf("e-[th_aes_init unknown mode]\r\n");
        return EE_STATUS_ERROR;
    }

    if (ret != 0)
    {
        th_printf("e-[th_aes_init failed to set AES key: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

void
th_aes_deinit(void *            p_context, // input: portable context
              ee_aes_mode_t mode       // input: see ee_aes_mode_t
)
{
    if (p_context)
    {
        wc_AesFree((Aes *)p_context);
    }
}

ee_status_t
th_aes_ecb_encrypt(void *         p_context, // input: portable context
                   const uint8_t *p_pt,      // input: plaintext
                   uint8_t *      p_ct       // output: ciphertext
)
{
    return wc_AesEcbEncrypt((Aes *)p_context, p_ct, p_pt, AES_BLOCK_SIZE)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

ee_status_t
th_aes_ecb_decrypt(void *         p_context, // input: portable context
                   const uint8_t *p_ct,      // input: ciphertext
                   uint8_t *      p_pt       // output: plaintext
)
{
    return wc_AesEcbDecrypt((Aes *)p_context, p_pt, p_ct, AES_BLOCK_SIZE)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

ee_status_t
th_aes_ctr_encrypt(void *         p_context, // input: portable context
                   const uint8_t *p_pt,      // input: plaintext
                   uint_fast32_t  ptlen, // input: length of plaintext in bytes
                   uint8_t *      p_ct   // output: ciphertext
)
{
    return wc_AesCtrEncrypt((Aes *)p_context, p_ct, p_pt, ptlen)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

ee_status_t
th_aes_ctr_decrypt(void *         p_context, // input: portable context
                   const uint8_t *p_ct,      // input: ciphertext
                   uint_fast32_t  ctlen, // input: length of ciphertext in bytes
                   uint8_t *      p_pt   // output: plaintext
)
{
    return wc_AesCtrEncrypt((Aes *)p_context, p_pt, p_ct, ctlen)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

ee_status_t
th_aes_ccm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return wc_AesCcmEncrypt((Aes *)p_context,
                            p_ct,
                            p_pt,
                            ptlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

ee_status_t
th_aes_ccm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return wc_AesCcmDecrypt((Aes *)p_context,
                            p_pt,
                            p_ct,
                            ctlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

ee_status_t
th_aes_gcm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return wc_AesGcmEncrypt((Aes *)p_context,
                            p_ct,
                            p_pt,
                            ptlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

ee_status_t
th_aes_gcm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of plaintext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
    return wc_AesGcmDecrypt((Aes *)p_context,
                            p_pt,
                            p_ct,
                            ctlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0)
               ? EE_STATUS_ERROR
               : EE_STATUS_OK;
}

void
th_aes_destroy(void *            p_context) // input: portable context
{
    if (p_context)
    {
        th_free(p_context);
    }
}
