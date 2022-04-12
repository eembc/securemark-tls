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
th_aes_create(void **p_context, ee_aes_mode_t mode)
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
th_aes_init(void *         p_context,
            const uint8_t *p_key,
            uint_fast32_t  keylen,
            const uint8_t *iv,
            ee_aes_func_t  func,
            ee_aes_mode_t  mode)
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
th_aes_deinit(void *p_context, ee_aes_mode_t mode)
{
    if (p_context)
    {
        wc_AesFree((Aes *)p_context);
    }
}

ee_status_t
th_aes_ecb_encrypt(void *p_context, const uint8_t *p_pt, uint8_t *p_ct)
{
    int ret;
    ret = wc_AesEcbEncrypt((Aes *)p_context, p_ct, p_pt, AES_BLOCK_SIZE);
    if (ret != 0) {
        th_printf("e-[wc_AesEcbEncrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ecb_decrypt(void *p_context, const uint8_t *p_ct, uint8_t *p_pt)
{
    int ret;
    ret = wc_AesEcbDecrypt((Aes *)p_context, p_pt, p_ct, AES_BLOCK_SIZE);
    if (ret != 0) {
        th_printf("e-[wc_AesEcbDecrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ctr_encrypt(void *         p_context,
                   const uint8_t *p_pt,
                   uint_fast32_t  ptlen,
                   uint8_t *      p_ct)
{
    int ret;
    ret = wc_AesCtrEncrypt((Aes *)p_context, p_ct, p_pt, ptlen);
    if (ret != 0) {
        th_printf("e-[wc_AesCtrEncrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ctr_decrypt(void *         p_context,
                   const uint8_t *p_ct,
                   uint_fast32_t  ctlen,
                   uint8_t *      p_pt)
{
    int ret;
    /* [sic] AesCtrEncrypt is also used for decrypt */
    ret = wc_AesCtrEncrypt((Aes *)p_context, p_pt, p_ct, ctlen);
    if (ret != 0) {
        th_printf("e-[wc_AesCtr(de)Encrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ccm_encrypt(void *         p_context,
                   const uint8_t *p_pt,
                   uint_fast32_t  ptlen,
                   uint8_t *      p_ct,
                   uint8_t *      p_tag,
                   uint_fast32_t  taglen,
                   const uint8_t *p_iv,
                   uint_fast32_t  ivlen)
{
    int ret;
    ret = wc_AesCcmEncrypt((Aes *)p_context,
                            p_ct,
                            p_pt,
                            ptlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0);
    if (ret != 0) {
        th_printf("e-[wc_AesCcmEncrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ccm_decrypt(void *         p_context,
                   const uint8_t *p_ct,
                   uint_fast32_t  ctlen,
                   uint8_t *      p_pt,
                   const uint8_t *p_tag,
                   uint_fast32_t  taglen,
                   const uint8_t *p_iv,
                   uint_fast32_t  ivlen)
{
    int ret;
    ret = wc_AesCcmDecrypt((Aes *)p_context,
                            p_pt,
                            p_ct,
                            ctlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0);
    if (ret != 0) {
        th_printf("e-[wc_AesCcmDecrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_gcm_encrypt(void *         p_context,
                   const uint8_t *p_pt,
                   uint_fast32_t  ptlen,
                   uint8_t *      p_ct,
                   uint8_t *      p_tag,
                   uint_fast32_t  taglen,
                   const uint8_t *p_iv,
                   uint_fast32_t  ivlen)
{
    int ret;
    ret = wc_AesGcmEncrypt((Aes *)p_context,
                            p_ct,
                            p_pt,
                            ptlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0);
    if (ret != 0) {
        th_printf("e-[wc_AesGcmEncrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_gcm_decrypt(void *         p_context,
                   const uint8_t *p_ct,
                   uint_fast32_t  ctlen,
                   uint8_t *      p_pt,
                   const uint8_t *p_tag,
                   uint_fast32_t  taglen,
                   const uint8_t *p_iv,
                   uint_fast32_t  ivlen)
{
    int ret;
    ret = wc_AesGcmDecrypt((Aes *)p_context,
                            p_pt,
                            p_ct,
                            ctlen,
                            p_iv,
                            ivlen,
                            p_tag,
                            taglen,
                            NULL,
                            0);
    if (ret != 0) {
        th_printf("e-[wc_AesGcmDecrypt: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

void
th_aes_destroy(void *p_context)
{
    if (p_context)
    {
        th_free(p_context);
    }
}
