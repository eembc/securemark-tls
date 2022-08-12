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

ee_status_t
th_chachapoly_create(void **pp_context)
{
    /* wolfCrypt creates uses a local context in its chachapoly functions */
    *pp_context = (uint8_t *)th_malloc(CHACHA20_POLY1305_AEAD_KEYSIZE);
    if (*pp_context == NULL) {
        th_printf("e-[th_chachapoly_create: malloc fail]\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_chachapoly_init(void *p_context, const uint8_t *p_key, uint32_t keylen)
{
    uint8_t *p_ctx = (uint8_t *)p_context;

    if (keylen != CHACHA20_POLY1305_AEAD_KEYSIZE)
    {
        th_printf("e-[wolfSSL expects a %d-byte tag for ChaChaPoly]\r\n",
                  CHACHA20_POLY1305_AEAD_KEYSIZE);
    }
    th_memcpy(p_ctx, p_key, CHACHA20_POLY1305_AEAD_KEYSIZE);
    /* wolfCrypt creates uses a local context in its chachapoly functions */
    return EE_STATUS_OK;
}

void
th_chachapoly_deinit(void *p_context)
{
    /* wolfCrypt creates uses a local context in its chachapoly functions */
    /* No need to decrypt anything */
}

ee_status_t
th_chachapoly_encrypt(void *         p_context,
                      const uint8_t *p_pt,
                      uint32_t  ptlen,
                      uint8_t *      p_ct,
                      uint8_t *      p_tag,
                      uint32_t  taglen,
                      uint8_t *      p_iv,
                      uint32_t  ivlen)
{
    uint8_t *p_key = (uint8_t *)p_context;

    return wc_ChaCha20Poly1305_Encrypt(
               p_key, p_iv, NULL, 0, p_pt, ptlen, p_ct, p_tag)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

ee_status_t
th_chachapoly_decrypt(void *         p_context,
                      const uint8_t *p_ct,
                      uint32_t  ctlen,
                      uint8_t *      p_pt,
                      uint8_t *      p_tag,
                      uint32_t  taglen,
                      uint8_t *      p_iv,
                      uint32_t  ivlen)
{
    uint8_t *p_key = (uint8_t *)p_context;

    return wc_ChaCha20Poly1305_Decrypt(
               p_key, p_iv, NULL, 0, p_ct, ctlen, p_tag, p_pt)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

void
th_chachapoly_destroy(void *p_context)
{
    th_free(p_context);
}
