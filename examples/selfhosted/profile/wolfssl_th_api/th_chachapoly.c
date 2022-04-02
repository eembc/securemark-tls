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

/* Set during our init call since there's no portable context for enc/dec */
uint8_t g_localKey[CHACHA20_POLY1305_AEAD_KEYSIZE];

ee_status_t
th_chachapoly_create(void **pp_context 
)
{
    /* wolfCrypt creates uses a local context in its chachapoly functions */
    return EE_STATUS_OK;
}

ee_status_t
th_chachapoly_init(void *            p_context, 
                   const uint8_t *   p_key,     
                   uint_fast32_t     keylen    
)
{
    if (keylen != CHACHA20_POLY1305_AEAD_KEYSIZE)
    {
        th_printf("e-[wolfSSL expects a %d-byte tag for ChaChaPoly]\r\n",
                  CHACHA20_POLY1305_AEAD_KEYSIZE);
    }
    th_memcpy(g_localKey, p_key, CHACHA20_POLY1305_AEAD_KEYSIZE);
    /* wolfCrypt creates uses a local context in its chachapoly functions */
    return EE_STATUS_OK;
}

void
th_chachapoly_deinit(void *            p_context 
)
{
    /* wolfCrypt creates uses a local context in its chachapoly functions */
}

ee_status_t
th_chachapoly_encrypt(
    void *         p_context, 
    const uint8_t *p_pt,      
    uint_fast32_t  ptlen,     
    uint8_t *      p_ct,      
    uint8_t *      p_tag,     
    uint_fast32_t  taglen,    
    uint8_t *      p_iv,      
    uint_fast32_t  ivlen      
)
{
    return wc_ChaCha20Poly1305_Encrypt(
               g_localKey, p_iv, NULL, 0, p_pt, ptlen, p_ct, p_tag)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

ee_status_t
th_chachapoly_decrypt(
    void *         p_context, 
    const uint8_t *p_ct,      
    uint_fast32_t  ctlen,     
    uint8_t *      p_pt,      
    uint8_t *      p_tag,     
    uint_fast32_t  taglen,    
    uint8_t *      p_iv,      
    uint_fast32_t  ivlen      
)
{
    return wc_ChaCha20Poly1305_Decrypt(
               g_localKey, p_iv, NULL, 0, p_ct, ctlen, p_tag, p_pt)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

void
th_chachapoly_destroy(void *p_context 
)
{
    /* wolfCrypt creates uses a local context in its chachapoly functions */
}
