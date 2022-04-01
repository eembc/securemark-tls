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

#include "ee_aes.h"

ee_status_t
th_aes_create(void **p_context, ee_aes_mode_t mode)
{
#warning "th_aes_create not implemented"
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
#warning "th_aes_init not implemented"
    return EE_STATUS_OK;
}

void
th_aes_deinit(void *p_context, ee_aes_mode_t mode) {
#warning "th_aes_deinit not implemented"
}

ee_status_t
    th_aes_ecb_encrypt(void *p_context, const uint8_t *p_pt, uint8_t *p_ct)
{
#warning "th_aes_ecb_encrypt not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ecb_decrypt(void *p_context, const uint8_t *p_ct, uint8_t *p_pt)
{
#warning "th_aes_ecb_decrypt not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ctr_encrypt(void *         p_context,
                   const uint8_t *p_pt,
                   uint_fast32_t  ptlen,
                   uint8_t *      p_ct)
{
#warning "th_aes_ctr_encrypt not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ctr_decrypt(void *         p_context,
                   const uint8_t *p_ct,
                   uint_fast32_t  ctlen,
                   uint8_t *      p_pt)
{
#warning "th_aes_ctr_decrypt not implemented"
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
#warning "th_aes_ccm_encrypt not implemented"
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
#warning "th_aes_ccm_decrypt not implemented"
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
#warning "th_aes_gcm_encrypt not implemented"
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
#warning "th_aes_gcm_decrypt not implemented"
    return EE_STATUS_OK;
}

void
th_aes_destroy(void *p_context)
{
#warning "th_aes_destroy not implemented"
}
