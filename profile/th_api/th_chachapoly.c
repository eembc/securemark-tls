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

#include "ee_chachapoly.h"

ee_status_t
th_chachapoly_create(void **pp_context)
{
#warning "th_chachapoly_create not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_chachapoly_init(void *               p_context,
                   const uint8_t *      p_key,
                   uint_fast32_t        keylen)
{
#warning "th_chachapoly_init not implemented"
    return EE_STATUS_OK;
}

void
th_chachapoly_deinit(void *p_context) {
#warning "th_chachapoly_deinit not implemented"
}

ee_status_t th_chachapoly_encrypt(void *         p_context,
                                  const uint8_t *p_pt,
                                  uint_fast32_t  ptlen,
                                  uint8_t *      p_ct,
                                  uint8_t *      p_tag,
                                  uint_fast32_t  taglen,
                                  uint8_t *      p_iv,
                                  uint_fast32_t  ivlen)
{
#warning "th_chachapoly_encrypt not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_chachapoly_decrypt(void *         p_context,
                      const uint8_t *p_ct,
                      uint_fast32_t  ctlen,
                      uint8_t *      p_pt,
                      uint8_t *      p_tag,
                      uint_fast32_t  taglen,
                      uint8_t *      p_iv,
                      uint_fast32_t  ivlen)
{
#warning "th_chachapoly_decrypt not implemented"
    return EE_STATUS_OK;
}

void
th_chachapoly_destroy(void *p_context)
{
#warning "th_chachapoly_destroy not implemented"
}
