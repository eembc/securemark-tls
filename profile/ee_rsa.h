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

#ifndef _EE_RSA_H
#define _EE_RSA_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum ee_rsa_id_t
{
    EE_RSA_2048 = 0,
    EE_RSA_3072,
    EE_RSA_4096
} ee_rsa_id_t;

typedef enum ee_rsa_function_t
{
    EE_RSA_SIGN = 0,
    EE_RSA_VERIFY
} ee_rsa_function_t;

void ee_rsa(ee_rsa_id_t       id,
            ee_rsa_function_t func,
            const uint8_t *   p_pri,
            unsigned int      prilen,
            uint8_t *         p_in,
            unsigned int      ilen,
            uint8_t *         p_out,
            uint_fast32_t *   olen,
            unsigned int      iter);

ee_status_t th_rsa_create(void **pp_context);

ee_status_t th_rsa_init(void *         p_context,
                        ee_rsa_id_t    id,
                        const uint8_t *p_pri,
                        uint_fast32_t  prilen);

ee_status_t th_rsa_sign(void *         p_context,
                        const uint8_t *p_hash,
                        uint_fast32_t  hlen,
                        uint8_t *      p_sig,
                        uint_fast32_t *p_slen);

ee_status_t th_rsa_verify(void *         p_context,
                          const uint8_t *p_sig,
                          uint_fast32_t  slen,
                          uint8_t *      p_out,
                          uint_fast32_t  olen);

void th_rsa_destroy(void *p_context);

#endif // _EE_RSA_H
