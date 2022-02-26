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

typedef enum rsa_id_t
{
    EE_RSA_2048 = 0,
    EE_RSA_3072,
    EE_RSA_4096
} rsa_id_t;

typedef enum rsa_function_t
{
    EE_RSA_SIGN = 0,
    EE_RSA_VERIFY
} rsa_function_t;

ee_status_t th_rsa_create(void **pp_context // output: portable context
);

ee_status_t th_rsa_init(void *        p_context, // input: portable context
                        rsa_id_t      id,        // input: enum of RSA types
                        uint8_t *     p_key,     // input: DER formatted key
                        uint8_t *     p_pubkey,
                        uint_fast32_t publen);

void th_rsa_deinit(void *p_context // input: portable context
);

ee_status_t th_rsa_sign(void *        p_context,
                        uint8_t *     p_msg,
                        uint_fast32_t mlen,
                        uint8_t *     p_sig,
                        uint_fast32_t slen);

ee_status_t th_rsa_verify(void *        p_context,
                          uint8_t *     p_msg,
                          uint_fast32_t mlen,
                          uint8_t *     p_sig,
                          uint_fast32_t slen,
                          uint8_t *     p_verify);

void th_rsa_destroy(void *p_context);

#endif // _EE_RSA_H
