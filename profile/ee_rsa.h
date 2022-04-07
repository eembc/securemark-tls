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

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_create(void **pp_context);

/**
 * @brief Verify a message (hash) with the public key.
 *
 * Note this doesn't actually compare the bytes of the decrypted message, just
 * that the decryption succeeded.
 *
 * @param p_context - The context from the `create` function
 * @param p_sig - The input signature buffer
 * @param slen - Length of the signature buffer
 * @param p_out - The output buffer
 * @param olen - Length of the output buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_verify(void *         p_context,
                          uint8_t *      p_msg,
                          uint_fast32_t  msglen,
                           uint8_t *p_sig,
                          uint_fast32_t  slen
                          );

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 */
void th_rsa_destroy(void *p_context);


ee_status_t
th_rsa_set_public_key(void *         p_context,
            const uint8_t *p_pubkey,
            uint_fast32_t  publen);
#endif /* _EE_RSA_H */
