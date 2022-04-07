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

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_create(void **pp_context);

/**
 * @brief Set the public key to use for verification.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_set_public_key(void *         p_context,
                                  const uint8_t *p_pub,
                                  uint_fast32_t  publen);

/**
 * @brief Verify a message (hash) with the public key.
 *
 * @param p_context - The context from the `create` function
 * @param p_sig - The input message buffer
 * @param msglen - Length of the input message buffer
 * @param p_sig - The output signature buffer
 * @param siglen - Length of the output signature buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_verify(void *        p_context,
                          uint8_t *     p_msg,
                          uint_fast32_t msglen,
                          uint8_t *     p_sig,
                          uint_fast32_t siglen);

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 */
void th_rsa_destroy(void *p_context);

#endif /* _EE_RSA_H */
