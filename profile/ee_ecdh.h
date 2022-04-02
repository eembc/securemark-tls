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

#ifndef __EE_ECDH_H
#define __EE_ECDH_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum ee_ecdh_group_t
{
    EE_P256R1  = 0,
    EE_P384    = 1,
    EE_C25519  = 2,
    EE_Ed25519 = 3, /* Not a group, but used for control later on. */
} ee_ecdh_group_t;

/* Ordering respective of above enumeration */
static const uint8_t ee_pub_sz[] = { 64, 96, 32, 32 };
static const uint8_t ee_pri_sz[] = { 32, 48, 32, 32 };
static const uint8_t ee_sec_sz[] = { 32, 48, 32, 32 };
static const uint8_t ee_sig_sz[] = { 64, 96, 64, 64 };

/**
 * @brief Performs ECDH key mixing to generate a secret a given number of times.
 * The host provides the peer public and private keys. The expected format
 * for the public key is two uncompressed coordinates { X | Y }.
 *
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_private - Private key buffer
 * @param prilen - Length of private key buffer
 * @param p_public - Public key buffer
 * @param publen - Length of public key buffer
 * @param p_secret - Output secret buffer
 * @param seclen - Length of output secret buffer
 * @param iter - Number of iterations to perform
 */
void ee_ecdh(ee_ecdh_group_t group,
             uint8_t *       p_private,
             uint_fast32_t   prilen,
             uint8_t *       p_public,
             uint_fast32_t   publen,
             uint8_t *       p_secret,
             uint_fast32_t   seclen,
             uint_fast32_t   iterations);

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @param group - See the `ee_ecdh_group_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_create(void **pp_context, ee_ecdh_group_t group);

/**
 * @brief Initializes the context.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_private - Private key buffer
 * @param prilen - Length of private key buffer
 * @param p_public - Public key buffer
 * @param publen - Length of public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_init(void *          p_context,
                         ee_ecdh_group_t group,
                         uint8_t *       p_private,
                         uint_fast32_t   prilen,
                         uint8_t *       p_public,
                         uint_fast32_t   publen);

/**
 * @brief Perform an ECDH key mix and create a shared secret.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_secret - The shared secret buffer
 * @param slen - Length of the shared secret buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_calc_secret(void *          p_context,
                                ee_ecdh_group_t group,
                                uint8_t *       p_secret,
                                uint_fast32_t   slen);

/**
 * @brief Deallocate/destroy the context.
 *
 * @param p_context - The context from the `create` function
 */
void th_ecdh_destroy(void *p_context);

#endif /* _EE_ECDH_H */
