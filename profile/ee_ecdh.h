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

/**
 * @brief Creates a context and generates a key pair.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @param group - See the `ee_ecdh_group_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_create(void **pp_context, ee_ecdh_group_t group);

/**
 * @brief Loads the peer public key for use in the secreat calc.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_set_peer_public_key(void *        p_context,
                                        uint8_t *     p_pub,
                                        uint32_t publen);

/**
 * @brief Returns the DUT's public key so that the HOST can verify
 * the secret with it's private key.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param p_publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_get_public_key(void *         p_context,
                                   uint8_t *      p_pub,
                                   uint32_t *p_publen);

/**
 * @brief Perform an ECDH key mix and create a shared secret.
 *
 * @param p_context - The context from the `create` function
 * @param p_sec - The shared secret buffer
 * @param p_seclen - Input is the max buffer length, output is length of secret
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdh_calc_secret(void *         p_context,
                                uint8_t *      p_sec,
                                uint32_t *p_seclen);

/**
 * @brief Deallocate/destroy the context.
 *
 * @param p_context - The context from the `create` function
 */
void th_ecdh_destroy(void *p_context);

#endif /* _EE_ECDH_H */
