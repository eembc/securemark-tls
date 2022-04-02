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

#ifndef __EE_ECDSA_H
#define __EE_ECDSA_H

#include "ee_main.h"
#include "ee_ecdh.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum ee_ecdsa_func_t
{
    EE_ECDSA_SIGN = 0,
    EE_ECDSA_VERIFY
} ee_ecdsa_func_t;

/**
 * @brief Performs an ECDSA sign or verify operation some number of iterations.
 *
 * @param group - See the `ee_ecdh_group_t` enum
 * @param func - Function to perform, see `the ee_ecdsa_func_t` enum
 * @param p_msg - The message buffer
 * @param mlen - Length of the message buffer
 * @param p_sig - The signature buffer
 * @param p_slen - Pointer to length of the signature buffer (set on sign)
 * @param p_pri - The private key buffer
 * @param plen - Length of the private key buffer
 * @param iter - Number of iterations to perform
 */
void ee_ecdsa(ee_ecdh_group_t group,
              ee_ecdsa_func_t func,
              uint8_t *       p_msg,
              uint_fast32_t   mlen,
              uint8_t *       p_sig,
              uint_fast32_t * p_slen,
              uint8_t *       p_pri,
              uint_fast32_t   plen,
              uint_fast32_t   iter);

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @param group - See the `ee_ecdh_group_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_create(void **pp_context, ee_ecdh_group_t group);

/**
 * @brief Initialize the context, creating the public key from the private
 * and storing it for later.
 * 
 * The private key is just the raw integer value of `d`.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_pri - The private key buffer
 * @param plen - Length of the private key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_init(void *          p_context,
                          ee_ecdh_group_t group,
                          uint8_t *       p_pri,
                          uint_fast32_t   plen);

/**
 * @brief Sign a message (hash) with the private key.
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_hash - The hashed buffer to sign
 * @param hlen - Length of the hashed buffer
 * @param p_sig - The output signature buffer (provided)
 * @param p_slen - The number of bytes used in the output signature buffer.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_sign(void *          p_context,
                          ee_ecdh_group_t group,
                          uint8_t *       p_hash,
                          uint_fast32_t   hlen,
                          uint8_t *       p_sig,
                          uint_fast32_t * p_slen);

/**
 * @brief Verify a message (hash) with the public key.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_hash - The hashed buffer to verify
 * @param hlen - Length of the hashed buffer
 * @param p_sig - The input signature buffer
 * @param slen - Length of the input signature buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_verify(void *          p_context,
                            ee_ecdh_group_t group,
                            uint8_t *       p_hash,
                            uint_fast32_t   hlen,
                            uint8_t *       p_sig,
                            uint_fast32_t   slen);

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 */
void th_ecdsa_destroy(void *p_context, ee_ecdh_group_t group);

#endif /* _EE_ECDSA_H */
