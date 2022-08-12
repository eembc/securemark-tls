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

/**
 * @brief Creates a context and generates a key pair.
 *
 * @param pp_context - A pointer to a context pointer to be created.
 * @param group - See the `ee_ecdh_group_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_create(void **pp_context, ee_ecdh_group_t group);

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
 * `p_siglen` should point to the buffer size on input; on return it will
 * contain the length of the signature.
 *
 * @param p_context - The context from the `create` function
 * @param p_msg - The hashed buffer to sign
 * @param msglen - Length of the hashed buffer
 * @param p_sig - The output signature buffer (provided)
 * @param p_siglen - The number of bytes used in the output signature buffer.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_sign(void *         p_context,
                          uint8_t *      p_msg,
                          uint32_t  msglen,
                          uint8_t *      p_sig,
                          uint32_t *p_siglen);

/**
 * @brief Verify a message (hash) with the public key.
 *
 * It will return EE_STATUS_OK on message verify, and EE_STATUS_ERROR if the
 * message does not verify, or if there is some other error (which shall
 * be reported with `th_printf("e-[....]r\n");`.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_hash - The hashed buffer to verify
 * @param hlen - Length of the hashed buffer
 * @param p_sig - The input signature buffer
 * @param slen - Length of the input signature buffer
 * @return ee_status_t - see above.
 */
ee_status_t th_ecdsa_verify(void *        p_context,
                            uint8_t *     p_msg,
                            uint32_t msglen,
                            uint8_t *     p_sig,
                            uint32_t siglen);

/**
 * @brief Return the public key generated during `th_ecdsa_create`.
 *
 * @param p_context - The context from the `create` function
 * @param p_out - Buffer to receive the public key
 * @param p_outlen - Number of bytes used in the buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_get_public_key(void *         p_context,
                                    uint8_t *      p_out,
                                    uint32_t *p_outlen);

/**
 * @brief Set the public key in the context in order to perform a verify.
 *
 * For EcDSA, the key shall be in SECP1 uncompressed format { 04 | X | Y }.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_set_public_key(void *        p_context,
                                    uint8_t *     p_pub,
                                    uint32_t publen);

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 */
void th_ecdsa_destroy(void *p_context);

#endif /* _EE_ECDSA_H */
