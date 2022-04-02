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
 * @brief Performs an RSA sign or verify operation some number of iterations.
 *
 * The message is the non-encoded encryption of message M according to PCKS1v15.
 * Meaning, the hash will not be encoded, it will simply be padded and
 * encrypted, and the expected signature for verification will follow the
 * same convention.
 *
 * The private key is always given, regardless of sign or verify. If the target
 * requires a public key to do verify, then it should be constructed during
 * the context create and init, as the specified ASN.1 format contains enough
 * information to reconstruct the public key.
 *
 * Note that this function only verifies that the RSA operation succeeded,
 * in the case of verify, the decrypted bytes are NOT compared to the message.
 *
 * @param id - See the `ee_rsa_id_t` enum
 * @param func - See the `ee_rsa_function_t` enum
 * @param p_pri - The private key buffer
 * @param prilen - Length of the private key buffer
 * @param p_in - The input buffer
 * @param ilen - Length of the input buffer
 * @param p_out - The output buffer
 * @param olen - Length of the output buffer
 * @param iter - Number of iterations to perform
 */
void ee_rsa(ee_rsa_id_t       id,
            ee_rsa_function_t func,
            const uint8_t *   p_pri,
            unsigned int      prilen,
            uint8_t *         p_in,
            unsigned int      ilen,
            uint8_t *         p_out,
            uint_fast32_t *   olen,
            unsigned int      iter);

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_create(void **pp_context);

/**
 * @brief Initialize the context, creating the public key from the private,
 * and storing it for later.
 *
 * The key shall be presented a complete ASN.1 private key per RFC 8017 A.1.2.
 *
 * @param p_context - The context from the `create` function
 * @param id - See the `ee_rsa_id_t` enum
 * @param p_pri - The private key buffer
 * @param prilen - Length of the private key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_init(void *         p_context,
                        ee_rsa_id_t    id,
                        const uint8_t *p_pri,
                        uint_fast32_t  prilen);

/**
 * @brief Sign a message (hash) with the private key.
 *
 * @param p_context - The context from the `create` function
 * @param p_hash - The hashed buffer to sign
 * @param hlen - Length of the hashed buffer
 * @param p_sig - The output signature buffer
 * @param p_slen - The number of bytes used in the output signature buffer.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rsa_sign(void *         p_context,
                        const uint8_t *p_hash,
                        uint_fast32_t  hlen,
                        uint8_t *      p_sig,
                        uint_fast32_t *p_slen);

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
                          const uint8_t *p_sig,
                          uint_fast32_t  slen,
                          uint8_t *      p_out,
                          uint_fast32_t  olen);

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 */
void th_rsa_destroy(void *p_context);

#endif /* _EE_RSA_H */
