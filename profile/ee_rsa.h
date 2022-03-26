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

/**
 * @brief Perform an RSA operation. Currently, only sign and verify are
 * supported. It returns no value because the host application will
 * intepret the messages printed by `th_printf`.
 *
 * @param id Size of the modulus, an `rsa_id_t` enum
 * @param func One of the `rsa_function_t` enums
 * @param p_pri Private key buffer, as quintuple ASN.1/DER RFC 8017 Sec 3.2
 * @param prilen Private key buffer length
 * @param p_pub Public key buffer, as N/E ASN.1/DER RFC 8017 Sec 3.1.2
 * @param publen Public key buffer length
 * @param p_in Input octet buffer
 * @param ilen Input buffer length
 * @param p_out Output octet buffer
 * @param olen Output buffer length, may be inout, as operation can set it
 * @param iter Number of iterations
 */
void ee_rsa(rsa_id_t       id,
            rsa_function_t func,
            const uint8_t *p_pri,
            unsigned int   prilen,
            const uint8_t *p_pub,
            unsigned int   publen,
            const uint8_t *p_in,
            unsigned int   ilen,
            uint8_t *      p_out,
            uint_fast32_t *olen,
            unsigned int   iter);

/**
 * @brief Creates a portable context structure for RSA operations.
 *
 * @param pp_context Pointer to portable context pointer.
 * @return ee_status_t EE_STATUS_OK or EE_STATUS_FAIL
 */
ee_status_t th_rsa_create(void **pp_context);

/**
 * @brief Initialize structures created ruing `th_rsa_create` and setup and
 * library or hardware functionality. Typically loads the private and public
 * keys, and inititalizes and RNGs or configuration options.
 *
 * @param p_context Portable context.
 * @param id Size of the modulus, an `rsa_id_t` enum
 * @param p_pri Private key buffer, as quintuple ASN.1/DER RFC 8017 Sec 3.2
 * @param prilen Private key buffer length
 * @param p_pub Public key buffer, as N/E ASN.1/DER RFC 8017 Sec 3.1.2
 * @param publen Public key buffer length
 * @return ee_status_t EE_STATUS_OK or EE_STATUS_FAIL
 */
ee_status_t th_rsa_init(void *         p_context,
                        rsa_id_t       id,
                        const uint8_t *p_prikey,
                        uint_fast32_t  prilen,
                        const uint8_t *p_pubkey,
                        uint_fast32_t  publen);

/**
 * @brief Perform an RSA sign (exp mod n) of a hash, and return the raw
 * (encrypted) signature. The validity of the output will be checked by the
 * host application.
 *
 * @param p_context Portable context pointer
 * @param p_hash Hash of data
 * @param hlen Length of hash
 * @param p_sig Output octect buffer for signature
 * @param p_slen Length of signature buffer (output pointer)
 * @return ee_status_t EE_STATUS_OK or EE_STATUS_FAIL
 */
ee_status_t th_rsa_sign(void *         p_context,
                        const uint8_t *p_hash,
                        uint_fast32_t  hlen,
                        uint8_t *      p_sig,
                        uint_fast32_t *p_slen);

/**
 * @brief Perform an RSA verify (exp mod n) of a hash, and return the raw
 * (decrypted) signature. The validity of the output will be checked by the
 * host application. This function must perform PKCS1v15 padding as
 * described in RFC 8017 9.2.
 *
 * @param p_context Portable context
 * @param p_sig Pointer to signature octet buffer, raw bytes
 * @param slen Length of signature buffer
 * @param p_outbuf Pointer to an output buffer
 * @param olen Length of provided output buffer
 * @return ee_status_t
 */
ee_status_t th_rsa_verify(void *         p_context,
                          const uint8_t *p_sig,
                          uint_fast32_t  slen,
                          uint8_t *      p_outbuf,
                          uint_fast32_t  olen);

/**
 * @brief De-initialize and destroy and context created, and free up any
 * memory allocated during `th_rsa_create`.
 *
 * @param p_context Portable context pointer
 */
void th_rsa_destroy(void *p_context);

#endif // _EE_RSA_H
