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

#ifndef __EE_AES_H
#define __EE_AES_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum ee_aes_mode_t
{
    EE_AES_ECB = 0,
    EE_AES_CTR,
    EE_AES_CCM,
    EE_AES_GCM,
} ee_aes_mode_t;

typedef enum ee_aes_func_t
{
    EE_AES_ENC = 0,
    EE_AES_DEC
} ee_aes_func_t;

// These must remain fixed for EEMBC profile (bytes)
#define EE_AES_BLOCKLEN    16u
#define EE_AES_CTR_IVLEN  16u
#define EE_AES_AEAD_IVLEN 12u
#define EE_AES_TAGLEN     16u
#define EE_AES_ROUNDS      0u

// Testing function.

void ee_aes(ee_aes_mode_t mode,   // input: cipher mode
            ee_aes_func_t    func,   // input: func (AES_ENC|EE_AES_DEC)
            const uint8_t *   p_key,  // input: key
            uint_fast32_t     keylen, // input: length of key in bytes
            const uint8_t *   p_iv,   // input: initialization vector
            const uint8_t *   p_in, // input: pointer to source input (pt or ct)
            uint_fast32_t     len,  // input: length of input in bytes
            uint8_t *         p_out, // output: pointer to output buffer
            uint8_t *      p_tag,  // inout: output in encrypt, input on decrypt
            const uint8_t *p_add,  // input: additional authentication data
            uint_fast32_t  addlen, // input: length of AAD in bytes
            uint_fast32_t  iterations // input: # of test iterations
);

// Implementation API

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_create(void **p_context,      // output: portable context
                          ee_aes_mode_t mode // input: AES_ENC or EE_AES_DEC
);

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_init(void *         p_context, // input: portable context
                        const uint8_t *p_key,     // input: key
                        uint_fast32_t  keylen, // input: length of key in bytes
                        const uint8_t *iv,     // input: IV if CTR mode, or NULL
                        uint_fast32_t  rounds, // input: number of AES rounds
                        ee_aes_func_t func,   // input: AES_ENC or EE_AES_DEC
                        ee_aes_mode_t mode // input: see ee_aes_mode_t
);

/**
 * Perform any cleanup required by init, but don't destroy the context.
 *
 * Some implementations of AES perform allocations on init and require a
 * de-init before initializing again, without destroying the context.
 */
void th_aes_deinit(void *            context, // input: portable context
                   ee_aes_mode_t mode     // input: EE_AES_ECB or EE_AES_CCM
);

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_ecb_encrypt(void *p_context,     // input: portable context
                               const uint8_t *p_pt, // input: plaintext
                               uint8_t *      p_ct  // output: ciphertext
);

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_ecb_decrypt(void *p_context,     // input: portable context
                               const uint8_t *p_ct, // input: ciphertext
                               uint8_t *      p_pt  // output: plaintext
);

/**
 * Perform an ECB CTR encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_ctr_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  plen,      // input: plaintext length in bytes
    uint8_t *      p_ct       // output: ciphertext
);

/**
 * Perform an ECB CTR decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_ctr_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  clen,      // input: ciphertext length in bytes
    uint8_t *      p_pt       // output: plaintext
);

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_ccm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: Additional Authentication Data
    uint_fast32_t  aadlen,    // input: Length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
);

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_ccm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: Additional Authentication Data
    uint_fast32_t  aadlen,    // input: Length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
);

/**
 * Perform an AES/GCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_gcm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: Additional Authentication Data
    uint_fast32_t  aadlen,    // input: Length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
);

/**
 * Perform a AES/GCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_gcm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: Additional Authentication Data
    uint_fast32_t  aadlen,    // input: Length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of plaintext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
);

/**
 * Clean up the context created.
 *
 * Indicate the mode that was used for _create()
 */
void th_aes_destroy(void *            p_context, // input: portable context
                    ee_aes_mode_t mode       // input: EE_AES_ECB or EE_AES_CCM
);

#endif // __EE_AES_H
