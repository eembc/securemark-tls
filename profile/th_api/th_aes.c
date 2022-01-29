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

#include "ee_aes.h"

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_create(void **           p_context, // output: portable context
                 aes_cipher_mode_t mode       // input: AES_ENC or AES_DEC
)
{
#warning "th_aes_create not implemented"
    return EE_STATUS_OK;
}

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_init(void *            p_context, // input: portable context
            const uint8_t *   p_key,     // input: key
            uint_fast32_t     keylen,    // input: length of key in bytes
            const uint8_t *   iv,        // input: IV if CTR mode, or NULL
            uint_fast32_t     rounds,    // input: number of AES rounds
            aes_function_t    func,      // input: AES_ENC or AES_DEC
            aes_cipher_mode_t mode       // input: see aes_cipher_mode_t
)
{
#warning "th_aes_init not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 *
 * Some implementations of AES perform allocations on init and require a
 * de-init before initializing again, without destroying the context.
 */
void
th_aes_deinit(void *            p_context, // input: portable context
            aes_cipher_mode_t mode       // input: see aes_cipher_mode_t
)
{
#warning "th_aes_deinit not implemented"
}

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t th_aes_ecb_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_pt,      // input: plaintext
    uint8_t *      p_ct       // output: ciphertext
)
{
#warning "th_aes_ecb_encrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ecb_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_ct,      // input: ciphertext
    uint8_t *      p_pt       // output: plaintext
)
{
#warning "th_aes_ecb_decrypt not implemented"
    return EE_STATUS_OK;
}

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
)
{
#warning "th_aes_ctr_encrypt not implemented"
    return EE_STATUS_OK;
}

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
)
{
#warning "th_aes_ctr_decrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ccm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
#warning "th_aes_ccm_encrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ccm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of ciphertext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *      p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
#warning "th_aes_ccm_decrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform an AES/GCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_gcm_encrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_pt,      // input: plaintext
    uint_fast32_t  ptlen,     // input: length of plaintext in bytes
    uint8_t *      p_ct,      // output: ciphertext
    uint8_t *      p_tag,     // output: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
#warning "th_aes_gcm_encrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Perform an AES/GCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_gcm_decrypt(
    void *         p_context, // input: portable context
    const uint8_t *p_aad,     // input: additional authentication data
    uint_fast32_t  aadlen,    // input: length of AAD in bytes
    const uint8_t *p_ct,      // input: ciphertext
    uint_fast32_t  ctlen,     // input: length of plaintext in bytes
    uint8_t *      p_pt,      // output: plaintext
    const uint8_t *      p_tag,     // input: tag
    uint_fast32_t  taglen,    // input: tag length in bytes
    const uint8_t *      p_iv,      // input: initialization vector
    uint_fast32_t  ivlen      // input: IV length in bytes
)
{
#warning "th_aes_gcm_decrypt not implemented"
    return EE_STATUS_OK;
}

/**
 * Clean up the context created.
 *
 * Indicate the mode that was used for _create()
 */
void
th_aes_destroy(void *            p_context, // input: portable context
                  aes_cipher_mode_t mode       // input: AES_ECB|CCM|GCM
)
{
#warning "th_aes_destroy not implemented"
}
