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

/* These must remain fixed for EEMBC profile (bytes) */
#define EE_AES_BLOCKLEN   16u
#define EE_AES_CTR_IVLEN  16u
#define EE_AES_AEAD_IVLEN 12u
#define EE_AES_TAGLEN     16u

/**
 * @brief This is the lowest-level benchmark function before the API calls.
 * It performs `i` number of iterations on the requested primitive.
 * 
 * None of the functions at this level return an error status; errors are
 * reported vi `th_printf` and intercepted by the host.
 * 
 * @param mode - AES mode
 * @param func - AES function
 * @param p_key - Key
 * @param keylen - Length of key
 * @param p_iv - Initialization vector
 * @param p_in - PT/CT buffer
 * @param len - Length of input buffer
 * @param p_out - CT/PT buffer
 * @param p_tag - Tag buffer
 * @param i - Number of iterations to perform
 */
void ee_aes(ee_aes_mode_t  mode,
            ee_aes_func_t  func,
            const uint8_t *p_key,
            uint_fast32_t  keylen,
            const uint8_t *p_iv,
            const uint8_t *p_in,
            uint_fast32_t  len,
            uint8_t *      p_out,
            uint8_t *      p_tag,
            uint_fast32_t  i);

/**
 * @brief Create an AES context for a given mode.
 * 
 * @param pp_context - A pointer to a context pointer to be created
 * @param mode - AES mode; most libraries need this to create a context
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_create(void **pp_context, ee_aes_mode_t mode);

/**
 * @brief Initialize an AES context with a key. CTR-mode may require an IV
 * on initialization, and this function is fall all AES modes.
 * 
 * @param p_context - The context from the `create` function
 * @param p_key - The key buffer
 * @param keylen - Length of the key buffer
 * @param iv - The IV buffer
 * @param func - AES function this context will perform
 * @param mode - The mode of this AES context
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_init(void *         p_context,
                        const uint8_t *p_key,
                        uint_fast32_t  keylen,
                        const uint8_t *iv,
                        ee_aes_func_t  func,
                        ee_aes_mode_t  mode);

/**
 * @brief De-initialize the AES context.
 * 
 * @param p_context - The context from the `create` function
 * @param mode - The mode of this AES context
 */
void th_aes_deinit(void *p_context, ee_aes_mode_t mode);

/**
 * @brief Perform an AES ECB encryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_pt - Plaintext buffer (16-octets)
 * @param p_ct - Ciphertext buffer (16-octets)
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ecb_encrypt(void *         p_context,
                               const uint8_t *p_pt,
                               uint8_t *      p_ct);

/**
 * @brief Perform an AES ECB decryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_ct - Ciphertext buffer (16-octets)
 * @param p_pt - Plaintext buffer (16-octets)
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ecb_decrypt(void *         p_context,
                               const uint8_t *p_ct,
                               uint8_t *      p_pt);

/**
 * @brief Perform an AES CTR encryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_pt - Plaintext buffer
 * @param ptlen - Length of the plaintext buffer
 * @param p_ct - Ciphertext buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ctr_encrypt(void *         p_context,
                               const uint8_t *p_pt,
                               uint_fast32_t  ptlen,
                               uint8_t *      p_ct);

/**
 * @brief Perform an AES CTR decryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_ct - Ciphertext buffer
 * @param ctlen - Length of the ciphertext buffer
 * @param p_pt - Plaintext buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ctr_decrypt(void *         p_context,
                               const uint8_t *p_ct,
                               uint_fast32_t  ctlen,
                               uint8_t *      p_pt);

/**
 * @brief Perform an AES CCM encryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_pt - Plaintext buffer
 * @param ptlen - Length of the plaintext buffer
 * @param p_ct - Ciphertext buffer
 * @param p_tag - Tag buffer.
 * @param taglen - Tag buffer length.
 * @param p_iv - IV buffer.
 * @param ivlen - IV buffer length.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ccm_encrypt(void *         p_context,
                               const uint8_t *p_pt,
                               uint_fast32_t  ptlen,
                               uint8_t *      p_ct,
                               uint8_t *      p_tag,
                               uint_fast32_t  taglen,
                               const uint8_t *p_iv,
                               uint_fast32_t  ivlen);

/**
 * @brief Perform an AES CCM decryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_ct - Ciphertext buffer
 * @param ctlen - Length of the ciphertext buffer
 * @param p_pt - Plaintext buffer
 * @param p_tag - Tag buffer.
 * @param taglen - Tag buffer length.
 * @param p_iv - IV buffer.
 * @param ivlen - IV buffer length.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_ccm_decrypt(void *         p_context,
                               const uint8_t *p_ct,
                               uint_fast32_t  ctlen,
                               uint8_t *      p_pt,
                               const uint8_t *p_tag,
                               uint_fast32_t  taglen,
                               const uint8_t *p_iv,
                               uint_fast32_t  ivlen);

/**
 * @brief Perform an AES GCM encryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_pt - Plaintext buffer
 * @param ptlen - Length of the plaintext buffer
 * @param p_ct - Ciphertext buffer
 * @param p_tag - Tag buffer.
 * @param taglen - Tag buffer length.
 * @param p_iv - IV buffer.
 * @param ivlen - IV buffer length.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_gcm_encrypt(void *         p_context,
                               const uint8_t *p_pt,
                               uint_fast32_t  ptlen,
                               uint8_t *      p_ct,
                               uint8_t *      p_tag,
                               uint_fast32_t  taglen,
                               const uint8_t *p_iv,
                               uint_fast32_t  ivlen);

/**
 * @brief Perform an AES GCM decryption.
 * 
 * @param p_context - The context from the `create` function
 * @param p_ct - Ciphertext buffer
 * @param ctlen - Length of the ciphertext buffer
 * @param p_pt - Plaintext buffer
 * @param p_tag - Tag buffer.
 * @param taglen - Tag buffer length.
 * @param p_iv - IV buffer.
 * @param ivlen - IV buffer length.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_aes_gcm_decrypt(void *         p_context,
                               const uint8_t *p_ct,
                               uint_fast32_t  ctlen,
                               uint8_t *      p_pt,
                               const uint8_t *p_tag,
                               uint_fast32_t  taglen,
                               const uint8_t *p_iv,
                               uint_fast32_t  ivlen);

/**
 * @brief Deallocate/destroy the context.
 * 
 * @param p_context - The context from the `create` function
 * @param mode 
 */
void th_aes_destroy(void *p_context);

#endif /* __EE_AES_H */
