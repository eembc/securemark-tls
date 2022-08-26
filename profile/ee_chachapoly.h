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

#ifndef __EE_CHACHAPOLY_H
#define __EE_CHACHAPOLY_H

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

typedef enum
{
    EE_CHACHAPOLY_ENC = 0,
    EE_CHACHAPOLY_DEC
} ee_chachapoly_func_t;

#define EE_CHACHAPOLY_KEYLEN 32u
#define EE_CHACHAPOLY_IVLEN  12u
#define EE_CHACHAPOLY_TAGLEN 16u

/**
 * @brief This is the lowest-level benchmark function before the API calls.
 * It performs `i` number of iterations on the primitive.
 *
 * None of the functions at this level return an error status; errors are
 * reported vi `th_printf` and intercepted by the host.
 *
 * @param func - ChaChaPoly function
 * @param p_key - The key buffer
 * @param p_iv - Initialization vector buffer
 * @param p_in - Input PT/CT buffer
 * @param len - Length of input buffer
 * @param p_out - Output CT/PT buffer
 * @param p_tag - Tag buffer
 * @param i - Number of iterations to perform
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_chachapoly(ee_chachapoly_func_t func,
                       uint8_t *            p_key,
                       uint8_t *            p_iv,
                       uint8_t *            p_in,
                       uint32_t             len,
                       uint8_t *            p_out,
                       uint8_t *            p_tag,
                       uint32_t             i);

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_chachapoly_create(void **pp_context);

/**
 * @brief Initialize the key for an impending operation.
 *
 * @param p_context - The context from the `create` function
 * @param p_key - The key buffer
 * @param keylen - Length of the key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_chachapoly_init(void *         p_context,
                               const uint8_t *p_key,
                               uint32_t       keylen);

/**
 * @brief De-initialize the context (but don't destroy it).
 *
 * @param p_context - The context from the `create` function
 */
void th_chachapoly_deinit(void *p_context);

/**
 * @brief Perform a ChaCha-Poly encrypt.
 *
 * @param p_context - The context from the `create` function
 * @param p_pt - Plaintext buffer
 * @param ptlen - Length of the plaintext buffer
 * @param p_ct - Ciphertext buffer
 * @param p_tag - Tag buffer
 * @param taglen - Tag buffer length
 * @param p_iv - IV buffer
 * @param ivlen - IV buffer length
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_chachapoly_encrypt(void *         p_context,
                                  const uint8_t *p_pt,
                                  uint32_t       ptlen,
                                  uint8_t *      p_ct,
                                  uint8_t *      p_tag,
                                  uint32_t       taglen,
                                  uint8_t *      p_iv,
                                  uint32_t       ivlen);

/**
 * @brief Perform a ChaCha-Poly decrypt.
 *
 * @param p_context - The context from the `create` function
 * @param p_ct - Ciphertext buffer
 * @param ctlen - Length of the ciphertext buffer
 * @param p_pt - Plaintext buffer
 * @param p_tag - Tag buffer
 * @param taglen - Tag buffer length
 * @param p_iv - IV buffer
 * @param ivlen - IV buffer length
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_chachapoly_decrypt(void *         p_context,
                                  const uint8_t *p_ct,
                                  uint32_t       ctlen,
                                  uint8_t *      p_pt,
                                  uint8_t *      p_tag,
                                  uint32_t       taglen,
                                  uint8_t *      p_iv,
                                  uint32_t       ivlen);

/**
 * @brief Deallocate/destroy the context.
 *
 * @param p_context - The context from the `create` function
 */
void th_chachapoly_destroy(void *p_context);

#endif /* _EE_CHACHAPOLY_H */
