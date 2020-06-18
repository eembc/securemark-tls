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

typedef enum
{
    AES_ECB = 0,
    AES_CCM
} aes_cipher_mode_t;

typedef enum
{
    AES_ENC = 0,
    AES_DEC
} aes_function_t;

// These must remain fixed for EEMBC profile (bytes)
#define AES_BLOCKLEN 16u
#define AES_KEYSIZE  16u
#define AES_IVSIZE   12u
#define AES_TAGSIZE  16u
#define AES_ROUNDS    0u

// Fixed test API

void
ee_aes128_ecb(
    unsigned char  *p_key,      // input: key
    unsigned char  *p_in,       // input: pointer to source input (pt or ct)
    unsigned int    len,        // input: length of input in bytes
    unsigned char  *p_out,      // output: pointer to output buffer
    aes_function_t  func,       // input: func (AES_ENC|AES_DEC)
    unsigned int    iterations  // input: # of test iterations
);

void
ee_aes128_ccm(
    unsigned char  *p_key,      // input: key
    unsigned char  *p_iv,       // input: initialization vector
    unsigned char  *p_in,       // input: pointer to source input (pt or ct)
    unsigned int    len,        // input: length of input in bytes
    unsigned char  *p_tag,      // inout: output in encrypt, input on decrypt
    unsigned char  *p_out,      // output: pointer to output buffer
    aes_function_t  func,       // input: func (AES_ENC|AES_DEC)
    unsigned int    iterations  // input: # of test iterations
);

// Implementation API


/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_create(
    void              **p_context,  // output: portable context
    aes_cipher_mode_t   mode        // input: AES_ENC or AES_DEC
);

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_init(
    void                *p_context, // input: portable context
    const unsigned char *p_key,     // input: key
    unsigned int         keylen,    // input: length of key in bytes
    unsigned int         rounds,    // input: number of AES rounds
    aes_function_t       func,      // input: AES_ENC or AES_DEC
    aes_cipher_mode_t    mode       // input: AES_ECB or AES_CCM
);

/**
 * Perform any cleanup required by init, but don't destroy the context.
 *
 * Some implementations of AES perform allocations on init and require a
 * de-init before initializing again, without destroying the context.
 */
void
th_aes128_deinit(
    void              *context,     // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
);

/**
 * Perform an ECB encrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ecb_encrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_pt,      // input: plaintext (AES_BLOCKSIZE bytes)
    unsigned char       *p_ct       // output: ciphertext (AES_BLOCKSIZE bytes)
);

/**
 * Perform an ECB decrypt on a single block of AES_BLOCKSIZE bytes.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ecb_decrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_ct,      // input: ciphertext (AES_BLOCKSIZE bytes)
    unsigned char       *p_pt       // output: plaintext (AES_BLOCKSIZE bytes)
);

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ccm_encrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_pt,      // input: plaintext
    unsigned int         ptlen,     // input: length of plaintext in bytes
    unsigned char       *p_ct,      // output: ciphertext
    unsigned char       *p_tag,     // output: tag
    unsigned int         taglen,    // input: tag length in bytes
    unsigned char       *p_iv,      // input: initialization vector
    unsigned int         ivlen      // input: IV length in bytes
);

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ccm_decrypt(
    void                *p_context, // input: portable context
    const unsigned char *p_ct,      // input: ciphertext
    unsigned int         ctlen,     // input: length of ciphertext in bytes
    unsigned char       *p_pt,      // output: plaintext
    unsigned char       *p_tag,     // input: tag
    unsigned int         taglen,    // input: tag length in bytes
    unsigned char       *p_iv,      // input: initialization vector
    unsigned int         ivlen      // input: IV length in bytes
); 

/**
 * Clean up the context created.
 * 
 * Indicate the mode that was used for _create()
 */
void
th_aes128_destroy(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
);

#endif // __EE_AES_H
