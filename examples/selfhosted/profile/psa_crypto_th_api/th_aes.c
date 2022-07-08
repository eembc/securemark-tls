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

/**
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#include "ee_aes.h"

#include "psa/crypto.h"

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_create(void            **p_context, // output: portable context
                 aes_cipher_mode_t mode       // input: AES_ENC or AES_DEC
)
{
    if (mode == AES_ECB)
    {
        *p_context = (psa_cipher_operation_t *)th_malloc(
            sizeof(psa_cipher_operation_t));
    }
    else if (mode == AES_CCM)
    {
        *p_context
            = (psa_aead_operation_t *)th_malloc(sizeof(psa_aead_operation_t));
    }
    else
    {
        th_printf("e-[Unknown mode in th_aes128_create\r\n");
        return EE_STATUS_ERROR;
    }

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_aes128_create\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

static psa_key_id_t key = PSA_KEY_ID_NULL;

/**
 * Initialize the key for an impending operation.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_init(void                *p_context, // input: portable context
               const unsigned char *p_key,     // input: key
               unsigned int         keylen,    // input: length of key in bytes
               unsigned int         rounds,    // input: number of AES rounds
               aes_function_t       func,      // input: AES_ENC or AES_DEC
               aes_cipher_mode_t    mode       // input: AES_ECB or AES_CCM
)
{
    (void)p_context;
    (void)rounds;

    if (mode == AES_ECB)
    {
        psa_status_t status;

        psa_cipher_operation_t *operation = (psa_cipher_operation_t *)p_context;
        *operation                        = psa_cipher_operation_init();
        psa_key_attributes_t attributes   = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_algorithm(&attributes, PSA_ALG_ECB_NO_PADDING);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
        if (func == AES_ENC)
        {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
            psa_set_key_bits(&attributes, 128);
            status = psa_import_key(&attributes, p_key, keylen, &key);
            if (status)
                return EE_STATUS_ERROR;
            status = psa_cipher_encrypt_setup(
                operation, key, PSA_ALG_ECB_NO_PADDING);
            if (status)
                return EE_STATUS_ERROR;
        }
        else
        {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
            psa_set_key_bits(&attributes, 128);
            status = psa_import_key(&attributes, p_key, keylen, &key);
            if (status)
                return EE_STATUS_ERROR;
            status = psa_cipher_decrypt_setup(
                operation, key, PSA_ALG_ECB_NO_PADDING);
            if (status)
                return EE_STATUS_ERROR;
        }
    }
    else if (mode == AES_CCM)
    {
        psa_status_t status;

        psa_aead_operation_t *operation = (psa_aead_operation_t *)p_context;
        *operation                      = psa_aead_operation_init();
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
        if (func == AES_ENC)
        {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
            psa_set_key_bits(&attributes, 128);
            status = psa_import_key(&attributes, p_key, keylen, &key);
            if (status)
                return EE_STATUS_ERROR;
            status = psa_aead_encrypt_setup(operation, key, PSA_ALG_CCM);
            if (status)
                return EE_STATUS_ERROR;
        }
        else
        {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
            psa_set_key_bits(&attributes, 128);
            status = psa_import_key(&attributes, p_key, keylen, &key);
            if (status)
                return EE_STATUS_ERROR;
            status = psa_aead_decrypt_setup(operation, key, PSA_ALG_CCM);
            if (status)
                return EE_STATUS_ERROR;
        }
    }
    else
    {
        th_printf("e-[Unknown mode in th_aes128_init\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform any cleanup required by init, but don't destroy the context.
 *
 * Some implementations of AES perform allocations on init and require a
 * de-init before initializing again, without destroying the context.
 */
void
th_aes128_deinit(void             *p_context, // input: portable context
                 aes_cipher_mode_t mode       // input: AES_ECB or AES_CCM
)
{
    if (mode == AES_ECB)
    {
        psa_cipher_abort((psa_cipher_operation_t *)p_context);
        psa_destroy_key(key);
    }
    else if (mode == AES_CCM)
    {
        psa_aead_abort((psa_aead_operation_t *)p_context);
    }
}

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
)
{
    size_t                  length;
    psa_cipher_operation_t *operation = (psa_cipher_operation_t *)p_context;
    psa_status_t            status
        = psa_cipher_update(operation, p_pt, 16, p_ct, 16, &length);
    if (status)
        return EE_STATUS_ERROR;

    return EE_STATUS_OK;
}

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
)
{
    size_t                  length;
    psa_cipher_operation_t *operation = (psa_cipher_operation_t *)p_context;
    psa_status_t            status
        = psa_cipher_update(operation, p_ct, 16, p_pt, 16, &length);
    if (status)
        return EE_STATUS_ERROR;

    return EE_STATUS_OK;
}

/**
 * Perform a CCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_ccm_encrypt(void                *p_context, // input: portable context
                      const unsigned char *p_pt,      // input: plaintext
                      unsigned int ptlen, // input: length of plaintext in bytes
                      unsigned char *p_ct,   // output: ciphertext
                      unsigned char *p_tag,  // output: tag
                      unsigned int   taglen, // input: tag length in bytes
                      unsigned char *p_iv,   // input: initialization vector
                      unsigned int   ivlen   // input: IV length in bytes
)
{
    psa_status_t          status;
    psa_aead_operation_t *operation = (psa_aead_operation_t *)p_context;
    size_t                length;
    status = psa_aead_set_lengths(operation, 0, ptlen);
    if (status)
        return EE_STATUS_ERROR;
    status = psa_aead_set_nonce(operation, p_iv, ivlen);
    if (status)
        return EE_STATUS_ERROR;
    status = psa_aead_update(operation, p_pt, ptlen, p_ct, ptlen, &length);
    if (status)
        return EE_STATUS_ERROR;
    status
        = psa_aead_finish(operation, NULL, 0, &length, p_tag, taglen, &length);
    if (status)
        return EE_STATUS_ERROR;
    status = psa_destroy_key(key);
    if (status)
        return EE_STATUS_ERROR;

    return EE_STATUS_OK;
}

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
)
{
    psa_status_t          status;
    psa_aead_operation_t *operation = (psa_aead_operation_t *)p_context;
    size_t                length;
    status = psa_aead_set_lengths(operation, 0, ctlen);
    if (status)
    {
        goto exit;
    }
    status = psa_aead_set_nonce(operation, p_iv, ivlen);
    if (status)
    {
        goto exit;
    }
    status = psa_aead_update(operation, p_ct, ctlen, p_pt, ctlen, &length);
    if (status)
    {
        goto exit;
    }
    status = psa_aead_verify(operation, NULL, 0, &length, p_tag, taglen);
    if (status)
    {
        goto exit;
    }
    status = psa_destroy_key(key);
    if (status)
        return EE_STATUS_ERROR;

    return EE_STATUS_OK;
exit:
    th_printf("e-[Failed perform CCM decrypt: -0x%04x]\r\n", -status);
    return EE_STATUS_ERROR;
}

/**
 * Clean up the context created.
 *
 * Indicate the mode that was used for _create()
 */
void
th_aes128_destroy(void             *p_context, // input: portable context
                  aes_cipher_mode_t mode       // input: AES_ECB or AES_CCM
)
{
    (void)mode;
    if (p_context != NULL)
    {
        th_free(p_context);
        p_context = NULL;
    }
}
