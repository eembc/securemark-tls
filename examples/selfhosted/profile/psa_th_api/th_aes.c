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

#include "psa/crypto.h"

struct psa_encryption_structure
{
    psa_key_attributes_t *attributes;
    psa_key_handle_t key_handle;
    psa_cipher_operation_t *operation;
};

typedef struct psa_encryption_structure  psa_encryption_structure;

#include "ee_aes.h"

/**
 * Create a context for use with the particular AES mode.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes128_create(
    void              **p_context,  // output: portable context
    aes_cipher_mode_t   mode        // input: AES_ECB or AES_CCM
)
{
    psa_encryption_structure *context;

    if (mode == AES_ECB)
    {
        context = 
            (psa_encryption_structure *)th_malloc(sizeof(psa_encryption_structure));

        context->attributes = th_malloc(sizeof(psa_key_attributes_t));
        memset(context->attributes, 0, sizeof(psa_key_attributes_t));

        if (mode == AES_ECB)
        {
            context->operation = th_malloc(sizeof(psa_cipher_operation_t));
            memset(context->operation, 0, sizeof(psa_cipher_operation_t));
        }
        psa_set_key_usage_flags( context->attributes,
                                 PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
        psa_set_key_algorithm( context->attributes, PSA_ALG_ECB_NO_PADDING );
        psa_set_key_type( context->attributes, PSA_KEY_TYPE_AES );

        *p_context = context;
    }
    else if (mode == AES_CCM)
    {
        context = 
            (psa_encryption_structure *)th_malloc(sizeof(psa_encryption_structure));

        context->attributes = th_malloc(sizeof(psa_key_attributes_t));
        memset(context->attributes, 0, sizeof(psa_key_attributes_t));

        psa_set_key_usage_flags( context->attributes,
                                    PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
        psa_set_key_algorithm( context->attributes, PSA_ALG_CCM );
        psa_set_key_type( context->attributes, PSA_KEY_TYPE_AES );

        *p_context = context;
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
)
{
    int                  keybits;

    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;

    keybits = keylen * 8;

    psa_crypto_init( );

    psa_set_key_bits( context->attributes, keybits );

    status = psa_import_key( context->attributes, p_key, keylen, &context->key_handle );
    if (status != PSA_SUCCESS)
    {
        th_printf("e-[Failed to set CCM key: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    if (mode == AES_ECB)
    {
        if (func == AES_ENC)
            status = psa_cipher_encrypt_setup( context->operation, context->key_handle, PSA_ALG_ECB_NO_PADDING );
        else // AES_DEC
            status = psa_cipher_decrypt_setup( context->operation, context->key_handle, PSA_ALG_ECB_NO_PADDING );

        if (status != PSA_SUCCESS)
        {
            th_printf("e-[psa_cipher_encrypt_setup: -0x%04x]\r\n", -status);
            return EE_STATUS_ERROR;
        }
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
th_aes128_deinit(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
)
{
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t res_len;

    if (mode == AES_ECB)
    {
        psa_cipher_finish( context->operation,
                                  NULL,
                                  AES_BLOCKLEN,
                                  &res_len );

        psa_cipher_abort( context->operation );
    }

    psa_destroy_key( context->key_handle );
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
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t res_len;

    status = psa_cipher_update( context->operation,
                                p_pt, AES_BLOCKLEN,
                                p_ct, AES_BLOCKLEN,
                                &res_len );

    if( status != PSA_SUCCESS )
    {
        return( EE_STATUS_ERROR );
    }

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
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t res_len;

    status = psa_cipher_update( context->operation,
                                p_ct, AES_BLOCKLEN,
                                p_pt, AES_BLOCKLEN,
                                &res_len );

    if( status != PSA_SUCCESS )
    {
        return( EE_STATUS_ERROR );
    }

    return EE_STATUS_OK;
}

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
)
{
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t ciphertext_length;

    status = psa_aead_encrypt( context->key_handle,      // key
                               PSA_ALG_CCM,              // algorithm
                               p_iv, ivlen,              // nonce
                               NULL, 0,                  // additional data
                               p_pt, ptlen,              // plaintext
                               p_ct, ptlen + taglen,     // ciphertext
                               &ciphertext_length );     // length of output
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed perform CCM encrypt: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

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
    psa_status_t status;
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;
    size_t plaintext_length;

    status = psa_aead_decrypt( context->key_handle,   // key
                               PSA_ALG_CCM,            // algorithm
                               p_iv, ivlen,            // nonce
                               NULL, 0,                // additional data
                               p_ct, ctlen,            // ciphertext
                               p_pt, ctlen,            // plaintext
                               &plaintext_length );    // length of output
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed perform CCM decrypt: -0x%04x]\r\n", -status);
        return( EE_STATUS_OK );
    }

    return EE_STATUS_OK;
}

/**
 * Clean up the context created.
 * 
 * Indicate the mode that was used for _create()
 */
void
th_aes128_destroy(
    void              *p_context,   // input: portable context
    aes_cipher_mode_t  mode         // input: AES_ECB or AES_CCM
)
{
    psa_encryption_structure *context = (psa_encryption_structure *) p_context;

    th_free(context->attributes);
     if (mode == AES_ECB) th_free(context->operation);

    mbedtls_psa_crypto_free( );

    th_free(p_context);
}
