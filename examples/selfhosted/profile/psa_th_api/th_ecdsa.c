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

#include "mbedtls/config.h"
#include "psa/crypto.h"

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_ECDSA_DETERMINISTIC) || !defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#error "Necessary PSA functionality not defined!"
#endif

struct psa_ecdsa_structure
{
    psa_key_attributes_t *attributes;  // own key attributes
    psa_key_handle_t key_handle;       // own key handle
};

typedef struct psa_ecdsa_structure psa_ecdsa_structure;

#include "ee_ecdh.h"
#include "ee_ecdsa.h" 

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_create(
    void **p_context // output: portable context
)
{
    psa_ecdsa_structure *p_ecdsa;

    p_ecdsa = 
       (psa_ecdsa_structure *)th_malloc(sizeof(psa_ecdsa_structure));
    if (p_ecdsa == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }
    memset(p_ecdsa,0,sizeof(psa_ecdsa_structure));

    p_ecdsa->attributes = th_malloc(sizeof(psa_key_attributes_t));
    memset(p_ecdsa->attributes, 0, sizeof(psa_key_attributes_t));

    *p_context = (void *)p_ecdsa; 
    return EE_STATUS_OK;
}

/**
 * Initialize to a group (must be in the EE_ enum) with a predefined
 * private key.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_init(
    void            *p_context, // input: portable context
    ecdh_group_t     group,     // input: see `ecdh_group_t` for options
    unsigned char   *p_private, // input: private key from host
    size_t           plen       // input: length of private key in bytes
)
{
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;
    psa_status_t status;

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_crypto_init: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    switch (group)
    { 
        case EE_P256R1:
            psa_set_key_usage_flags( context->attributes,
                                     PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH );
            psa_set_key_algorithm( context->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256) );
            psa_set_key_type( context->attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );
            break; 
        default:
            th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }

    // Import own private key
    status = psa_import_key(context->attributes, p_private, plen, &context->key_handle );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_import_key: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Create a signature using the specified hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_sign(
    void          *p_context,   // input: portable context
    unsigned char *p_hash,      // input: sha256 digest
    unsigned int   hlen,        // input: length of digest in bytes
    unsigned char *p_sig,       // output: signature
    unsigned int  *p_slen       // in/out: input=MAX slen, output=resultant
)
{
    size_t                 slent;
    psa_status_t status;
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;

    status = psa_sign_hash( context->key_handle,            // key handle 
                            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), // signature algorithm
                            p_hash, hlen,                   // hash of the message
                            p_sig, *p_slen,                 // signature (as output)
                            &slent );                       // length of signature output
    
	if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed to sign in th_ecdsa_sign: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    *p_slen = (unsigned int)slent;

    return EE_STATUS_OK;
}

/**
 * Create a signature using SHA256 hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_verify(
    void          *p_context,   // input: portable context
    unsigned char *p_hash,      // input: sha256 digest
    unsigned int   hlen,        // input: length of digest in bytes
    unsigned char *p_sig,       // input: signature
    unsigned int   slen         // input: length of signature in bytes
)
{ 
    psa_status_t status;
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;

    status = psa_verify_hash( context->key_handle,                // key handle
                              PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),     // signature algorithm
                              p_hash, hlen,                       // hash of message
                              p_sig, slen );                      // signature
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed to verify in th_ecdsa_verify: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdsa_destroy(
    void *p_context // portable context
)
{ 
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;

    th_free(context->attributes);

    psa_destroy_key( context->key_handle );

    mbedtls_psa_crypto_free( );

    th_free(p_context);
}
