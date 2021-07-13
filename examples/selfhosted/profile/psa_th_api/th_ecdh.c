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

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_ECP_C) || !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#error "Necessary PSA functionality not defined!"
#endif

struct psa_ke_structure
{
    psa_key_attributes_t *client_attributes;  // own key attributes
    psa_key_handle_t client_key_handle;       // own key handle
    unsigned char *p_public;                  // public key of peer
    uint_fast32_t  publen;                    // peer public key length
};

typedef struct psa_ke_structure psa_ke_structure;

#include "ee_ecdh.h"

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_create(
    void **p_context // output: portable context
)
{
    psa_ke_structure *context;
    psa_status_t status;

    context = 
       (psa_ke_structure *)th_malloc(sizeof(psa_ke_structure));
    if (context == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }
    memset(context,0,sizeof(psa_ke_structure));

    context->client_attributes = th_malloc(sizeof(psa_key_attributes_t));
    memset(context->client_attributes, 0, sizeof(psa_key_attributes_t));

    // Initialize the PSA Crypto API
    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_crypto_init: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }
	
    *p_context = context;

    return EE_STATUS_OK;
}

/**
 * Initialize to a group (must be in the EE_ enum)
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_init(
    void           *p_context, // input: portable context
    ecdh_group_t    group,     // input: see `ecdh_group_t` for options
    uint8_t        *p_private, // input: private key, from host
    uint_fast32_t   prilen,    // input: private key length in bytes
    uint8_t        *p_public,  // input: peer public key, from host
    uint_fast32_t   publen     // input: peer public key length in bytes
)
{
    psa_ke_structure *context = (psa_ke_structure *) p_context;
    psa_status_t status;

    switch (group)
    { 
        case EE_P256R1:
            psa_set_key_usage_flags( context->client_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( context->client_attributes, PSA_ALG_ECDH );
            psa_set_key_type( context->client_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );
            break; 
        default:
            th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }

    // Copy public key of peer into internal context structure
    context->p_public = th_malloc(publen+1);
    if (context->p_public == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_init\r\n");
        return EE_STATUS_ERROR;
    }

    // First byte for mbedtls_ecp_point_read_binary must be 0x04
    context->p_public[0] = 0x04;
    th_memcpy(&(context->p_public[1]), p_public, publen);
    context->publen = publen+1;

    // Import own private key
    status = psa_import_key(context->client_attributes, p_private, prilen, &context->client_key_handle );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_import_key (client): -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform ECDH mixing.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_calc_secret(
    void          *p_context,  // input: portable context
    unsigned char *p_secret,   // output: shared secret
    uint_fast32_t  slen        // input: length of shared buffer in bytes
)
{
    size_t olen;
    psa_status_t status;

    psa_ke_structure *context = (psa_ke_structure *) p_context;

    /* Produce ECDHE derived key */
    status = psa_raw_key_agreement( PSA_ALG_ECDH,                       // algorithm
                                    context->client_key_handle,         // client secret key
                                    context->p_public, context->publen, // server public key
                                    p_secret, slen,                     // buffer to store derived key
                                    &olen );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_raw_key_agreement: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR; 
    }

    /**
     * Must be the same size as the curve size; for example, if the curve is 
     * secp256r1, secret must be 32 bytes long.
     */
    // TODO: Magic number
    if (olen != 32u)
    {
        th_printf("e-[Output length isn 32B: %lu]\r\n", olen);
        return EE_STATUS_ERROR; 
    }

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdh_destroy(
    void *p_context // input: portable context
)
{
    psa_ke_structure *context = (psa_ke_structure *) p_context;

    th_free(context->client_attributes);
    th_free(context->p_public);

    psa_destroy_key( context->client_key_handle );

    mbedtls_psa_crypto_free( );

    th_free(p_context);
}
