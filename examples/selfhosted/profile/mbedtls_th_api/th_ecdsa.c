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

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/ecdsa.h"

#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_random.h"


// helper function defined in th_ecdh.h; not mandatory but very useful!
int load_private_key(void *, unsigned char *, size_t);

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
    mbedtls_ecdsa_context *p_ecdsa;
    
    p_ecdsa = (mbedtls_ecdsa_context *)th_malloc(sizeof(mbedtls_ecdsa_context));
    if (p_ecdsa == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdsa_create\r\n");
        return EE_STATUS_ERROR;
    }
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
    mbedtls_ecdsa_context *p_ecdsa;
    int                    ret;

    p_ecdsa = (mbedtls_ecdsa_context *)p_context;
    mbedtls_ecdsa_init(p_ecdsa);
    switch (group) {
        case EE_P256R1:
            ret = mbedtls_ecp_group_load(&p_ecdsa->grp,
                                         MBEDTLS_ECP_DP_SECP256R1);
            if (ret != 0)
            {
                th_printf("e-[Failed to ECDSA init: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
            break;
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_init]\r\n");
            return EE_STATUS_ERROR;
    }

    // load the private key and generate our own public key
    return load_private_key(p_context, p_private, plen);
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
    mbedtls_ecdsa_context *p_ecdsa;
    size_t                 slent;
    int                    ret;

    p_ecdsa = (mbedtls_ecdsa_context*)p_context;
    // WARNING: Copy *slen into local storage if your SDK size type is
    //          not the same size as "unsigned int" and recast on assignment.
    slent = *p_slen;

    ret = mbedtls_ecdsa_write_signature(
        p_ecdsa,
        MBEDTLS_MD_SHA256,
        p_hash,
        hlen,
        p_sig,
        slent,
        &slent,
        ee_random,
        NULL
    );

    if (ret != 0)
    {
        th_printf("e-[Failed to sign in th_ecdsa_sign: -0x%04x]\r\n", -ret);
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
    unsigned char *p_sig,       // output: signature
    unsigned int   slen         // input: length of signature in bytes
)
{ 
    mbedtls_ecdsa_context *p_ecdsa;
    int                    ret;

    p_ecdsa = (mbedtls_ecdsa_context *)p_context;
    ret = mbedtls_ecdsa_read_signature(p_ecdsa, p_hash, hlen, p_sig, slen);

    if (ret != 0)
    {
        th_printf("e-[Failed to verify in th_ecdsa_verify: -0x%04x]\r\n", -ret);
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
    mbedtls_ecdsa_free((mbedtls_ecdsa_context*)p_context);
    th_free(p_context);
}
