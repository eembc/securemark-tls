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

#include <wolfssl/options.h> 
#include <wolfssl/wolfcrypt/ecc.h>

/* can be set for static memory use */
#define HEAP_HINT NULL

/* used with crypto callbacks and async */
#define DEVID -1


#include "ee_ecdh.h"
#include "ee_ecdsa.h" 

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
    ecc_key *p_ecdsa;
    
    p_ecdsa = (ecc_key*)th_malloc(sizeof(ecc_key));
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
    ecc_key *p_ecdsa;
    int     ret, curveId;

    p_ecdsa = (ecc_key*)p_context;
    ret = wc_ecc_init_ex(p_ecdsa, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[Failed to intialize key : -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    switch (group) {
        case EE_P256R1:
            curveId = ECC_SECP256R1;
            break;
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_init]\r\n");
            return EE_STATUS_ERROR;
    }

    ret = wc_ecc_import_private_key_ex(p_private, plen, NULL, 0, p_ecdsa,
            curveId);
    if (ret != 0)
    {
        th_printf("e-[loading group key failed : -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = wc_ecc_make_pub((ecc_key*)p_context, NULL);
    if (ret != 0)
    {
        th_printf("e-[error generating public EC key from private :"
                  " -0x%04x]\r\n", -ret);
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
    ecc_key *p_ecdsa;
    int     ret;
    WC_RNG  rng;

    p_ecdsa = (ecc_key*)p_context;
    ret = wc_InitRng_ex(&rng, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[Failed to create RNG for ECC signing: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = wc_ecc_sign_hash(p_hash, hlen, p_sig, p_slen, &rng, p_ecdsa);
    if (ret != 0)
    {
        th_printf("e-[Failed to sign in th_ecdsa_sign: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    wc_FreeRng(&rng);

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
    ecc_key *p_ecdsa;
    int     ret, verify;

    p_ecdsa = (ecc_key*)p_context;
    ret = wc_ecc_verify_hash(p_sig, slen, p_hash, hlen, &verify, p_ecdsa);
    if (ret != 0 || verify != 1)
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
    wc_ecc_free((ecc_key*)p_context);
    th_free(p_context);
}
