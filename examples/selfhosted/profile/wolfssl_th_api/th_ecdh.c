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

typedef struct ecc_context {
    ecc_key *key;
    WC_RNG  *rng;
} ecc_context;

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
    WC_RNG      *rng;
    ecc_key     *key;
    ecc_context *ctx;

    key = (ecc_key*)th_malloc(sizeof(ecc_key));
    if (key == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }

    rng = (WC_RNG*)th_malloc(sizeof(WC_RNG));
    if (rng == NULL)
    {
        th_free(key);
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }

    ctx = (ecc_context*)th_malloc(sizeof(ecc_context));
    if (key == NULL)
    {
        th_free(key);
        th_free(rng);
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }

    ctx->key = key;
    ctx->rng = rng;

    wc_ecc_init_ex(key, HEAP_HINT, DEVID);
    wc_InitRng_ex(rng, HEAP_HINT, DEVID);
    *p_context = (void*)ctx;
    return EE_STATUS_OK;
}

/**
 * Load a 64-byte public key from a peer, big-endian; confim is on curve
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
load_public_peer_key(
    void          *p_context,
    unsigned char *p_pub, /* raw X | Y */
    size_t         publen
)
{
    int ret;
    unsigned char uncompressed[65];

    uncompressed[0] = 0x04;
    th_memcpy(&(uncompressed[1]), p_pub, publen);

    ret = wc_ecc_import_x963(uncompressed, publen+1,
            ((ecc_context*)p_context)->key);
    if (ret != 0)
    {
        th_printf("e-[import EC key failed : -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

/**
 * Load private & populate ecdh->Q public point
 */
ee_status_t
load_private_key(
    void          *p_context,
    unsigned char *p_private,
    size_t         prilen
) {
    int ret;

    ret = wc_ecc_import_private_key(p_private, prilen, NULL, 0,
            ((ecc_context*)p_context)->key);
    if (ret != 0)
    {
        th_printf("e-[error loading private key : -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    // compute the public key from the provided secret
    ret = wc_ecc_make_pub(((ecc_context*)p_context)->key, NULL);
    if (ret != 0)
    {
        th_printf("e-[error generating public EC key from private :"
                  " -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

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
    unsigned char  *p_private, // input: private key, from host
    unsigned int    prilen,    // input: private key length in bytes
    unsigned char  *p_public,  // input: peer public key, from host
    unsigned int    publen     // input: peer public key length in bytes
)
{
    int curveId;
    int ret;
    unsigned char uncompressed[65];
    
    switch (group)
    { 
        case EE_P256R1:
            curveId = ECC_SECP256R1;
            break; 
        default:
            th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }


    uncompressed[0] = 0x04;
    th_memcpy(&(uncompressed[1]), p_public, publen);

#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    #error undifne WOLFSSL_VALIDATE_ECC_IMPORT to set up missmatch private ours public peers
#endif

    ret = wc_ecc_import_private_key_ex(p_private, prilen,
                uncompressed, publen+1, ((ecc_context*)p_context)->key, curveId);
    if (ret != 0)
    {
        th_printf("e-[loading group key failed : -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

#ifdef ECC_TIMING_RESISTANT
    wc_ecc_set_rng(((ecc_context*)p_context)->key,
                   ((ecc_context*)p_context)->rng);
#endif
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
    unsigned int   slen        // input: length of shared buffer in bytes
)
{
    ecc_key *key;
    int     ret;
    word32  olen = slen;
    
    key = ((ecc_context*)p_context)->key;
    if (slen != wc_ecc_size(key))
    {
        th_printf("e-[Secret buffer wrong size %u ]\r\n", slen);
        return EE_STATUS_ERROR;
    }

    ret = wc_ecc_shared_secret(key, key, p_secret, &olen);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_shared_secret: -0x%04x]\r\n", -ret);
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
    if (p_context != NULL) {
        ecc_context *ctx = (ecc_context*)p_context;
        wc_ecc_free(ctx->key);
        wc_FreeRng(ctx->rng);
        th_free(ctx->key);
        th_free(ctx->rng);
        th_free(p_context);
    }
}
