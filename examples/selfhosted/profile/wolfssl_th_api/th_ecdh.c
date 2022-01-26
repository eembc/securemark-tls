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
#include <wolfssl/wolfcrypt/curve25519.h>

/* can be set for static memory use */
#define HEAP_HINT NULL

/* used with crypto callbacks and async */
#define DEVID -1

#include "ee_ecdh.h"

#define FREE(x) if (NULL != x) th_free(x)

typedef struct ecc_context
{
    ecc_key * ecc_key_pri;
    ecc_key * ecc_key_pub;
    curve25519_key * x255_key_pri;
    curve25519_key * x255_key_pub;
    WC_RNG * rng;
} ecc_context;

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_create(
    void    **p_context, // output: portable context
    ecdh_group_t   group // input: curve group
)
{
    ecc_context *ctx = NULL;

    ctx = (ecc_context *)th_malloc(sizeof(ecc_context));
    if (NULL == ctx) goto error;

    th_memset(ctx, 0, sizeof(ecc_context));

    switch (group) {
        case EE_P256R1:
            ctx->ecc_key_pri = (ecc_key *)th_malloc(sizeof(ecc_key));
            if (NULL == ctx->ecc_key_pri) {
                goto error;
            }
            wc_ecc_init_ex(ctx->ecc_key_pri, HEAP_HINT, DEVID);
            break;
        case EE_C25519:
            ctx->x255_key_pri = (curve25519_key *)th_malloc(sizeof(curve25519_key));
            if (NULL == ctx->x255_key_pri) {
                goto error;
            }
            wc_curve25519_init(ctx->x255_key_pri);
            ctx->x255_key_pub = (curve25519_key *)th_malloc(sizeof(curve25519_key));
            if (NULL == ctx->x255_key_pub) {
                goto error;
            }
            wc_curve25519_init(ctx->x255_key_pub);
            break;
        default:
            th_printf("e-[Invalid curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }

    ctx->rng = (WC_RNG *)th_malloc(sizeof(WC_RNG));
    if (NULL == ctx->rng) goto error;
    wc_InitRng_ex(ctx->rng, HEAP_HINT, DEVID);

    *p_context = (void *)ctx;
    return EE_STATUS_OK;

error:
    FREE(ctx->ecc_key_pri);
    FREE(ctx->ecc_key_pub);
    FREE(ctx->x255_key_pri);
    FREE(ctx->x255_key_pub);
    FREE(ctx->rng);
    FREE(ctx);
    th_printf("e-[Malloc error in th_ecdh_init\r\n");
    return EE_STATUS_ERROR;
}

/**
 * Initialize to a group (must be in the EE_ enum)
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_init(void *         p_context, // input: portable context
             ecdh_group_t   group,     // input: see `ecdh_group_t` for options
             unsigned char *p_private, // input: private key, from host
             unsigned int   prilen,    // input: private key length in bytes
             unsigned char *p_public,  // input: peer public key, from host
             unsigned int   publen     // input: peer public key length in bytes
)
{
    int           ret;
    unsigned char uncompressed[65];
    ecc_context *ctx = (ecc_context *)p_context;

#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
#error undifne WOLFSSL_VALIDATE_ECC_IMPORT to set up missmatch private ours public peers
#endif

    switch (group)
    {
        case EE_P256R1:
            uncompressed[0] = 0x04;
            th_memcpy(&(uncompressed[1]), p_public, publen);
            ret = wc_ecc_import_private_key_ex(p_private,
                                            prilen,
                                            uncompressed,
                                            publen + 1,
                                            ctx->ecc_key_pri,
                                            ECC_SECP256R1);
            if (ret != 0)
            {
                th_printf("e-[wc_ecc_import_private_key_ex: -%d]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
#ifdef ECC_TIMING_RESISTANT
            wc_ecc_set_rng(ctx->ecc_key_pri, ctx->rng);
#endif
            break;
        case EE_C25519:
            ret = wc_curve25519_import_private(
                p_private,
                prilen,
                ctx->x255_key_pri);
            if (ret != 0)
            {
                th_printf("e-[wc_curve25519_import_private: -%d]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
            th_memcpy(uncompressed, p_public, publen);
            // RFC7748 Section 5
            uncompressed[0] &= 127;
            ret = wc_curve25519_check_public(uncompressed, publen, EC25519_BIG_ENDIAN);
            if (ret != 0)
            {
                th_printf("e-[wc_curve25519_check_public: -%d]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
            ret = wc_curve25519_import_public(
                uncompressed,
                publen,
                ctx->x255_key_pub);
            if (ret != 0)
            {
                th_printf("e-[wc_curve25519_import_public: -%d]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
            break;
        default:
            th_printf("e-[Invalid curve in th_ecdh_init]\r\n");
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
th_ecdh_calc_secret(void *         p_context, // input: portable context
                    ecdh_group_t group, // input: curve group
                    unsigned char *p_secret,  // output: shared secret
                    unsigned int slen // input: length of shared buffer in bytes
)
{
    int      ret;
    word32   olen = slen;
    ecc_context *ctx = (ecc_context *)p_context;

    switch (group) {
        case EE_P256R1:
            ret = wc_ecc_shared_secret(
                ctx->ecc_key_pri,
                ctx->ecc_key_pri,
                p_secret,
                &olen);
            break;
        case EE_C25519:
            ret = wc_curve25519_shared_secret(
                ctx->x255_key_pri,
                ctx->x255_key_pub,
                p_secret,
                &olen);
            break;
        default:
            th_printf("e-[Invalid curve in th_ecdh_calc_secret]\r\n");
            return EE_STATUS_ERROR;
    }
    if (ret != 0)
    {
        th_printf("e-[wc_*_shared_secret: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdh_destroy(void *p_context // input: portable context
)
{
    if (p_context != NULL)
    {
        ecc_context *ctx = (ecc_context *)p_context;
        if (ctx->rng) wc_FreeRng(ctx->rng);
        if (ctx->ecc_key_pri) wc_ecc_free(ctx->ecc_key_pri);
        if (ctx->ecc_key_pub) wc_ecc_free(ctx->ecc_key_pub);
        if (ctx->x255_key_pri) wc_curve25519_free(ctx->x255_key_pri);
        if (ctx->x255_key_pub) wc_curve25519_free(ctx->x255_key_pub);
        FREE(ctx->ecc_key_pri);
        FREE(ctx->ecc_key_pub);
        FREE(ctx->x255_key_pri);
        FREE(ctx->x255_key_pub);
        FREE(ctx->rng);
        FREE(ctx);
    }
}
