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

#define FREE(x)    \
    if (NULL != x) \
    th_free(x)

#define CHK1(x)         \
    {                   \
        ret = x;        \
        if (ret < 0)    \
        {               \
            goto error; \
        }               \
    }

typedef struct
{
    union
    {
        ecc_key        ecc;
        curve25519_key c25519;
    } key;
    union
    {
        ecc_key        ecc;
        curve25519_key c25519;
    } peer;
    WC_RNG       rng;
    ecc_curve_id curve;
} ctx_t;

ee_status_t
th_ecdh_create(void **pp_context, ee_ecdh_group_t group)
{
    int    ret;
    ctx_t *ctx = (ctx_t *)th_malloc(sizeof(ctx_t));

    if (ctx == NULL)
    {
        th_printf("e-[th_ecdsa_create: malloc fail]\r\n");
        return EE_STATUS_ERROR;
    }
    th_memset(ctx, 0, sizeof(ctx_t));
    wc_InitRng_ex(&(ctx->rng), HEAP_HINT, DEVID);
    /* Switch from EEMBC group enums to SDK enums for consistency, make key. */
    switch (group)
    {
        case EE_P256R1:
            ctx->curve = ECC_SECP256R1;
            CHK1(wc_ecc_init_ex(&(ctx->key.ecc), HEAP_HINT, DEVID));
            CHK1(wc_ecc_make_key(&(ctx->rng), 32, &(ctx->key.ecc)));
            break;
        case EE_P384:
            ctx->curve = ECC_SECP384R1;
            CHK1(wc_ecc_init_ex(&(ctx->key.ecc), HEAP_HINT, DEVID));
            CHK1(wc_ecc_make_key(&(ctx->rng), 48, &(ctx->key.ecc)));
            break;
        case EE_C25519:
            ctx->curve = ECC_X25519; /* [sic], should be C25519? */
            CHK1(wc_curve25519_init(&(ctx->key.c25519)));
            CHK1(wc_curve25519_make_key(&(ctx->rng), 32, &(ctx->key.c25519)));
            break;
        default:
            th_printf("e-[th_ecdsa_create: invalid group %d]\r\n", group);
            return EE_STATUS_ERROR;
    }
    *pp_context = ctx;
    return EE_STATUS_OK;
error:
    *pp_context = NULL;
    th_free(ctx);
    th_printf("e-[th_ecdh_create: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdh_set_peer_public_key(void *        p_context,
                            uint8_t *     p_pub,
                            uint_fast32_t publen)
{
    int    ret;
    ctx_t *ctx = (ctx_t *)p_context;

    switch (ctx->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_init_ex(&(ctx->peer.ecc), HEAP_HINT, DEVID));
            CHK1(wc_ecc_import_x963(p_pub, publen, &(ctx->peer.ecc)));
            break;
        case ECC_X25519:
            CHK1(wc_curve25519_init(&(ctx->peer.c25519)));
            CHK1(wc_curve25519_import_public_ex(
                p_pub, publen, &(ctx->peer.c25519), EC25519_LITTLE_ENDIAN));
            break;
        default:
            th_printf("e-[th_ecdh_set_peer_public_key: invalid curve %d]\r\n",
                      ctx->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdh_set_peer_public_key: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdh_calc_secret(void *p_context, uint8_t *p_sec, uint_fast32_t *p_seclen)
{
    int    ret;
    ctx_t *ctx = (ctx_t *)p_context;

    switch (ctx->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_shared_secret(
                &(ctx->key.ecc), &(ctx->peer.ecc), p_sec, p_seclen));
            break;
        case ECC_X25519:
            CHK1(wc_curve25519_shared_secret_ex(&(ctx->key.c25519),
                                                &(ctx->peer.c25519),
                                                p_sec,
                                                p_seclen,
                                                EC25519_LITTLE_ENDIAN));
            break;
        default:
            th_printf("e-[Invalid curve in th_ecdh_calc_secret]\r\n");
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdh_calc_secret: error: %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

void
th_ecdh_destroy(void *p_context)
{
    ctx_t *ctx = (ctx_t *)p_context;

    if (NULL == ctx)
    {
        return;
    }
    switch (ctx->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            wc_ecc_free(&(ctx->key.ecc));
            wc_ecc_free(&(ctx->peer.ecc));
            break;
        case ECC_X25519:
            wc_curve25519_free(&(ctx->key.c25519));
            wc_curve25519_free(&(ctx->peer.c25519));
            break;
        default:
            th_printf("e-[th_ecdh_destroy: invalid curve %d]\r\n", ctx->curve);
            /* still need to free ctx! ... return EE_STATUS_ERROR; */
            break;
    }
    wc_FreeRng(&(ctx->rng));
    th_free(ctx);

    ctx = NULL;
}
