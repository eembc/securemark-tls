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
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* can be set for static memory use */
#define HEAP_HINT NULL
/* used with crypto callbacks and async */
#define DEVID -1

#include "ee_ecdh.h"
#include "ee_ecdsa.h"

typedef struct
{
    union
    {
        ecc_key     ecc;
        ed25519_key ed25519;
    } key;
    WC_RNG       rng;
    ecc_curve_id curve;
} ctx_t;

#define CHK1(x)         \
    {                   \
        ret = x;        \
        if (ret < 0)    \
        {               \
            goto error; \
        }               \
    }

ee_status_t
th_ecdsa_create(void **pp_context, ee_ecdh_group_t group)
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
            CHK1(wc_ecc_set_deterministic(&(ctx->key.ecc), 1));
            break;
        case EE_P384:
            ctx->curve = ECC_SECP384R1;
            CHK1(wc_ecc_init_ex(&(ctx->key.ecc), HEAP_HINT, DEVID));
            CHK1(wc_ecc_make_key(&(ctx->rng), 48, &(ctx->key.ecc)));
            CHK1(wc_ecc_set_deterministic(&(ctx->key.ecc), 1));
            break;
        case EE_Ed25519:
            ctx->curve = ECC_X25519; /* [sic], should be C25519? */
            CHK1(wc_ed25519_init(&(ctx->key.ed25519)));
            CHK1(wc_ed25519_make_key(&(ctx->rng), 32, &(ctx->key.ed25519)));
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
    th_printf("e-[th_ecdsa_create: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdsa_sign(void *         p_context,
              uint8_t *      p_msg,
              uint_fast32_t  msglen,
              uint8_t *      p_sig,
              uint_fast32_t *p_siglen)
{
    ctx_t *c = (ctx_t *)p_context;
    int    ret;

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_sign_hash(
                p_msg, msglen, p_sig, p_siglen, &(c->rng), &(c->key.ecc)));
            break;
        case ECC_X25519:
            CHK1(wc_ed25519_sign_msg(
                p_msg, msglen, p_sig, p_siglen, &(c->key.ed25519)));
            break;
        default:
            th_printf("e-[th_ecdsa_sign: invalid curve %d]\r\n", c->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_sign: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdsa_verify(void *        p_context,
                uint8_t *     p_msg,
                uint_fast32_t msglen,
                uint8_t *     p_sig,
                uint_fast32_t siglen)
{
    ctx_t *c = (ctx_t *)p_context;
    int    ret;
    int    verify = 0;

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_verify_hash(
                p_sig, siglen, p_msg, msglen, &verify, &(c->key.ecc)));
            break;
        case ECC_X25519:
            ret = wc_ed25519_verify_msg(
                p_sig, siglen, p_msg, msglen, &verify, &(c->key.ed25519));
            if (ret != 0 && ret != SIG_VERIFY_E)
            {
                th_printf("e-[wc_ed25519_verify_msg: %d]\r\n", ret);
                return EE_STATUS_ERROR;
            }
            break;
        default:
            th_printf("e-[th_ecdsa_sign: invalid curve %d]\r\n", c->curve);
            return EE_STATUS_ERROR;
    }
    return verify == 0 ? EE_STATUS_ERROR : EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_verify: error: %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdsa_get_public_key(void *         p_context,
                        uint8_t *      p_out,
                        uint_fast32_t *p_outlen)
{
    ctx_t *c = (ctx_t *)p_context;
    int    ret;

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_export_x963(&(c->key.ecc), p_out, p_outlen));
            break;
        case ECC_X25519:
            CHK1(wc_ed25519_export_public(&(c->key.ed25519), p_out, p_outlen));
            break;
        default:
            th_printf("e-[th_ecdsa_get_public_key: invalid curve %d]\r\n",
                      c->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_get_public_key: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdsa_set_public_key(void *p_context, uint8_t *p_pub, uint_fast32_t publen)
{
    ctx_t *c = (ctx_t *)p_context;
    int    ret;

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_import_x963(p_pub, publen, &(c->key.ecc)));
            break;
        case ECC_X25519:
            CHK1(wc_ed25519_import_public(p_pub, publen, &(c->key.ed25519)));
            break;
        default:
            th_printf("e-[th_ecdsa_set_public_key: invalid curve %d]\r\n",
                      c->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_set_public_key: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

void
th_ecdsa_destroy(void *p_context)
{
    ctx_t *c = (ctx_t *)p_context;

    if (NULL == c)
    {
        return;
    }
    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            wc_ecc_free(&(c->key.ecc));
            break;
        case ECC_X25519:
            wc_ed25519_free(&(c->key.ed25519));
            break;
        default:
            th_printf("e-[th_ecdsa_destroy: invalid curve %d]\r\n", c->curve);
            /* still need to free ctx! ... return EE_STATUS_ERROR; */
            break;
    }
    wc_FreeRng(&(c->rng));
    th_free(c);

    c = NULL;
}
