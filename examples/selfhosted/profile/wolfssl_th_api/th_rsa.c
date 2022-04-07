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

#include "ee_rsa.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>

/* can be set for static memory use */
#define HEAP_HINT NULL
/* used with crypto callbacks and async */
#define DEVID -1

typedef struct rsa_context_t
{
    RsaKey *pubkey;
    WC_RNG *rng;
} rsa_context_t;

#define FREE(x)         \
    {                   \
        if (x)          \
        {               \
            th_free(x); \
            x = NULL;   \
        }               \
    }

ee_status_t
th_rsa_create(void **pp_context)
{
    rsa_context_t *ctx;
    int ret;

    ctx = (rsa_context_t *)th_malloc(sizeof(rsa_context_t));
    if (!ctx)
    {
        th_printf("e-[th_rsa_create failed to malloc]\r\n");
        return EE_STATUS_ERROR;
    }

    th_memset(ctx, 0, sizeof(rsa_context_t));

    ctx->pubkey = (RsaKey *)th_malloc(sizeof(RsaKey));
    ctx->rng    = (WC_RNG *)th_malloc(sizeof(WC_RNG));

    if (!ctx->pubkey || !ctx->rng)
    {
        th_printf("e-[th_rsa_create failed to malloc]\r\n");
        FREE(ctx->pubkey);
        FREE(ctx->rng);
        FREE(ctx);
        return EE_STATUS_ERROR;
    }

    ret = wc_InitRsaKey_ex(ctx->pubkey, HEAP_HINT, DEVID);
    if (ret)
    {
        th_printf("e-[wc_InitRsaKey_ex on private: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }


    *pp_context = ctx;

    return EE_STATUS_OK;
}

ee_status_t
th_rsa_set_public_key(void *         p_context,
            const uint8_t *p_pubkey,
            uint_fast32_t  publen)
{
    rsa_context_t *ctx      = (rsa_context_t *)p_context;
    word32         inOutIdx = 0;
    int            ret;

    ret = wc_RsaPublicKeyDecode(p_pubkey, &inOutIdx, ctx->pubkey, publen);
    if (ret)
    {
        th_printf("e-[wc_RsaPublicKeyDecode: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

ee_status_t
th_rsa_verify(void *         p_context,
              uint8_t *p_msg,
              uint_fast32_t  msglen,
              uint8_t *      p_sig,
              uint_fast32_t  slen)
{
    rsa_context_t *ctx = (rsa_context_t *)p_context;
    int            ret;

    ret = wc_RsaSSL_Verify(p_sig, slen, p_msg, msglen, ctx->pubkey);
    if (ret < 0)
    {
        th_printf("e-[wc_RsaSSL_Verify: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

void
th_rsa_destroy(void *p_context)
{
    rsa_context_t *ctx = (rsa_context_t *)p_context;
    FREE(ctx->pubkey);
    FREE(ctx->rng);
    FREE(ctx);
}
