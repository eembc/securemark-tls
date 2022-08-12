/*
 * Copyright (C) 2015-2017 EEMBC(R). All Rights Reserved
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
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/types.h>

#include "ee_sha.h"

/* can be set for static memory use */
#define HEAP_HINT NULL
/* used with crypto callbacks and async */
#define DEVID -1

typedef struct BenchmarkHashContext_s
{
    enum wc_HashType type;
    union ShaUnion_u {
        wc_Sha256 sha256;
        wc_Sha384 sha384;
    } sha;
} ctx_t;

ee_status_t
th_sha_create(void **pp_context, ee_sha_size_t size)
{
    ctx_t *ctx;

    ctx = (ctx_t *)th_malloc(sizeof(ctx_t));
    if (NULL == ctx)
    {
        th_printf("e-[th_sha_create() malloc failure]\r\n");
        return EE_STATUS_ERROR;
    }
    switch (size)
    {
        /* Switch to wolfSSL identifiers. */
        case EE_SHA256:
            ctx->type = WC_HASH_TYPE_SHA3_256;
            break;
        case EE_SHA384:
            ctx->type = WC_HASH_TYPE_SHA3_384;
            break;
        default:
            th_printf("e-[th_sha_create() invalid SHA size]\r\n");
            return EE_STATUS_ERROR;
    }
    *pp_context = (void *)ctx;
    return EE_STATUS_OK;
}

ee_status_t
th_sha_init(void *p_context)
{
    ctx_t *ctx = (ctx_t *)p_context;
    int ret;

    switch (ctx->type)
    {
        case WC_HASH_TYPE_SHA3_256:
            ret = wc_InitSha256_ex(&(ctx->sha.sha256), HEAP_HINT, DEVID);
            break;
        case WC_HASH_TYPE_SHA3_384:
            ret = wc_InitSha384_ex(&(ctx->sha.sha384), HEAP_HINT, DEVID);
            break;
        default:
            th_printf("e-[th_sha_init() invalid SHA size]\r\n");
            return EE_STATUS_ERROR;
    }
    if (ret != 0)
    {
        th_printf("e-[th_sha_init() failed to initialize]\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_sha_process(void *         p_context,
               const uint8_t *p_in,
               uint32_t  len)
{
    ctx_t *ctx = (ctx_t *)p_context;
    int ret;

    switch (ctx->type)
    {
        case WC_HASH_TYPE_SHA3_256:
            ret = wc_Sha256Update(&(ctx->sha.sha256), p_in, len);
            break;
        case WC_HASH_TYPE_SHA3_384:
            ret = wc_Sha384Update(&(ctx->sha.sha384), p_in, len);
            break;
        default:
            th_printf("e-[th_sha_process() invalid SHA size]\r\n");
            return EE_STATUS_ERROR;
    }
    if (ret != 0)
    {
        th_printf("e-[th_sha_process() failed to update]\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_sha_done(void *p_context, uint8_t *p_result)
{
    ctx_t *ctx = (ctx_t *)p_context;
    int ret;

    switch (ctx->type)
    {
        case WC_HASH_TYPE_SHA3_256:
            ret = wc_Sha256Final(&(ctx->sha.sha256), p_result);
            break;
        case WC_HASH_TYPE_SHA3_384:
            ret = wc_Sha384Final(&(ctx->sha.sha384), p_result);
            break;
        default:
            th_printf("e-[th_sha_done() invalid SHA size]\r\n");
            return EE_STATUS_ERROR;
    }
    if (ret != 0)
    {
        th_printf("e-[th_sha_done() failed to update]\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

void
th_sha_destroy(void *p_context)
{
    ctx_t *ctx = (ctx_t *)p_context;

    if (NULL == p_context)
    {
        return;
    }
    switch (ctx->type)
    {
        case WC_HASH_TYPE_SHA3_256:
            wc_Sha256Free(&(ctx->sha.sha256));
            break;
        case WC_HASH_TYPE_SHA3_384:
            wc_Sha384Free(&(ctx->sha.sha384));
            break;
        default:
            th_printf("e-[th_sha_destroy() invalid SHA size]\r\n");
    }
    th_free(ctx);
    p_context = NULL;
}
