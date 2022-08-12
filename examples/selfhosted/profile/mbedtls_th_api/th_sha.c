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

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#include "ee_sha.h"

typedef struct {
    ee_sha_size_t size;
    union {
        mbedtls_sha256_context sha256;
        mbedtls_sha512_context sha512;
    } ctx;
} th_mbedtls_sha_context_t;

/**
 * Create the context passed between functions.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_create(void **pp_context, ee_sha_size_t size)
{
    th_mbedtls_sha_context_t *ctx;

    if (size != EE_SHA256 && size != EE_SHA384)
    {
        th_printf("e-[th_sha_create unsupported size]\r\n");
        return EE_STATUS_ERROR;
    }
    ctx = th_malloc(sizeof(th_mbedtls_sha_context_t));
    if (!ctx)
    {
        th_printf("e-[th_sha_create malloc fail]\r\n");
        return EE_STATUS_ERROR;
    }
    ctx->size = size;
    *pp_context = (void *)ctx;
    return EE_STATUS_OK;
}

/**
 * Initialize the context prior to a hash operation.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_init(void *p_context)
{
    int ret;
    if (((th_mbedtls_sha_context_t*)(p_context))->size == EE_SHA256)
    {
        mbedtls_sha256_init(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha256);
        ret = mbedtls_sha256_starts(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha256,
                                    0 /* 0 for SHA-256 */);
    }
    else if (((th_mbedtls_sha_context_t*)(p_context))->size == EE_SHA384)
    {
        mbedtls_sha512_init(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha512);
        ret = mbedtls_sha512_starts(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha512,
                                    1 /* 1 for SHA-384 */);
    }
    else
    {
        th_printf("e-[th_sha_init unsupported size]\r\n");
        return EE_STATUS_ERROR;
    }

    if (ret != 0)
    {
        th_printf("e-[th_sha_init: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Process the hash
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_process(void *p_context, const uint8_t *p_in, uint32_t len)
{
    int ret;
    if (((th_mbedtls_sha_context_t*)(p_context))->size == EE_SHA256)
    {
        ret = mbedtls_sha256_update(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha256, p_in, len);
    }
    else if (((th_mbedtls_sha_context_t*)(p_context))->size == EE_SHA384)
    {
        ret = mbedtls_sha512_update(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha512, p_in, len);
    }
    else
    {
        th_printf("e-[th_sha_process unsupported size]\r\n");
        return EE_STATUS_ERROR;
    }

    if (ret != 0)
    {
        th_printf("e-[th_sha_process: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Return the digest.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha_done(void *p_context, uint8_t *p_result)
{
    int ret;
    if (((th_mbedtls_sha_context_t*)(p_context))->size == EE_SHA256)
    {
        ret = mbedtls_sha256_finish(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha256, p_result);
    }
    else if (((th_mbedtls_sha_context_t*)(p_context))->size == EE_SHA384)
    {
        ret = mbedtls_sha512_finish(&((th_mbedtls_sha_context_t*)(p_context))->ctx.sha512, p_result);
    }
    else
    {
        th_printf("e-[th_sha_done unsupported size]\r\n");
        return EE_STATUS_ERROR;
    }

    if (ret != 0)
    {
        th_printf("e-[th_sha_done: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 *
 * return EE_STATUS_OK on success.
 */
void
th_sha_destroy(void *p_context)
{
    th_free(p_context);
}
