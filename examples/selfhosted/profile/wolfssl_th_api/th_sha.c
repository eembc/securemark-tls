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

#include "ee_sha.h"

ee_status_t
th_sha_create(void **pp_context, sha_size_t size)
{
    switch (size)
    {
        case EE_SHA256:
            *pp_context = (void *)th_malloc(sizeof(wc_Sha256));
            break;
        case EE_SHA384:
            *pp_context = (void *)th_malloc(sizeof(wc_Sha384));
            break;
        default:
            th_printf("e-[th_sha_create() invalid SHA size]\r\n");
            return EE_STATUS_ERROR;
    }
    if (NULL == *pp_context)
    {
        th_printf("e-[th_sha_create() malloc failure]\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_sha_init(void *p_context, sha_size_t size)
{
    int ret;
    switch (size)
    {
        case EE_SHA256:
            ret = wc_InitSha256((wc_Sha256 *)p_context);
            break;
        case EE_SHA384:
            ret = wc_InitSha384((wc_Sha384 *)p_context);
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
th_sha_process(void *         p_context, // input: portable context
               sha_size_t     size,      // input: SHA algorithm size
               const uint8_t *p_in,      // input: data to hash
               uint_fast32_t  len        // input: length of data in bytes
)
{
    int ret;
    switch (size)
    {
        case EE_SHA256:
            ret = wc_Sha256Update((wc_Sha256 *)p_context, p_in, len);
            break;
        case EE_SHA384:
            ret = wc_Sha384Update((wc_Sha384 *)p_context, p_in, len);
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
th_sha_done(void *     p_context, // input: portable context
            sha_size_t size,      // input: SHA algorithm size
            uint8_t *  p_result   // output: digest, SHA_SIZE bytes
)
{
    int ret;
    switch (size)
    {
        case EE_SHA256:
            ret = wc_Sha256Final((wc_Sha256 *)p_context, p_result);
            break;
        case EE_SHA384:
            ret = wc_Sha384Final((wc_Sha384 *)p_context, p_result);
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
th_sha_destroy(void *     p_context, // input: portable context
               sha_size_t size       // input: SHA algorithm size
)
{
    if (NULL == p_context)
    {
        return;
    }
    switch (size)
    {
        case EE_SHA256:
            wc_Sha256Free((wc_Sha256 *)p_context);
            break;
        case EE_SHA384:
            wc_Sha384Free((wc_Sha384 *)p_context);
            break;
        default:
            th_printf("e-[th_sha_destroy() invalid SHA size]\r\n");
    }
    th_free(p_context);
    p_context = NULL;
}
