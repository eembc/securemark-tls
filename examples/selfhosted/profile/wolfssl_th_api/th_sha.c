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

#include "ee_sha.h"

/**
 * Create the context passed between functions.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_create(void **context)
{
    wc_Sha256 *sha256;
    sha256 = th_malloc(sizeof(wc_Sha256));
    if (sha256 == NULL)
    {
        th_printf("e-sha256-?malloc\r\n");
        return EE_STATUS_ERROR;
    }
    *context = (void *)sha256;
    return EE_STATUS_OK;
}

/**
 * Initialize the context prior to a hash operation.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_init(void *context)
{
    int ret;

    ret = wc_InitSha256((wc_Sha256 *)context);
    if (ret != 0)
    {
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
th_sha256_process(void *context, const unsigned char *in, unsigned int size)
{
    int ret;

    ret = wc_Sha256Update((wc_Sha256 *)context, in, size);
    if (ret != 0)
    {
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
th_sha256_done(void *context, unsigned char *result)
{
    int ret;

    ret = wc_Sha256Final((wc_Sha256 *)context, result);
    if (ret != 0)
    {
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
th_sha256_destroy(void *context)
{
    if (context != NULL)
    {
        wc_Sha256Free((wc_Sha256 *)context);
        th_free(context);
        context = NULL;
    }
}
