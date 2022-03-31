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

#include "ee_sha.h"

/**
 * Create the context passed between functions.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_create(void **context)
{
    mbedtls_sha256_context *sha256;
    sha256 = th_malloc(sizeof(mbedtls_sha256_context));
    if (!sha256)
    {
        th_printf("e-[th_sha256_create malloc fail]\r\n");
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
    mbedtls_sha256_init((mbedtls_sha256_context *)context);
    mbedtls_sha256_starts((mbedtls_sha256_context *)context,
                          0 /* 0 for SHA-256 */);
    return EE_STATUS_OK;
}

/**
 * Process the hash
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_process(void *         p_context, // input: portable context
                  const uint8_t *p_in,      // input: data to hash
                  uint_fast32_t  len        // input: length of data in bytes
)
{
    mbedtls_sha256_update((mbedtls_sha256_context *)p_context, p_in, len);
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
    mbedtls_sha256_finish((mbedtls_sha256_context *)context, result);
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
        th_free(context);
        context = NULL;
    }
}
