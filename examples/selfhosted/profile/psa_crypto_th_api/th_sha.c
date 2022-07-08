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

/**
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#include "psa/crypto.h"

#include "ee_sha.h"

/**
 * Create the context passed between functions.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_create(void **context)
{
    psa_hash_operation_t *operation;
    operation = th_malloc(sizeof(psa_hash_operation_t));
    if (!operation)
    {
        th_printf("e-[malloc() fail in th_sha256_create]\r\n");
        return EE_STATUS_ERROR;
    }
    *context = (void *)operation;
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
    psa_hash_operation_t *operation = (psa_hash_operation_t *)context;
    *operation                      = psa_hash_operation_init();
    psa_hash_setup(operation, PSA_ALG_SHA_256);
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
    psa_hash_operation_t *operation = (psa_hash_operation_t *)context;
    psa_status_t          status    = psa_hash_update(operation, in, size);
    if (status)
        return EE_STATUS_ERROR;

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
    psa_hash_operation_t *operation = (psa_hash_operation_t *)context;
    size_t                length    = PSA_HASH_LENGTH(PSA_ALG_SHA_256);
    psa_status_t status = psa_hash_finish(operation, result, length, &length);
    if (status)
        return EE_STATUS_ERROR;

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
