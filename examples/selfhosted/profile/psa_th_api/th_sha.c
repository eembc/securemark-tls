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
#include "psa/crypto.h"

#include "ee_sha.h"

/**
 * Create the context passed between functions.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_create(
	void **context
) {
    psa_hash_operation_t *sha256;
    sha256 = th_malloc(sizeof(psa_hash_operation_t));
    memset(sha256, 0, sizeof(psa_hash_operation_t));

	if (! sha256) {
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
th_sha256_init(
	void *context
) {
    psa_crypto_init( );

    psa_hash_setup( (psa_hash_operation_t *) context, PSA_ALG_SHA_256 );

	return EE_STATUS_OK;
}

/**
 * Process the hash
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_process(
	void          *context,
	const uint8_t *in,
	uint_fast32_t  size
) {
    psa_hash_update( (psa_hash_operation_t *) context, in, size );

	return EE_STATUS_OK;
}

/**
 * Return the digest.
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
th_sha256_done(
	void *context,
	unsigned char *result
) {

    size_t hash_size;

    psa_hash_finish( (psa_hash_operation_t *) context, result, 32, &hash_size );

	return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 *
 * return EE_STATUS_OK on success.
 */
void
th_sha256_destroy(
	void *context
) {
	if (context != NULL) {
		th_free(context);
		context = NULL;
	}
}
