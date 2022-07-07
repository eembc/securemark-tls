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

#include "th_lib.h"
#include "th_util.h"
#include "psa/crypto.h"

#ifdef MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length )
{
    memset(output, 0xAA, output_size);
    *output_length = output_size;
    return PSA_SUCCESS;
}
#endif

// NOTE: Feel free to replace the static variable with any allocation scheme
#define BUFFER_SIZE (1024)
static unsigned char g_generic_buffer[BUFFER_SIZE];

/**
 * The pre/post hooks are called immediately before the th_timestamp() and
 * immediately after. These hooks give the developer a chance to turn off
 * certain features (like UART) to save power during the loop.
 */

void th_pre(void) {
}

void th_post(void) {
}

/**
 * PORTME: If you opt to not use the heap, set up the buffer here.
 */
void
th_buffer_initialize(void) {
    psa_status_t status = psa_crypto_init();
    if (status) printf("psa_crypto_init failed with status %i.\r\n", status);
}

/**
 * PORTME: Return the address of a region of memory that the the framework
 * can use as a generic place to store data. Should be 1K at least, but profiles
 * will always check to make sure it is suitably sized.
 */
unsigned char *
th_buffer_address(void) {
    return g_generic_buffer;
}

/**
 * PORTME: If you opt to do a malloc, be sure to return the size here
 */
size_t
th_buffer_size(void) {
    return BUFFER_SIZE;
}
