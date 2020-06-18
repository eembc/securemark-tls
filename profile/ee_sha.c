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

#include "ee_sha.h"

/**
 * Runs a SHA-256 hash on an input message a given number of times.
 */
void
ee_sha256(
    const unsigned char *p_in,      // input: bytes to hash
    unsigned int         len,       // input: length of input in bytes
    unsigned char       *p_result,  // output: resulting digest
    unsigned int         iterations // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (th_sha256_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-sha256-[Failed to create context]\r\n");
        return;
    }

    th_printf("m-sha256-iterations-%d\r\n", iterations);
    th_printf("m-sha256-message-length-%d\r\n", len);
    th_printf("m-sha256-start\r\n");
    th_timestamp();
    th_pre();
    if (th_sha256_init(p_context) != EE_STATUS_OK)
    {
        th_post();
        th_printf("e-sha246-[Failed to initialize]\r\n");
        goto exit;
    }
    while (iterations-- > 0)
    {
        if (th_sha256_process(p_context, p_in, len) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha256-[Failed to process bytes]\r\n");
            goto exit;
        }
    }
    if (th_sha256_done(p_context, p_result) != EE_STATUS_OK)
    {
        th_post();
        th_printf("e-sha256-[Failed to complete]\r\n");
        goto exit;
    }
    th_post();
    th_timestamp();
    th_printf("m-sha256-finish\r\n");
exit:
    th_sha256_destroy(p_context);
}
