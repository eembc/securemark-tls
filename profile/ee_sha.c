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
ee_sha(ee_sha_size_t     size,      // input: SHA algorithm size
       const uint8_t *p_in,      // input: bytes to hash
       uint_fast32_t  len,       // input: length of input in bytes
       uint8_t *      p_result,  // output: resulting digest
       uint_fast32_t  iterations // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (th_sha_create(&p_context, size) != EE_STATUS_OK)
    {
        th_printf("e-sha%d-[Failed to create context]\r\n", size);
        return;
    }
    th_printf("m-sha%d-iterations-%d\r\n", size, iterations);
    th_printf("m-sha%d-message-length-%d\r\n", size, len);
    th_printf("m-sha%d-start\r\n", size);
    th_timestamp();
    th_pre();
    if (th_sha_init(p_context, size) != EE_STATUS_OK)
    {
        th_post();
        th_printf("e-sha%d-[Failed to initialize]\r\n", size);
        goto exit;
    }
    while (iterations-- > 0)
    {
        if (th_sha_process(p_context, size, p_in, len) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d-[Failed to process bytes]\r\n", size);
            goto exit;
        }
        // 2022-03-09: Vote to move `done` into the timing loop. See minutes.
        if (th_sha_done(p_context, size, p_result) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d-[Failed to complete]\r\n", size);
            goto exit;
        }
    }
    th_post();
    th_timestamp();
    th_printf("m-sha%d-finish\r\n", size);
exit:
    th_sha_destroy(p_context, size);
}
