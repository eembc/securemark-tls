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

void
ee_sha(ee_sha_size_t  size,
       const uint8_t *p_in,
       uint_fast32_t  len,
       uint8_t *      p_out,
       uint_fast32_t  iter)
{
    void *p_context;

    if (th_sha_create(&p_context, size) != EE_STATUS_OK)
    {
        th_printf("e-sha%d-[Failed to create context]\r\n", size);
        return;
    }
    th_printf("m-sha%d-iter-%d\r\n", size, iter);
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
    while (iter-- > 0)
    {
        if (th_sha_process(p_context, size, p_in, len) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d-[Failed to process bytes]\r\n", size);
            goto exit;
        }

        if (th_sha_done(p_context, size, p_out) != EE_STATUS_OK)
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
