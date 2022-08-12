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

uint32_t
ee_sha(ee_sha_size_t  size,
       const uint8_t *p_in,
       uint32_t  len,
       uint8_t *      p_out,
       uint32_t  iter)
{
    void *   p_context;
    uint32_t t0 = 0;
    uint32_t t1 = 0;

    if (th_sha_create(&p_context, size) != EE_STATUS_OK)
    {
        th_printf("e-sha%d-[Failed to create context]\r\n", size);
        return 0;
    }
    th_printf("m-sha%d-iter[%d]\r\n", size, iter);
    th_printf("m-sha%d-length[%d]\r\n", size, len);
    th_printf("m-sha%d-start\r\n", size);
    t0 = th_timestamp();
    th_pre();
    while (iter-- > 0)
    {
        if (th_sha_init(p_context) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d-[Failed to initialize]\r\n", size);
            goto exit;
        }
        if (th_sha_process(p_context, p_in, len) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d-[Failed to process bytes]\r\n", size);
            goto exit;
        }
        /* Version 2.x moved this into the timing loop. */
        if (th_sha_done(p_context, p_out) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d-[Failed to complete]\r\n", size);
            goto exit;
        }
    }
    th_post();
    t1 = th_timestamp();
    th_printf("m-sha%d-finish\r\n", size);
exit:
    th_sha_destroy(p_context);
    return t1 - t0;
}

uint32_t
ee_sha_multi(ee_sha_size_t  size,
        uint8_t      *pp_in[],
        uint32_t  p_len[],
         uint8_t       *pp_out[],
       uint32_t  count,
       uint32_t  iter)
{
    void *   p_context;
    uint32_t i; /* index in to in/len/out arrays */
    uint32_t t0 = 0;
    uint32_t t1 = 0;

    if (th_sha_create(&p_context, size) != EE_STATUS_OK)
    {
        th_printf("e-sha%d_multi-[Failed to create context]\r\n", size);
        return 0;
    }
    th_printf("m-sha%d_multi-iter[%d]\r\n", size, iter);
    th_printf("m-sha%d_multi-count[%d]\r\n", size, count);
    th_printf("m-sha%d_multi-start\r\n", size);
    t0 = th_timestamp();
    th_pre();
    while (iter-- > 0)
    {
        if (th_sha_init(p_context) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d_multi-[Failed to initialize]\r\n", size);
            goto exit;
        }
        for (i = 0; i < count; ++i)
        {
            if (th_sha_process(p_context, pp_in[i], p_len[i]) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-sha%d_multi-[Failed to process bytes]\r\n", size);
                goto exit;
            }
        }
        /* Version 2.x moved this into the timing loop. */
        if (th_sha_done(p_context, pp_out[i]) != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-sha%d_multi-[Failed to complete]\r\n", size);
            goto exit;
        }
    }
    th_post();
    t1 = th_timestamp();
    th_printf("m-sha%d_multi-finish\r\n", size);
exit:
    th_sha_destroy(p_context);
    return t1 - t0;
}
