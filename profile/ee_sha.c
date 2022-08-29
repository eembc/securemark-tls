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
ee_sha(ee_sha_size_t size, uint32_t count, void *p_message_list, uint32_t iter)
{
    void *    p_context; /* The generic context */
    uint32_t *p32;       /* Helper construction pointer */
    uint8_t * p8;        /* Helper construction pointer */
    uint32_t  length;    /* Length of the input message */
    uint32_t  t0 = 0;    /* Start time */
    uint32_t  t1 = 0;    /* Stop time */
    uint32_t  i;         /* Generic loop index */

    if (th_sha_create(&p_context, size) != EE_STATUS_OK)
    {
        th_printf("e-sha%d-[Failed to create context]\r\n", size);
        return 0;
    }
    th_printf("m-sha%d-iter[%d]\r\n", size, iter);
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
        /* Work through the list of messages for this context */
        p32 = (uint32_t *)p_message_list;
        for (i = 0; i < count; ++i)
        {
            length = *p32++;
            p8     = (uint8_t *)p32;
            if (th_sha_process(p_context, p8, length) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-sha%d-[Failed to process bytes]\r\n", size);
                goto exit;
            }
            p8 += length;
            p32 = (uint32_t *)p8;
        }
        /* p8 now points to the end of the message list, and is the digest */
        if (th_sha_done(p_context, p8) != EE_STATUS_OK)
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
