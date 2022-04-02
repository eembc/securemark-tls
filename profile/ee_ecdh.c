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

#include "ee_ecdh.h"

void
ee_ecdh(ee_ecdh_group_t group,
        uint8_t *       p_private,
        uint_fast32_t   prilen,
        uint8_t *       p_public,
        uint_fast32_t   publen,
        uint8_t *       p_secret,
        uint_fast32_t   seclen,
        uint_fast32_t   iter)
{
    void *p_context;

    if (th_ecdh_create(&p_context, group) != EE_STATUS_OK)
    {
        th_printf("e-ecdh-[Failed to create context]\r\n");
        return;
    }
    if (th_ecdh_init(p_context, group, p_private, prilen, p_public, publen)
        != EE_STATUS_OK)
    {
        th_printf("e-ecdh-[Failed to initialize]\r\n");
        goto exit;
    }
    th_printf("m-ecdh-iter-%d\r\n", iter);
    th_printf("m-ecdh-start\r\n");
    th_timestamp();
    th_pre();
    while (iter-- > 0)
    {
        if (th_ecdh_calc_secret(p_context, group, p_secret, seclen)
            != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-ecdh-[Failed to compute shared secret]\r\n");
            goto exit;
        }
    }
    th_post();
    th_timestamp();
    th_printf("m-ecdh-finish\r\n");
exit:
    th_ecdh_destroy(p_context);
}
