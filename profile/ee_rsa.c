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

#include "ee_rsa.h"

void
ee_rsa(ee_rsa_id_t       id,
       ee_rsa_function_t func,
       const uint8_t *   p_key,
       unsigned int      keylen,
       uint8_t *         p_hash,
       unsigned int      hashlen,
       uint8_t *         p_sig,
       uint_fast32_t *   p_siglen,
       unsigned int      iter)
{
    void *p_context;

    if (th_rsa_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-rsa-[Failed to create context]\r\n");
        return;
    }

    th_printf("m-rsa-iter-%d\r\n", iter);
    th_printf("m-rsa-n-%d\r\n", hashlen);

    if (th_rsa_init(p_context, id, p_key, keylen) != EE_STATUS_OK)
    {
        th_printf("e-rsa-[Failed to initialize]\r\n");
        return;
    }

    th_printf("m-rsa-start\r\n");
    th_timestamp();
    th_pre();

    if (func == EE_RSA_SIGN)
    {
        while (iter-- > 0)
        {
            if (th_rsa_sign(p_context, p_hash, hashlen, p_sig, p_siglen)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa-[Failed to sign]\r\n");
                goto exit;
            }
        }
    }
    else
    {
        while (iter-- > 0)
        {
            if (th_rsa_verify(p_context, p_sig, *p_siglen, p_hash, hashlen)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa-[Failed to verify]\r\n");
                goto exit;
            }
        }
    }

    th_post();
    th_timestamp();
    th_printf("m-rsa-finish\r\n");

exit:
    th_rsa_destroy(p_context);
}
