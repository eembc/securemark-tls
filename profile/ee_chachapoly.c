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

#include "ee_main.h"
#include "ee_chachapoly.h"

uint32_t
ee_chachapoly(ee_chachapoly_func_t func,
              uint8_t *            p_key,
              uint8_t *            p_iv,
              uint32_t count,
              void * p_message_list,
              uint32_t iter)
{
    void *   p_context;
    uint8_t *   p_in;
    uint8_t *   p_out;
    uint8_t *   p_tag;
    uint32_t *  p32;
    uint8_t *   p8;
    uint32_t len;
    uint32_t t0 = 0;
    uint32_t t1 = 0;
    uint32_t x;

    if (th_chachapoly_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-chachapoly-[Failed to create context]\r\n");
        return 0;
    }
    th_printf("m-chachapoly-iter[%d]\r\n", iter);
    th_printf("m-chachapoly-count[%d]\r\n", count);
    if (func == EE_CHACHAPOLY_ENC)
    {
        th_printf("m-chachapoly-encrypt-start\r\n");
        t0 = th_timestamp();
        th_pre();
        while (iter-- > 0)
        {
            if (th_chachapoly_init(p_context, p_key, EE_CHACHAPOLY_KEYLEN)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-chachapoly-[Failed to initialize]\r\n");
                goto exit;
            }
            /* Work through the list of messages for this context */
            p32 = (uint32_t *)p_message_list;
            /* Perform multiple en/decrypts in the same context */
            for (x = 0; x < count; ++x)
            {
                /* Set up the data pointers */
                len  = *p32++;
                p8   = (uint8_t *)p32;
                p_in = p8;
                p8 += len;
                p_out = p8;
                p8 += len;
                p_tag = p8;
                p8 += EE_CHACHAPOLY_TAGLEN;
                p32 = (uint32_t *)p8;
                if (th_chachapoly_encrypt(p_context,
                                        p_in,
                                        len,
                                        p_out,
                                        p_tag,
                                        EE_CHACHAPOLY_TAGLEN,
                                        p_iv,
                                        EE_CHACHAPOLY_IVLEN)
                    != EE_STATUS_OK)
                {
                    th_post();
                    th_printf("e-chachapoly-[Failed to encrypt]\r\n");
                    goto exit;
                }
            }
            th_chachapoly_deinit(p_context);
        }
        th_post();
        t1 = th_timestamp();
        th_printf("m-chachapoly-encrypt-finish\r\n");
    }
    else
    {
        th_printf("m-chachapoly-decrypt-start\r\n");
        t0 = th_timestamp();
        th_pre();
        while (iter-- > 0)
        {
            if (th_chachapoly_init(p_context, p_key, EE_CHACHAPOLY_KEYLEN)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-chachapoly-[Failed to initialize]\r\n");
                goto exit;
            }
            /* Work through the list of messages for this context */
            p32 = (uint32_t *)p_message_list;
            /* Perform multiple en/decrypts in the same context */
            for (x = 0; x < count; ++x)
            {
                /* Set up the data pointers */
                len  = *p32++;
                p8   = (uint8_t *)p32;
                p_in = p8;
                p8 += len;
                p_out = p8;
                p8 += len;
                p_tag = p8;
                p8 += EE_CHACHAPOLY_TAGLEN;
                p32 = (uint32_t *)p8;
                if (th_chachapoly_decrypt(p_context,
                                        p_in,
                                        len,
                                        p_out,
                                        p_tag,
                                        EE_CHACHAPOLY_TAGLEN,
                                        p_iv,
                                        EE_CHACHAPOLY_IVLEN)
                    != EE_STATUS_OK)
                {
                    th_post();
                    th_printf("e-chachapoly-[Failed to decrypt]\r\n");
                    goto exit;
                }
            }
            th_chachapoly_deinit(p_context);
        }
        th_post();
        t1 = th_timestamp();
        th_printf("m-chachapoly-decrypt-finish\r\n");
    }
exit:
    th_chachapoly_destroy(p_context);
    return t1 - t0;
}
