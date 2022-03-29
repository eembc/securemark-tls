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

/**
 * Perform a ChaCha20/Poly1305 operation a given number of times.
 */
void
ee_chachapoly(chachapoly_func_t func,   // input: EE_CHACHAPOLY_(ENC|DEC)
              uint8_t *         p_key,  // input: key
              const uint8_t *   p_add,  // input: additional authentication data
              uint_fast32_t     addlen, // input: length of AAD in bytes
              uint8_t *         p_iv,   // input: initialization vector
              uint8_t *     p_in,  // input: pointer to source input (pt or ct)
              uint_fast32_t len,   // input: length of input in bytes
              uint8_t *     p_tag, // inout: output in encrypt, input on decrypt
              uint8_t *     p_out, // output: pointer to output buffer
              uint_fast32_t iterations // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (th_chachapoly_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-chachapoly-[Failed to create context]\r\n");
        return;
    }

    th_printf("m-chachapoly-iterations-%d\r\n", iterations);
    th_printf("m-chachapoly-message-length-%d\r\n", len);

    if (func == EE_CHACHAPOLY_ENC)
    {
        th_printf("m-chachapoly-encrypt-start\r\n");
        th_timestamp();
        th_pre();
        while (iterations-- > 0)
        {
            if (th_chachapoly_init(
                    p_context, p_key, EE_CHACHAPOLY_KEYSIZE, EE_CHACHAPOLY_ENC)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-chachapoly-[Failed to initialize]\r\n");
                goto exit;
            }
            if (th_chachapoly_encrypt(p_context,
                                      p_add,
                                      addlen,
                                      p_in,
                                      len,
                                      p_out,
                                      p_tag,
                                      EE_CHACHAPOLY_TAGSIZE,
                                      p_iv,
                                      EE_CHACHAPOLY_IVSIZE)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-chachapoly-[Failed to encrypt]\r\n");
                goto exit;
            }
            th_chachapoly_deinit(p_context, EE_CHACHAPOLY_ENC);
        }
        th_post();
        th_timestamp();
        th_printf("m-chachapoly-encrypt-finish\r\n");
    }
    else
    {
        th_printf("m-chachapoly-decrypt-start\r\n");
        th_timestamp();
        th_pre();
        while (iterations-- > 0)
        {
            if (th_chachapoly_init(
                    p_context, p_key, EE_CHACHAPOLY_KEYSIZE, EE_CHACHAPOLY_DEC)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-chachapoly-[Failed to initialize]\r\n");
                goto exit;
            }
            if (th_chachapoly_decrypt(p_context,
                                      p_add,
                                      addlen,
                                      p_in,
                                      len,
                                      p_out,
                                      p_tag,
                                      EE_CHACHAPOLY_TAGSIZE,
                                      p_iv,
                                      EE_CHACHAPOLY_IVSIZE)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-chachapoly-[Failed to decrypt]\r\n");
                goto exit;
            }
            th_chachapoly_deinit(p_context, EE_CHACHAPOLY_DEC);
        }
        th_post();
        th_timestamp();
        th_printf("m-chachapoly-decrypt-finish\r\n");
    }
exit:
    th_chachapoly_destroy(p_context);
}
