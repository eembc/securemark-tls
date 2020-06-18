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

#include "ee_aes.h"

/**
 * Perform an AES128 ECB mode operation a given number of times.
 */
void
ee_aes128_ecb(
    unsigned char  *p_key,      // input: key
    unsigned char  *p_in,       // input: pointer to source input (pt or ct)
    unsigned int    len,        // input: length of input in bytes
    unsigned char  *p_out,      // output: pointer to output buffer
    aes_function_t  func,       // input: func (AES_ENC|AES_DEC)
    unsigned int    iterations  // input: # of test iterations
)
{
    void         *p_context;    // Generic context if needed by implementation
    unsigned int  numblocks;    // This wrapper uses fixed-size blocks
    unsigned int  i;            // iteration index
    unsigned int  j;            // iteration index

    if (len < AES_BLOCKLEN)
    {
        th_printf("e-aes128_ecb-[Input must be >=%u bytes]\r\n", AES_BLOCKLEN);
        return;
    }
    
    numblocks = len / AES_BLOCKLEN;
    if (len % AES_BLOCKLEN != 0) // Note: No padding
    {
        th_printf("e-aes128_ecb-[Input must be modulo %d]\r\n", AES_BLOCKLEN);
        return;
    }

    if (th_aes128_create(&p_context, AES_ECB) != EE_STATUS_OK)
    {
        th_printf("e-aes128_ecb-[Failed to create context]\r\n");
        return;
    }

    th_printf("m-aes128_ecb-iterations-%d\r\n", iterations);
    th_printf("m-aes128_ecb-message-length-%d\r\n", len);

    if (func == AES_ENC)
    {
        th_printf("m-aes128_ecb-encrypt-start\r\n");
        th_timestamp();
        th_pre();
        while (iterations-- > 0)
        {
            if (th_aes128_init(p_context, p_key, AES_KEYSIZE, AES_ROUNDS, func,
                               AES_ECB) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes128_ecb-[Failed to initialize]\r\n");
                goto exit;
            }
            for (i = 0, j = 0; j < numblocks; ++j)
            {
                i = j * AES_BLOCKLEN;
                if (th_aes128_ecb_encrypt(p_context, &(p_in[i]), &(p_out[i]))
                    != EE_STATUS_OK)
                {
                    th_post();
                    th_printf("e-aes128_ecb-[Failed to ecnrypt]\r\n");
                    goto exit;
                }
            }
        }
        th_post();
        th_timestamp();
        th_printf("m-aes128_ecb-encrypt-finish\r\n");
    }
    else
    {
        th_printf("m-aes128_ecb-decrypt-start\r\n");
        th_timestamp();
        th_pre();
        while (iterations-- > 0)
        {
            if (th_aes128_init(p_context, p_key, AES_KEYSIZE, AES_ROUNDS, func,
                               AES_ECB) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes128_ecb-[Failed to initialize]\r\n");
                goto exit;
            }
            for (i = 0, j = 0; j < numblocks; ++j)
            {
                i = j * AES_BLOCKLEN;
                if (th_aes128_ecb_decrypt(p_context, &(p_in[i]), &(p_out[i]))
                    != EE_STATUS_OK)
                {
                    th_post();
                    th_printf("e-aes128_ecb-[Failed to decrypt]\r\n");
                    goto exit;
                }
            }
        }
        th_post();
        th_timestamp();
        th_printf("m-aes128_ecb-decrypt-finish\r\n");
    }
exit:
    th_aes128_destroy(p_context, AES_ECB);
}

/**
 * Perform an AES128 CCM mode operation a given number of times.
 */
void
ee_aes128_ccm(
    unsigned char  *p_key,      // input: key
    unsigned char  *p_iv,       // input: initialization vector
    unsigned char  *p_in,       // input: pointer to source input (pt or ct)
    unsigned int    len,        // input: length of input in bytes
    unsigned char  *p_tag,      // inout: output in encrypt, input on decrypt
    unsigned char  *p_out,      // output: pointer to output buffer
    aes_function_t  func,       // input: func (AES_ENC|AES_DEC)
    unsigned int    iterations  // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (len < AES_BLOCKLEN)
    {
        th_printf("e-aes128_ccm-[Input must be >=%u bytes]\r\n", AES_BLOCKLEN);
        return;
    }

    if (th_aes128_create(&p_context, AES_CCM) != EE_STATUS_OK)
    {
        th_printf("e-aes128_ccm-[Failed to create context]\r\n");
        return;
    }

    th_printf("m-aes128_ccm-iterations-%d\r\n", iterations);
    th_printf("m-aes128_ccm-message-length-%d\r\n", len);

    if (func == AES_ENC)
    {
        th_printf("m-aes128_ccm-encrypt-start\r\n");
        th_timestamp();
        th_pre();
        while (iterations-- > 0)
        {
            if (th_aes128_init(p_context, p_key, AES_KEYSIZE, AES_ROUNDS, func,
                               AES_CCM) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes128_ccm-[Failed to initialize]\r\n");
                goto exit;
            }
            if (th_aes128_ccm_encrypt(p_context, p_in, len, p_out, p_tag, 
                                      AES_KEYSIZE, p_iv, AES_IVSIZE)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes128_ccm-[Failed to encrypt]\r\n");
                goto exit;
            }
            th_aes128_deinit(p_context, AES_CCM);
        }
        th_post();
        th_timestamp();
        th_printf("m-aes128_ccm-encrypt-finish\r\n");
    }
    else
    {
        th_printf("m-aes128_ccm-decrypt-start\r\n");
        th_timestamp();
        th_pre();
        while (iterations-- > 0)
        {
            if (th_aes128_init(p_context, p_key, AES_KEYSIZE, AES_ROUNDS, func,
                               AES_CCM) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes128_ccm-[Failed to initialize]\r\n");
                goto exit;
            }
            if (th_aes128_ccm_decrypt(p_context, p_in, len, p_out, p_tag,
                                      AES_KEYSIZE, p_iv, AES_IVSIZE)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes128_ccm-[Failed to decrypt]\r\n");
                goto exit;
            }
            th_aes128_deinit(p_context, AES_CCM);
        }
        th_post();
        th_timestamp();
        th_printf("m-aes128_ccm-decrypt-finish\r\n");
    }
exit:
    th_aes128_destroy(p_context, AES_CCM);
}
