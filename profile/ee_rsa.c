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
ee_rsa_sign(
    rsa_id_t id,
    const uint8_t *p_pri,  // input: private key in ASN.1/DER PKCS1_v1.5
    uint_fast32_t  prilen, // input: key length in bytes
    const uint8_t *p_in,   // input: input data (max based on keysize)
    uint_fast32_t  ilen,   // input: input length in bytes
    uint8_t       *p_out,  // output: output bytes (CT/PT)
    uint_fast32_t *olen,   // inout: in: size of buffer, out: size used
    uint_fast32_t  iter    // input: # of test iterations
) {
    void *p_context;
    int text;

    switch (id)
    {
        case EE_RSA_2048: text = 2048; break;
        case EE_RSA_3072: text = 3072; break;
        case EE_RSA_4096: text = 4096; break;
    }
    
    if (th_rsa_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-rsa%d-[Failed to create context]\r\n", text);
        return;
    }
    th_printf("m-rsa%d-iter-%d\r\n", text, iter);
    th_printf("m-rsa%d-message-length-%d\r\n", text, ilen);
    if (th_rsa_init(p_context, EE_RSA_SIGN, id, p_pri, prilen) != EE_STATUS_OK)
    {
        th_printf("e-rsa%d-[Failed to initialize]\r\n", text);
        return;
    }
    th_timestamp();
    th_pre();
    if (func == EE_RSA_ENC)
    {
        while (iter-- > 0)
        {
            if (th_rsa_encrypt(p_context, p_in, ilen, p_out, olen) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa%d-[Failed to encrypt]\r\n", text);
                goto exit;
            }
        }
    }
    else
    {
        while (iter-- > 0)
        {
            if (th_rsa_decrypt(p_context, p_in, ilen, p_out, olen) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa%d-[Failed to decrypt]\r\n", text);
                goto exit;
            }
        }
    }
    th_post();
    th_timestamp();
exit:
    th_rsa_deinit(p_context);
    th_rsa_destroy(p_context);

}
#if 0
void
ee_rsa(rsa_id_t       id,     // input: Keysize ID RSA_(2048|3072|4096)
       rsa_function_t func,   // input: RSA_(ENC|DEC)
       const uint8_t *p_pri,  // input: private key in ASN.1/DER PKCS1_v1.5
       uint_fast32_t  keylen, // input: hey length in bytes
       const uint8_t *p_in,   // input: input data (max based on keysize)
       uint_fast32_t  ilen,   // input: input length in bytes
       uint8_t       *p_out,  // output: output bytes (CT/PT)
       uint_fast32_t  olen,   // input: in: size of buffer
       uint_fast32_t  iter    // input: # of test iterations
)
{
    void *p_context;
    int text;

    switch (id)
    {
        case EE_RSA2048: text = 2048; break;
        case EE_RSA3072: text = 3072; break;
        case EE_RSA4096: text = 4096; break;
    }
    
    if (th_rsa_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-rsa%d-[Failed to create context]\r\n", text);
        return;
    }
    th_printf("m-rsa%d-iter-%d\r\n", text, iter);
    th_printf("m-rsa%d-message-length-%d\r\n", text, ilen);
    if (th_rsa_init(p_context, id, p_pri, keylen) != EE_STATUS_OK)
    {
        th_printf("e-rsa%d-[Failed to initialize]\r\n", text);
        return;
    }
    th_timestamp();
    th_pre();
    if (func == EE_RSA_ENC)
    {
        while (iter-- > 0)
        {
            if (th_rsa_encrypt(p_context, p_in, ilen, p_out, olen) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa%d-[Failed to encrypt]\r\n", text);
                goto exit;
            }
        }
    }
    else
    {
        while (iter-- > 0)
        {
            if (th_rsa_decrypt(p_context, p_in, ilen, p_out, olen) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa%d-[Failed to decrypt]\r\n", text);
                goto exit;
            }
        }
    }
    th_post();
    th_timestamp();
exit:
    th_rsa_deinit(p_context);
    th_rsa_destroy(p_context);
}
#endif