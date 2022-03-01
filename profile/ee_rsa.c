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
ee_rsa(rsa_id_t       id,     // input: EE_RSA_{2048,3072,4096}
       rsa_function_t func,   // input: EE_RSA_SIGN/EE_RSA_VERIFY
       const uint8_t *p_pri,  // input: private key in ASN.1/DER PKCS1_v1.5
       unsigned int   prilen, // input: key length in bytes
       const uint8_t *p_pub,  // input: public key in ASN.1/DER PKCS1_v1.5
       unsigned int   publen, // input: key length in bytes
       const uint8_t *p_in,   // input: input data (max based on keysize)
       unsigned int   ilen,   // input: input length in bytes
       uint8_t *      p_out,  // output: output bytes
       unsigned int * olen,   // inout: in: size of buffer, out: size used
       unsigned int   iter    // input: # of test iterations
)
{
    void *p_context;
    int   text;

    switch (id)
    {
        case EE_RSA_2048:
            text = 2048;
            break;
        case EE_RSA_3072:
            text = 3072;
            break;
        case EE_RSA_4096:
            text = 4096;
            break;
    }

    if (th_rsa_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-rsa%d-[Failed to create context]\r\n", text);
        return;
    }

    th_printf("m-rsa%d-iter-%d\r\n", text, iter);
    th_printf("m-rsa%d-message-length-%d\r\n", text, ilen);
    
    if (th_rsa_init(p_context, id, p_pri, prilen, p_pub, publen)
        != EE_STATUS_OK)
    {
        th_printf("e-rsa%d-[Failed to initialize]\r\n", text);
        return;
    }
    
    th_timestamp();
    th_pre();
    
    if (func == EE_RSA_SIGN)
    {
        while (iter-- > 0)
        {
            if (th_rsa_sign(p_context, p_in, ilen, p_out, olen) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa%d-[Failed to sign]\r\n", text);
                goto exit;
            }
        }
    }
    else
    {
        while (iter-- > 0)
        {
            if (th_rsa_verify(p_context, p_out, *olen) != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-rsa%d-[Failed to verify]\r\n", text);
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
