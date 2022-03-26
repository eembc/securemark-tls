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

/**
 * @brief Perform an RSA operation. Currently, only sign and verify are
 * supported. It returns no value because the host application will
 * intepret the messages printed by `th_printf`.
 *
 * @param id Size of the modulus, an `rsa_id_t` enum
 * @param func One of the `rsa_function_t` enums
 * @param p_pri Private key buffer, as quintuple ASN.1/DER RFC 8017 Sec 3.2
 * @param prilen Private key buffer length
 * @param p_pub Public key buffer, as N/E ASN.1/DER RFC 8017 Sec 3.1.2
 * @param publen Public key buffer length
 * @param p_in Input octet buffer
 * @param ilen Input buffer length
 * @param p_out Output octet buffer
 * @param olen Output buffer length, may be inout, as operation can set it
 * @param iter Number of iterations
 */
void
ee_rsa(rsa_id_t       id,
       rsa_function_t func,
       const uint8_t *p_pri,
       unsigned int   prilen,
       const uint8_t *p_pub,
       unsigned int   publen,
       const uint8_t *p_in,
       unsigned int   ilen,
       uint8_t *      p_out,
       uint_fast32_t *olen,
       unsigned int   iter)
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
        default:
            th_printf("e-rsa-[Invalid modulus size]\r\n");
            return;
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
            if (th_rsa_verify(p_context, p_in, ilen, p_out, *olen)
                != EE_STATUS_OK)
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
    th_rsa_destroy(p_context);
}
