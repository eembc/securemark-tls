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

#include "ee_ecdsa.h"

/**
 * @brief Performs an ECDSA sign or verify operation some number of iterations.
 *
 * @param group The ECC curve to use (non-Edwards)
 * @param func The operation enum to perform
 * @param p_msg Pointer to the message octet buffer to sign
 * @param mlen Length of the message buffer
 * @param p_sig Pointer to a buffer for the signature
 * @param p_slen As input, size of the buffer; as output, octets used
 * @param p_private The private key for the context (public will be generated)
 * @param plen Length of private key
 * @param iter Number of iterations
 */
void
ee_ecdsa(ee_ecdh_group_t     group,
         ee_ecdsa_func_t func,
         uint8_t *        p_msg,
         uint_fast32_t    mlen,
         uint8_t *        p_sig,
         uint_fast32_t *  p_slen,
         uint8_t *        p_private,
         uint_fast32_t    plen,
         uint_fast32_t    iter)
{
    void *p_context; // Generic context if needed by implementation

    if (th_ecdsa_create(&p_context, group) != EE_STATUS_OK)
    {
        th_printf("e-ecdsa-[Failed to create context]\r\n");
        return;
    }

    if (th_ecdsa_init(p_context, group, p_private, plen) != EE_STATUS_OK)
    {
        th_printf("e-ecdsa-[Failed to initialize]\r\n");
        return;
    }

    th_printf("m-ecdsa-start\r\n");
    th_timestamp();
    th_pre();
    if (func == EE_ECDSA_SIGN)
    {
        while (iter-- > 0)
        {
            if (th_ecdsa_sign(p_context, group, p_msg, mlen, p_sig, p_slen)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-ecdsa-[Failed to sign]\r\n");
                goto exit;
            }
        }
    }
    else
    {
        while (iter-- > 0)
        {
            if (th_ecdsa_verify(p_context, group, p_msg, mlen, p_sig, *p_slen)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-ecdsa-[Failed to verify]\r\n");
                goto exit;
            }
        }
    }
    th_post();
    th_timestamp();
    th_printf("m-ecdsa-finish\r\n");
exit:
    th_ecdsa_destroy(p_context, group);
}
