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

/**
 * Performs ECDH secret mixing a given number of times. The host software
 * provides the public and private keys.
 *
 * Peer public key is two 32-byte uncompressed points X & Y on the curve,
 * private key is 32-byte value used in G * m = R (the 'm' value).
 */
void ee_ecdh(ecdh_group_t group, // input: input: see `ecdh_group_t` for options
             uint8_t *    p_public, // input: peer public key, from host
             uint_fast32_t publen,    // input: peer public key length in bytes
             uint8_t *     p_private, // input: private key, from host
             uint_fast32_t prilen,    // input: private key length in bytes
             uint8_t *     p_secret,  // output: shared secret
             uint_fast32_t seclen, // input: size of buffer for secret, in bytes
             uint_fast32_t iterations // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

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

    th_printf("m-ecdh-iterations-%d\r\n", iterations);
    th_printf("m-ecdh-start\r\n");
    th_timestamp();
    th_pre();
    while (iterations-- > 0)
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
