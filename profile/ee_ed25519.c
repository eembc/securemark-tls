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

#include "ee_ed25519.h"

/*
TODO: We need to specify if there are constraints on the digest or signature
 * HASH: SHA256 digest (32 bytes)
 * SIGNATURE: ASN.1 or raw R/S (32B each)
 *
 * PRIVATE: 32B secret
*/

/**
 * Perform an ECDSA sign a given number of times.
 */
void
ee_ed25519_sign(
    uint8_t *      p_hash,    // input: digest
    uint_fast32_t  hlen,      // input: length of digest in bytes
    uint8_t *      p_sig,     // output: signature
    uint_fast32_t *p_slen,    // in/out: input=MAX slen, output=resultant
    uint8_t *      p_private, // input: private key (from host)
    uint_fast32_t  plen,      // input: private key length in bytes
    uint_fast32_t  iterations // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (th_ed25519_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-ed25519_sign-[Failed to create context]\r\n");
        return;
    }

    if (th_ed25519_init(p_context, p_private, plen) != EE_STATUS_OK)
    {
        th_printf("e-ed25519_sign-[Failed to initialize]\r\n");
        return;
    }

    th_printf("m-ed25519_sign-iterations-%d\r\n", iterations);
    th_printf("m-ed25519_sign-start\r\n");
    th_timestamp();
    th_pre();
    while (iterations-- > 0)
    {
        if (th_ed25519_sign(p_context, p_hash, hlen, p_sig, p_slen)
            != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-ed25519_sign-[Failed to sign]\r\n");
            goto exit;
        }
    }
    th_post();
    th_timestamp();
    th_printf("m-ed25519_sign-finish\r\n");
exit:
    th_ed25519_destroy(p_context);
}

/**
 * Perform an ECDSA verify a given number of times.
 */
void
ee_ed25519_verify(uint8_t *     p_hash, // input: digest
                  uint_fast32_t hlen,   // input: length of digest in bytes
                  uint8_t *     p_sig,  // input: signature
                  uint_fast32_t slen,   // input: length of signature in bytes
                  uint8_t *     p_private, // input: private key (from host)
                  uint_fast32_t plen,      // input: private key length in bytes
                  uint_fast32_t iterations // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (th_ed25519_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-ed25519_verify-[Failed to create context]\r\n");
        return;
    }

    if (th_ed25519_init(p_context, p_private, plen) != EE_STATUS_OK)
    {
        th_printf("e-ed25519_verify-[Failed to initialize]\r\n");
        return;
    }

    th_printf("m-ed25519_verify-iterations-%d\r\n", iterations);
    th_printf("m-ed25519_verify-start\r\n");
    th_timestamp();
    th_pre();
    while (iterations-- > 0)
    {
        if (th_ed25519_verify(p_context, p_hash, hlen, p_sig, slen)
            != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-ed25519_verify-[Vailed to verify]\r\n");
            goto exit;
        }
    }
    th_post();
    th_timestamp();
    th_printf("m-ed25519_verify-finish\r\n");
exit:
    th_ed25519_destroy(p_context);
}
