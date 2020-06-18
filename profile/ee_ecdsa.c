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
 * Perform an ECDSA sign a given number of times.
 *
 * HASH: SHA256 digest (32 bytes)
 * SIGNATURE: ASN.1 or raw R/S (32B each)
 * PRIVATE: 32B secret
 */
void
ee_ecdsa_sign(
    unsigned char *p_hash,      // input: sha256 digest
    unsigned int   hlen,        // input: length of digest in bytes
    unsigned char *p_sig,       // output: signature
    unsigned int  *p_slen,      // in/out: input=MAX slen, output=resultant
    unsigned char *p_private,   // input: private key (from host)
    unsigned int   plen,        // input: private key length in bytes
    unsigned int   iterations   // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (th_ecdsa_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-ecdsa_sign-[Failed to create context]\r\n");
        return;
    }

    if (th_ecdsa_init(p_context, EE_P256R1, p_private, plen) != EE_STATUS_OK)
    {
        th_printf("e-ecdsa_sign-[Failed to initialize]\r\n");
        return;
    }

    th_printf("m-ecdsa_sign-iterations-%d\r\n", iterations);
    th_printf("m-ecdsa_sign-start\r\n");
    th_timestamp();
    th_pre();
    while (iterations-- > 0)
    {
        if (th_ecdsa_sign(p_context, p_hash, hlen, p_sig, p_slen)
            != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-ecdsa_sign-[Failed to sign]\r\n");
            goto exit;
        }
    }
    th_post();
    th_timestamp();
    th_printf("m-ecdsa_sign-finish\r\n");
exit:
    th_ecdsa_destroy(p_context);
}

/**
 * Perform an ECDSA verify a given number of times.
 *
 * HASH: SHA256 digest (32 bytes)
 * SIGNATURE: ASN.1 or raw R/S (32B each)
 * PRIVATE: 32B secret
 */
void
ee_ecdsa_verify(
    unsigned char *p_hash,      // input: sha256 digest
    unsigned int   hlen,        // input: length of digest in bytes
    unsigned char *p_sig,       // input: signature
    unsigned int   slen,        // input: length of signature in bytes
    unsigned char *p_private,   // input: private key (from host)
    unsigned int   plen,        // input: private key length in bytes
    unsigned int   iterations   // input: # of test iterations
)
{
    void *p_context; // Generic context if needed by implementation

    if (th_ecdsa_create(&p_context) != EE_STATUS_OK)
    {
        th_printf("e-ecdsa_verify-[Failed to create context]\r\n");
        return;
    }

    if (th_ecdsa_init(p_context, EE_P256R1, p_private, plen) != EE_STATUS_OK)
    {
        th_printf("e-ecdsa_verify-[Failed to initialize]\r\n");
        return;
    }

    th_printf("m-ecdsa_verify-iterations-%d\r\n", iterations);
    th_printf("m-ecdsa_verify-start\r\n");
    th_timestamp();
    th_pre();
    while (iterations-- > 0)
    {
        if (th_ecdsa_verify(p_context, p_hash, hlen, p_sig, slen)
            != EE_STATUS_OK)
        {
            th_post();
            th_printf("e-ecdsa_verify-[Vailed to verify]\r\n");
            goto exit;
        }
    }
    th_post();
    th_timestamp();
    th_printf("m-ecdsa_verify-finish\r\n");
exit:
    th_ecdsa_destroy(p_context);
}
