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

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "th_util.h"

#include "ee_ecdh.h"

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_create(void **p_context // output: portable context
)
{
    mbedtls_ecdh_context *p_ecdh;

    p_ecdh = (mbedtls_ecdh_context *)th_malloc(sizeof(mbedtls_ecdh_context));
    if (p_ecdh == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create]\r\n");
        return EE_STATUS_ERROR;
    }
    *p_context = (void *)p_ecdh;
    return EE_STATUS_OK;
}

/**
 * Load a 64-byte public key from a peer, big-endian; confim is on curve
 *
 * return EE_STATUS_OK on success.
 */
ee_status_t
load_public_peer_key(void *p_context, unsigned char *p_pub, size_t publen)
{
    mbedtls_ecdh_context *p_ecdh;
    mbedtls_ecp_point     Q;
    unsigned char         uncompressed_point_buffer[65];
    int                   ret;

    p_ecdh = (mbedtls_ecdh_context *)p_context;

    mbedtls_ecp_point_init(&Q);

    // First byte for mbedtls_ecp_point_read_binary must be 0x04
    uncompressed_point_buffer[0] = 0x04;
    th_memcpy(&(uncompressed_point_buffer[1]), p_pub, publen);

    ret = mbedtls_ecp_point_read_binary(
        &p_ecdh->grp, &Q, uncompressed_point_buffer, 65);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_point_read_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = mbedtls_ecp_check_pubkey(&p_ecdh->grp, &Q);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_check_pubkey: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = mbedtls_ecp_copy(&p_ecdh->Qp, &Q);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_copy: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Load private & populate ecdh->Q public point
 */
ee_status_t
load_private_key(void *p_context, unsigned char *p_private, size_t prilen)
{
    int                   ret;
    mbedtls_ecdh_context *p_ecdh;
    mbedtls_ecp_group *   p_grp;

    p_ecdh = (mbedtls_ecdh_context *)p_context;
    p_grp  = &p_ecdh->grp;

    ret = mbedtls_mpi_read_binary(&p_ecdh->d, p_private, prilen);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_mpi_read_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    // compute the public key from the provided secret
    mbedtls_ecp_point_init(&p_ecdh->Q);
    ret = mbedtls_ecp_mul(
        p_grp,
        &p_ecdh->Q,          // R <-- this value will be computed as P * m
        &p_ecdh->d,          // m
        &p_grp->G,           // P
        mbedtls_fake_random, // random function
        0);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_mul: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Initialize to a group (must be in the EE_ enum)
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_init(void *        p_context, // input: portable context
             ee_ecdh_group_t  group,     // input: see `ee_ecdh_group_t` for options
             uint8_t *     p_private, // input: private key, from host
             uint_fast32_t prilen,    // input: private key length in bytes
             uint8_t *     p_public,  // input: peer public key, from host
             uint_fast32_t publen     // input: peer public key length in bytes
)
{
    mbedtls_ecdh_context *p_ecdh;
    int                   ret;

    p_ecdh = (mbedtls_ecdh_context *)p_context;
    switch (group)
    {
        case EE_P256R1:
            mbedtls_ecdh_init(p_ecdh);
            ret = mbedtls_ecp_group_load(&p_ecdh->grp,
                                         MBEDTLS_ECP_DP_SECP256R1);
            if (ret)
            {
                th_printf("e-[mbedtls_ecp_group_load: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
            break;
        default:
            th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }
    ret = load_public_peer_key(p_context, p_public, publen);
    if (ret != EE_STATUS_OK)
    {
        th_printf("e-[load_public_peer_key: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = load_private_key(p_context, p_private, prilen);
    if (ret != EE_STATUS_OK)
    {
        th_printf("e-[load_private_key: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Perform ECDH mixing.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_calc_secret(
    void *        p_context, // input: portable context
    uint8_t *     p_secret,  // output: shared secret
    uint_fast32_t slen       // input: length of shared buffer in bytes
)
{
    mbedtls_ecdh_context *p_ecdh;
    size_t                olen;
    int                   ret;

    p_ecdh = (mbedtls_ecdh_context *)p_context;
    /**
     * For the MBEDTLS_ECP_DP_SECP256R1 the buffer must be equal to or larger
     * than 32 bytes.
     */
    // TODO: Magic number
    if (slen < 32u)
    {
        th_printf("e-[Secret buffer too small: %u < 32]\r\n", slen);
        return EE_STATUS_ERROR;
    }
    ret = mbedtls_ecdh_calc_secret(
        p_ecdh, &olen, p_secret, slen, mbedtls_fake_random, NULL);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecdh_calc_secret: 0x%04x]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    /**
     * Must be the same size as the curve size; for example, if the curve is
     * secp256r1, secret must be 32 bytes long.
     */
    // TODO: Magic number
    if (olen != 32u)
    {
        th_printf("e-[Output length isn 32B: %lu]\r\n", olen);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdh_destroy(void *p_context // input: portable context
)
{
    mbedtls_ecdh_free((mbedtls_ecdh_context *)p_context);
    th_free(p_context);
}
