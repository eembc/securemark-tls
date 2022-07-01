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
#include "mbedtls/ecdsa.h"

#include "ee_ecdsa.h"
#include "th_util.h"

typedef struct {
    mbedtls_ecp_group_id group;
    mbedtls_ecdsa_context ecdsa_ctx;
    mbedtls_ecp_keypair our_key;
} th_mbedtls_ecdsa_t;

/**
 * @brief Creates a context and generates a key pair.
 *
 * @param pp_context - A pointer to a context pointer to be created.
 * @param group - See the `ee_ecdh_group_t` enum
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_create(void **pp_context, ee_ecdh_group_t group)
{
    th_mbedtls_ecdsa_t     *p_ecdsa;
    mbedtls_ecp_group_id    group_id;
    int                     result;

    switch (group)
    {
        case EE_P256R1:
            group_id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case EE_P384:
            group_id = MBEDTLS_ECP_DP_SECP384R1;
            break;
        default:
            th_printf("e-[unsupported curve in th_ecdsa_create]\r\n");
            return EE_STATUS_ERROR;
    }

    p_ecdsa = (th_mbedtls_ecdsa_t *)th_malloc(sizeof(th_mbedtls_ecdsa_t));
    if (p_ecdsa == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdsa_create]\r\n");
        return EE_STATUS_ERROR;
    }

    // Generate keypair
    mbedtls_ecp_keypair_init(&p_ecdsa->our_key);
    result = mbedtls_ecp_gen_key(group_id, &p_ecdsa->our_key,
                                 mbedtls_fake_random, NULL);

    if (result != 0)
    {
        th_printf("e-[cannot create key in th_ecdsa_create]\r\n");
        mbedtls_ecp_keypair_free(&p_ecdsa->our_key);
        th_free(p_ecdsa);
        return EE_STATUS_ERROR;
    }

    // Create ECDSA context from keypair
    mbedtls_ecdsa_init(&p_ecdsa->ecdsa_ctx);
    result = mbedtls_ecdsa_from_keypair(&p_ecdsa->ecdsa_ctx, &p_ecdsa->our_key);
    if (result != 0)
    {
        th_printf("e-[cannot create key in th_ecdsa_create]\r\n");
        mbedtls_ecdsa_free(&p_ecdsa->ecdsa_ctx);
        mbedtls_ecp_keypair_free(&p_ecdsa->our_key);
        th_free(p_ecdsa);
        return EE_STATUS_ERROR;
    }

    p_ecdsa->group = group_id;

    *pp_context = (void *)p_ecdsa;
    return EE_STATUS_OK;
}

/**
 * @brief Deallocate/destroy the context
 *
 * @param p_context - The context from the `create` function
 */
void th_ecdsa_destroy(void *p_context)
{
    mbedtls_ecp_keypair_free(&((th_mbedtls_ecdsa_t *)p_context)->our_key);
    mbedtls_ecdsa_free(&((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx);
    th_free(p_context);
}

/**
 * @brief Return the public key generated during `th_ecdsa_create`.
 *
 * @param p_context - The context from the `create` function
 * @param p_out - Buffer to receive the public key
 * @param p_outlen - Number of bytes used in the buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_get_public_key(void *         p_context,
                                    uint8_t *      p_out,
                                    uint_fast32_t *p_outlen)
{
    mbedtls_ecp_keypair    *p_our_key = &((th_mbedtls_ecdsa_t *)p_context)->our_key;
    int                     ret;
    size_t                  olen;

    // Until MbedTLS exposes functions to handle public keys, we need to reach down
    ret = mbedtls_ecp_point_write_binary(&p_our_key->MBEDTLS_PRIVATE(grp), &p_our_key->MBEDTLS_PRIVATE(Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, p_out, *p_outlen);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_point_write_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    *p_outlen = olen;

    return EE_STATUS_OK;
}

/**
 * @brief Set the public key in the context in order to perform a verify.
 *
 * For EcDSA, the key shall be in SECP1 uncompressed format { 04 | X | Y }.
 *
 * @param p_context - The context from the `create` function
 * @param p_pub - The public key buffer
 * @param publen - Length of the public key buffer
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_set_public_key(void *        p_context,
                                    uint8_t *     p_pub,
                                    uint_fast32_t publen)
{
    mbedtls_ecdsa_context  *p_ecdsa = &((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx;
    mbedtls_ecp_group_id    group_id = ((th_mbedtls_ecdsa_t *)p_context)->group;
    int                     ret;
    mbedtls_ecp_keypair     their_key;

    mbedtls_ecp_keypair_init(&their_key);

    // Until MbedTLS exposes functions to handle public keys, we need to reach down
    ret = mbedtls_ecp_group_load(&their_key.MBEDTLS_PRIVATE(grp), group_id);
    if (ret != 0)
    {
        mbedtls_ecp_keypair_free(&their_key);
        th_printf("e-[mbedtls_ecp_group_load: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = mbedtls_ecp_point_read_binary(
        &their_key.MBEDTLS_PRIVATE(grp), &their_key.MBEDTLS_PRIVATE(Q),
        p_pub, publen);
    if (ret != 0)
    {
        mbedtls_ecp_keypair_free(&their_key);
        th_printf("e-[mbedtls_ecp_point_read_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    /*
    ret = mbedtls_ecp_check_pubkey(&their_key.MBEDTLS_PRIVATE(grp), &their_key.MBEDTLS_PRIVATE(Q));
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_check_pubkey: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    */

    ret = mbedtls_ecdsa_from_keypair(p_ecdsa, &their_key);
    mbedtls_ecp_keypair_free(&their_key);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecdh_get_params: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * @brief Sign a message (hash) with the private key.
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * `p_siglen` should point to the buffer size on input; on return it will
 * contain the length of the signature.
 *
 * @param p_context - The context from the `create` function
 * @param p_msg - The hashed buffer to sign
 * @param msglen - Length of the hashed buffer
 * @param p_sig - The output signature buffer (provided)
 * @param p_siglen - The number of bytes used in the output signature buffer.
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_ecdsa_sign(void *         p_context,
                          uint8_t *      p_msg,
                          uint_fast32_t  msglen,
                          uint8_t *      p_sig,
                          uint_fast32_t *p_siglen)
{
    mbedtls_ecdsa_context  *p_ecdsa = &((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx;
    mbedtls_ecp_group_id    group_id = ((th_mbedtls_ecdsa_t *)p_context)->group;
    mbedtls_md_type_t       md_type;
    int                     result;
    size_t                  olen;

    switch (group_id)
    {
        case MBEDTLS_ECP_DP_SECP256R1:
            md_type = MBEDTLS_MD_SHA256;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
            md_type = MBEDTLS_MD_SHA384;
            break;
        default:
            th_printf("e-[Unsupported curve in th_ecdsa_sign]\r\n");
            return EE_STATUS_ERROR;
    }

    result = mbedtls_ecdsa_write_signature(p_ecdsa, md_type,
                                           p_msg, msglen,
                                           p_sig, *p_siglen, &olen,
                                           mbedtls_fake_random, NULL);
    if (result != 0)
    {
        th_printf("e-[mbedtls_ecdsa_write_signature: -0x%04x]\r\n", -result);
        return EE_STATUS_ERROR;
    }

    *p_siglen = olen;
    return EE_STATUS_OK;
}

/**
 * @brief Verify a message (hash) with the public key.
 *
 * It will return EE_STATUS_OK on message verify, and EE_STATUS_ERROR if the
 * message does not verify, or if there is some other error (which shall
 * be reported with `th_printf("e-[....]r\n");`.
 *
 * @param p_context - The context from the `create` function
 * @param group - See the `ee_ecdh_group_t` enum
 * @param p_hash - The hashed buffer to verify
 * @param hlen - Length of the hashed buffer
 * @param p_sig - The input signature buffer
 * @param slen - Length of the input signature buffer
 * @return ee_status_t - see above.
 */
ee_status_t th_ecdsa_verify(void *        p_context,
                            uint8_t *     p_msg,
                            uint_fast32_t msglen,
                            uint8_t *     p_sig,
                            uint_fast32_t siglen)
{
    mbedtls_ecdsa_context  *p_ecdsa = &((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx;
    int                     result;

    result = mbedtls_ecdsa_read_signature(p_ecdsa,
                                          p_msg, msglen,
                                          p_sig, siglen);
    if (result != 0)
    {
        th_printf("e-[mbedtls_ecdsa_read_signature: -0x%04x]\r\n", -result);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}
