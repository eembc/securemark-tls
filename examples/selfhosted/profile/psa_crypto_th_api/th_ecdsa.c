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

/**
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#include "psa/crypto.h"

#include "ee_ecdh.h"
#include "ee_ecdsa.h"

typedef struct {
    psa_key_id_t private_key;
    psa_key_id_t public_key;
} ecdsa_p256_context;

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_create(
    void **p_context // output: portable context
)
{
    *p_context = (ecdsa_p256_context *)th_malloc(sizeof(ecdsa_p256_context));
    if (*p_context == NULL) {
        th_printf("e-[malloc() fail in th_ecdsa_create\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

/**
 * Initialize to a group (must be in the EE_ enum) with a predefined
 * private key.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_init(
    void            *p_context, // input: portable context
    ecdh_group_t     group,     // input: see `ecdh_group_t` for options
    unsigned char   *p_private, // input: private key from host
    size_t           plen       // input: length of private key in bytes
)
{
    psa_status_t status;

    ecdsa_p256_context *p_ecdsa = (ecdsa_p256_context *)p_context;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t key_data[65];
    size_t key_size;

    if (group != EE_P256R1) {
        th_printf("e-[Invalid ECC curve in th_ecdsa_init]\r\n");
        return EE_STATUS_ERROR;
    }
    if (plen != 32) {
        th_printf("e-[Invalid key length in th_ecdsa_init]\r\n");
        return EE_STATUS_ERROR;
    }

    psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    status = psa_import_key(&attributes, p_private, plen, &p_ecdsa->private_key);
    if (status) return EE_STATUS_ERROR;

    status = psa_export_public_key(p_ecdsa->private_key, key_data, sizeof key_data, &key_size);
    if (status) return EE_STATUS_ERROR;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    status = psa_import_key(&attributes, key_data, key_size, &p_ecdsa->public_key);
    if (status) return EE_STATUS_ERROR;

    return EE_STATUS_OK;
}

/**
 * Create a signature using the specified hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_sign(
    void          *p_context,   // input: portable context
    unsigned char *p_hash,      // input: sha256 digest
    unsigned int   hlen,        // input: length of digest in bytes
    unsigned char *p_sig,       // output: signature
    unsigned int  *p_slen       // in/out: input=MAX slen, output=resultant
)
{
    ecdsa_p256_context *p_ecdsa = (ecdsa_p256_context *)p_context;
#if EE_CFG_SELFHOSTED == 1
    unsigned char raw_sig[64];
#endif

    if (hlen != 32) {
        th_printf("e-[Invalid hash length in th_ecdsa_sign]\r\n");
        return EE_STATUS_ERROR;
    }
#if EE_CFG_SELFHOSTED != 1
    if (*p_slen < 64) {
#else
    if (*p_slen < 72) {
#endif
        th_printf("e-[Invalid signature length in th_ecdsa_sign]\r\n");
        return EE_STATUS_ERROR;
    }

    psa_status_t status;

#if EE_CFG_SELFHOSTED != 1
    status = psa_sign_hash(
        p_ecdsa->private_key,
        PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
        p_hash, hlen,
        p_sig, *p_slen, p_slen);
    if (status) return EE_STATUS_ERROR;
#else
    size_t length;
    status = psa_sign_hash(
            p_ecdsa->private_key,
            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
            p_hash, hlen,
            raw_sig, sizeof raw_sig, &length);
    if (status) return EE_STATUS_ERROR;

    // ASN encoded signature
    p_sig[0] = 0x30;  // Sequence tag
    p_sig[1] = 70;    // length
    p_sig[2] = 0x02;  // Integer tag
    p_sig[3] = 33;    // length
    p_sig[4] = 0;     // leading 0 byte
    memcpy(&p_sig[5], &raw_sig[0], 32); // r
    p_sig[37] = 0x02; // Integer tag
    p_sig[38] = 33;   // length
    p_sig[39] = 0;    // leading 0 byte
    memcpy(&p_sig[40], &raw_sig[32], 32); // s
    *p_slen = 72;
#endif
    return EE_STATUS_OK;
}

/**
 * Create a signature using SHA256 hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_verify(
    void          *p_context,   // input: portable context
    unsigned char *p_hash,      // input: sha256 digest
    unsigned int   hlen,        // input: length of digest in bytes
    unsigned char *p_sig,       // output: signature
    unsigned int   slen         // input: length of signature in bytes
)
{
    ecdsa_p256_context *p_ecdsa = (ecdsa_p256_context *)p_context;
#if EE_CFG_SELFHOSTED == 1
    unsigned char raw_sig[64];
#endif

    if (hlen != 32) {
        th_printf("e-[Invalid hash length in th_ecdsa_verify]\r\n");
        return EE_STATUS_ERROR;
    }
#if EE_CFG_SELFHOSTED != 1
    if (slen != 64) {
#else
    if (slen != 72) {
#endif
        th_printf("e-[Invalid signature length in th_ecdsa_verify]\r\n");
        return EE_STATUS_ERROR;
    }

    psa_status_t status;

#if EE_CFG_SELFHOSTED != 1
    status = psa_verify_hash(
        p_ecdsa->public_key,
        PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
        p_hash, hlen,
        p_sig, slen);
#else
    // extract raw signature
    memcpy(&raw_sig[0], &p_sig[5], 32);   // r
    memcpy(&raw_sig[32], &p_sig[40], 32); // s

    status = psa_verify_hash(
            p_ecdsa->public_key,
            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
            p_hash, hlen,
            raw_sig, sizeof raw_sig);
#endif
    if (status != PSA_SUCCESS) {
        th_printf("e-[Failed to verify in th_ecdsa_verify]\r\n");
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdsa_destroy(
    void *p_context // portable context
)
{
    ecdsa_p256_context *p_ecdsa = (ecdsa_p256_context *)p_context;
    psa_destroy_key(p_ecdsa->private_key);
    psa_destroy_key(p_ecdsa->public_key);
    th_free(p_context);
}
