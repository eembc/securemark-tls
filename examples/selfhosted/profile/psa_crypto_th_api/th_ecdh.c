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

typedef struct
{
    psa_key_id_t  private_key;
    unsigned char public_key[65];
} ecdh_p256_context;

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_create(void **p_context // output: portable context
)
{
    *p_context = (ecdh_p256_context *)th_malloc(sizeof(ecdh_p256_context));
    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
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
th_ecdh_init(void *         p_context, // input: portable context
             ecdh_group_t   group,     // input: see `ecdh_group_t` for options
             unsigned char *p_private, // input: private key, from host
             unsigned int   prilen,    // input: private key length in bytes
             unsigned char *p_public,  // input: peer public key, from host
             unsigned int   publen     // input: peer public key length in bytes
)
{
    ecdh_p256_context *p_ecdh = (ecdh_p256_context *)p_context;

    if (group != EE_P256R1)
    {
        th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
        return EE_STATUS_ERROR;
    }
    if (prilen != 32)
    {
        th_printf("e-[Invalid private key length in th_ecdh_init]\r\n");
        return EE_STATUS_ERROR;
    }
    if (publen != 64)
    {
        th_printf("e-[Invalid public key length in th_ecdh_init]\r\n");
        return EE_STATUS_ERROR;
    }

    psa_status_t status;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    status
        = psa_import_key(&attributes, p_private, prilen, &p_ecdh->private_key);
    if (status)
        return EE_STATUS_ERROR;

    memcpy(&p_ecdh->public_key[1], p_public, publen);
    p_ecdh->public_key[0] = 0x04;
    return EE_STATUS_OK;
}

/**
 * Perform ECDH mixing.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdh_calc_secret(void *         p_context, // input: portable context
                    unsigned char *p_secret,  // output: shared secret
                    unsigned int slen // input: length of shared buffer in bytes
)
{
    ecdh_p256_context *p_ecdh = (ecdh_p256_context *)p_context;

    if (slen != 32)
    {
        th_printf("e-[Invalid buffer length in th_ecdh_init]\r\n");
        return EE_STATUS_ERROR;
    }

    psa_status_t status;
    size_t       length;

    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                   p_ecdh->private_key,
                                   p_ecdh->public_key,
                                   sizeof p_ecdh->public_key,
                                   p_secret,
                                   slen,
                                   &length);
    if (status)
        return EE_STATUS_ERROR;

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdh_destroy(void *p_context // input: portable context
)
{
    ecdh_p256_context *p_ecdh_context = (ecdh_p256_context *)p_context;
    psa_destroy_key(p_ecdh_context->private_key);
    th_free(p_context);
}
