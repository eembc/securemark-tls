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
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_create(
    void **p_context // output: portable context
)
{
    #warning "th_ecdsa_create not implemented"
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
    #warning "th_ecdsa_init not implemented"
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
    // WARNING: Copy *slen into local storage if your SDK size type is not
    //          the same size as "unsigned int" and recast on assignment.
    #warning "th_ecdsa_sign not implemented"
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
    #warning "th_ecdsa_verify not implemented"
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
    #warning "th_ecdsa_destroy not implemented"
}
