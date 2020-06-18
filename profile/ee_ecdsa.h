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

#ifndef __EE_ECDSA_H
#define __EE_ECDSA_H

#include "ee_main.h"
#include "ee_ecdh.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

// Fixed test API

/**
 * Perform an ECDSA sign a given number of times.
 *
 * HASH: SHA256 digest (32 bytes)
 * SIGNATURE: ASN.1 or raw R/S (32B each)
 * PRIVATE: 32B secret
 *
 * Note: slen is bidirectional depending on the operation, can denote MAX len
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
);

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
);

// Implementation API

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_create(
    void **p_context // output: portable context
);

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
);

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
);

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
);

/**
 * Destroy the context created earlier.
 */
void
th_ecdsa_destroy(
    void *p_context // portable context
);

#endif // __EE_ECDSA_H
