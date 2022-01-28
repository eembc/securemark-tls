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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>

/* can be set for static memory use */
#define HEAP_HINT NULL

/* used with crypto callbacks and async */
#define DEVID -1

#include "ee_ecdh.h"
#include "ee_ecdsa.h"

// helper function defined in th_ecdh.h; not mandatory but very useful!
int load_private_key(void *, unsigned char *, size_t);

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_create(void **      p_context, // output: portable context
                ecdh_group_t group      // input: see `ecdh_group_t` for options
)
{
    void *ptr = NULL;

    switch (group)
    {
        case EE_C25519:
            ptr = th_malloc(sizeof(ed25519_key));
            break;
        case EE_P256R1:
            ptr = th_malloc(sizeof(ecc_key));
            break;
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_create]\r\n");
            return EE_STATUS_ERROR;
    }
    if (ptr == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdsa_create\r\n");
        return EE_STATUS_ERROR;
    }
    *p_context = ptr;

    return EE_STATUS_OK;
}

ee_status_t
init_ecc(ecc_key *p_key, uint8_t *p_private, uint_fast32_t plen)
{
    int ret;

    ret = wc_ecc_init_ex(p_key, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_init_ex: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ecc_import_private_key_ex(
        p_private, plen, NULL, 0, p_key, ECC_SECP256R1);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_import_private_key_ex: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ecc_make_pub(p_key, NULL);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_make_pub: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    /* set deterministic k value */
    ret = wc_ecc_set_deterministic(p_key, 1);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_set_deterministic: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
#else
#error compile wolfSSL with WOLFSSL_ECDSA_DETERMINISTIC_K
#endif
    return EE_STATUS_OK;
}

ee_status_t
init_ed25519(ed25519_key *p_key, uint8_t *p_private, uint_fast32_t plen)
{
    int     ret;
    uint8_t tmp_public[ED25519_PUB_KEY_SIZE];

    ret = wc_ed25519_init_ex(p_key, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_init_ex: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ed25519_import_private_only(p_private, plen, p_key);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_import_private_only: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ed25519_make_public(p_key, tmp_public, ED25519_PUB_KEY_SIZE);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_make_public: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ed25519_import_public(tmp_public, ED25519_PUB_KEY_SIZE, p_key);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_import_public: -%d]\r\n", -ret);
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
th_ecdsa_init(void *        p_context, // input: portable context
              ecdh_group_t  group,     // input: see `ecdh_group_t` for options
              uint8_t *     p_private, // input: private key from host
              uint_fast32_t plen       // input: length of private key in bytes
)
{
    switch (group)
    {
        case EE_P256R1:
            return init_ecc((ecc_key *)p_context, p_private, plen);
        case EE_C25519:
            return init_ed25519((ed25519_key *)p_context, p_private, plen);
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_init]\r\n");
            return EE_STATUS_ERROR;
    }
}

ee_status_t
sign_ecc(ecc_key *      p_context, // input: portable context
         uint8_t *      p_hash,    // input: sha256 digest
         uint_fast32_t  hlen,      // input: length of digest in bytes
         uint8_t *      p_sig,     // output: signature
         uint_fast32_t *p_slen     // in/out: input=MAX slen, output=resultant
)
{
    int    ret;
    WC_RNG rng;

    ret = wc_InitRng_ex(&rng, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[wc_InitRng_ex: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ecc_sign_hash(p_hash, hlen, p_sig, p_slen, &rng, p_context);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_sign_hash: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    wc_FreeRng(&rng);
    return EE_STATUS_OK;
}

ee_status_t
sign_ed25519(ed25519_key *  p_context, // input: portable context
             uint8_t *      p_msg,     // input: message
             uint_fast32_t  mlen,      // input: length of message in bytes
             uint8_t *      p_sig,     // output: signature
             uint_fast32_t *p_slen     // output: signature length in bytes
)
{
    int ret;
    ret = wc_ed25519_sign_msg(p_msg, mlen, p_sig, p_slen, p_context);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_sign_msg: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

/**
 * Create a signature using the specified hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_sign(void *         p_context, // input: portable context
              ecdh_group_t   group,     // input: see `ecdh_group_t` for options
              uint8_t *      p_msg,     // input: message
              uint_fast32_t  mlen,      // input: length of message in bytes
              uint8_t *      p_sig,     // output: signature
              uint_fast32_t *p_slen // in/out: input=MAX slen, output=resultant
)
{
    switch (group)
    {
        case EE_P256R1:
            return sign_ecc((ecc_key *)p_context, p_msg, mlen, p_sig, p_slen);
        case EE_C25519:
            return sign_ed25519(
                (ed25519_key *)p_context, p_msg, mlen, p_sig, p_slen);
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_sign]\r\n");
            return EE_STATUS_ERROR;
    }
}

ee_status_t
verify_ecc(ecc_key *     p_context,
           uint8_t *     p_hash, // input: sha256 digest
           uint_fast32_t hlen,   // input: length of digest in bytes
           uint8_t *     p_sig,  // output: signature
           uint_fast32_t slen    // input: length of signature in bytes
)
{
    int ret;
    int verify;

    ret = wc_ecc_verify_hash(p_sig, slen, p_hash, hlen, &verify, p_context);
    if (ret != 0 || verify != 1)
    {
        th_printf("e-[Failed to verify in verify_ecc: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
verify_ed25519(ed25519_key * p_context,
               uint8_t *     p_hash, // input: sha256 digest
               uint_fast32_t hlen,   // input: length of digest in bytes
               uint8_t *     p_sig,  // output: signature
               uint_fast32_t slen    // input: length of signature in bytes
)
{
    int ret;
    int verify;

    ret = wc_ed25519ph_verify_hash(
        p_sig, slen, p_hash, hlen, &verify, p_context, NULL, 0);
    if (ret != 0 || verify != 1)
    {
        th_printf("e-[Failed to verify in verify_ed25519: -%d]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

/**
 * Create a signature using SHA256 hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_verify(void *        p_context, // input: portable context
                ecdh_group_t  group,  // input: see `ecdh_group_t` for options
                uint8_t *     p_hash, // input: sha256 digest
                uint_fast32_t hlen,   // input: length of digest in bytes
                uint8_t *     p_sig,  // output: signature
                uint_fast32_t slen    // input: length of signature in bytes
)
{
    switch (group)
    {
        case EE_P256R1:
            return verify_ecc((ecc_key *)p_context, p_hash, hlen, p_sig, slen);
        case EE_C25519:
            return verify_ed25519(
                (ed25519_key *)p_context, p_hash, hlen, p_sig, slen);
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_verify]\r\n");
            return EE_STATUS_ERROR;
    }
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdsa_destroy(void *       p_context, // portable context
                 ecdh_group_t group // input: see `ecdh_group_t` for options
)
{
    switch (group)
    {
        case EE_P256R1:
            wc_ecc_free((ecc_key *)p_context);
            break;
        case EE_C25519:
            wc_ed25519_free((ed25519_key *)p_context);
            break;
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_destroy]\r\n");
            break;
    }
}
