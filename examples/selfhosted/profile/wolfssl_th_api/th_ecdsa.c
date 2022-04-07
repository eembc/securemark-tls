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
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>

/* can be set for static memory use */
#define HEAP_HINT NULL

/* used with crypto callbacks and async */
#define DEVID -1

#include "ee_ecdh.h"
#include "ee_ecdsa.h"

ee_status_t
th_ecdsa_create(void **p_context, ee_ecdh_group_t group)
{
    void *ptr = NULL;

    switch (group)
    {
        case EE_P256R1:
        case EE_P384:
            ptr = th_malloc(sizeof(ecc_key));
            break;
        case EE_Ed25519:
            ptr = th_malloc(sizeof(ed25519_key));
            break;
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_create]\r\n");
            return EE_STATUS_ERROR;
    }
    if (ptr == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdsa_create]\r\n");
        return EE_STATUS_ERROR;
    }
    *p_context = ptr;

    return EE_STATUS_OK;
}

ee_status_t
init_ecc(ecc_key *     p_key,
         uint8_t *     p_private,
         uint_fast32_t plen,
         ecc_curve_id  id)
{
    int ret;
    ret = wc_ecc_init_ex(p_key, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_init_ex: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ecc_import_private_key_ex(p_private, plen, NULL, 0, p_key, id);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_import_private_key_ex: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ecc_make_pub(p_key, NULL);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_make_pub: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    /* set deterministic k value */
    /* TODO: This forces SHA256 for det-k, but there's no way to change it */
    ret = wc_ecc_set_deterministic(p_key, 1);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_set_deterministic: %d]\r\n", ret);
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
        th_printf("e-[wc_ed25519_init_ex: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ed25519_import_private_only(p_private, plen, p_key);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_import_private_only: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ed25519_make_public(p_key, tmp_public, ED25519_PUB_KEY_SIZE);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_make_public: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ed25519_import_public(tmp_public, ED25519_PUB_KEY_SIZE, p_key);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_import_public: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_init(void *          p_context,
              ee_ecdh_group_t group,
              uint8_t *       p_private,
              uint_fast32_t   plen)
{
    switch (group)
    {
        case EE_P256R1:
            return init_ecc(
                (ecc_key *)p_context, p_private, plen, ECC_SECP256R1);
        case EE_P384:
            return init_ecc(
                (ecc_key *)p_context, p_private, plen, ECC_SECP384R1);
        case EE_Ed25519:
            return init_ed25519((ed25519_key *)p_context, p_private, plen);
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_init]\r\n");
            return EE_STATUS_ERROR;
    }
}

static ee_status_t
sign_ecc(ecc_key *      p_context,
         uint8_t *      p_hash,
         uint_fast32_t  hlen,
         uint8_t *      p_sig,
         uint_fast32_t *p_slen)
{
    int     ret;
    WC_RNG  rng;
    word32 *p_slen2 = (word32 *)p_slen;

    ret = wc_InitRng_ex(&rng, HEAP_HINT, DEVID);
    if (ret != 0)
    {
        th_printf("e-[wc_InitRng_ex: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_ecc_sign_hash(p_hash, hlen, p_sig, p_slen2, &rng, p_context);
    if (ret != 0)
    {
        th_printf("e-[wc_ecc_sign_hash: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    wc_FreeRng(&rng);
    return EE_STATUS_OK;
}

static ee_status_t
sign_ed25519(ed25519_key *  p_context,
             uint8_t *      p_msg,
             uint_fast32_t  mlen,
             uint8_t *      p_sig,
             uint_fast32_t *p_slen)
{
    int     ret;
    word32 *p_slen2 = (word32 *)p_slen;

    ret = wc_ed25519_sign_msg(p_msg, mlen, p_sig, p_slen2, p_context);
    if (ret != 0)
    {
        th_printf("e-[wc_ed25519_sign_msg: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_sign(void *          p_context,
              ee_ecdh_group_t group,
              uint8_t *       p_msg,
              uint_fast32_t   mlen,
              uint8_t *       p_sig,
              uint_fast32_t * p_slen)
{
    switch (group)
    {
        case EE_P256R1:
        case EE_P384:
            return sign_ecc((ecc_key *)p_context, p_msg, mlen, p_sig, p_slen);
        case EE_Ed25519:
            return sign_ed25519(
                (ed25519_key *)p_context, p_msg, mlen, p_sig, p_slen);
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_sign]\r\n");
            return EE_STATUS_ERROR;
    }
}

static ee_status_t
verify_ecc(ecc_key *     p_context,
           uint8_t *     p_hash,
           uint_fast32_t hlen,
           uint8_t *     p_sig,
           uint_fast32_t slen)
{
    int ret;
    int verify;

    ret = wc_ecc_verify_hash(p_sig, slen, p_hash, hlen, &verify, p_context);
    if (ret != 0 || verify != 1)
    {
        th_printf("e-[wc_ecc_verify_hash: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

static ee_status_t
verify_ed25519(ed25519_key * p_context,
               uint8_t *     p_msg,
               uint_fast32_t mlen,
               uint8_t *     p_sig,
               uint_fast32_t slen)
{
    int ret;
    int verify;

    ret = wc_ed25519_verify_msg(p_sig, slen, p_msg, mlen, &verify, p_context);
    if (ret != 0 || verify != 1)
    {
        th_printf("e-[wc_ed25519_verify_msg: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_verify(void *          p_context,
                ee_ecdh_group_t group,
                uint8_t *       p_msg,
                uint_fast32_t   mlen,
                uint8_t *       p_sig,
                uint_fast32_t   slen)
{
    switch (group)
    {
        case EE_P256R1:
        case EE_P384:
            return verify_ecc((ecc_key *)p_context, p_msg, mlen, p_sig, slen);
        case EE_Ed25519:
            return verify_ed25519(
                (ed25519_key *)p_context, p_msg, mlen, p_sig, slen);
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_verify]\r\n");
            return EE_STATUS_ERROR;
    }
}

void
th_ecdsa_destroy(void *p_context, ee_ecdh_group_t group)
{
    switch (group)
    {
        case EE_P256R1:
        case EE_P384:
            wc_ecc_free((ecc_key *)p_context);
            break;
        case EE_Ed25519:
            wc_ed25519_free((ed25519_key *)p_context);
            break;
        default:
            th_printf("e-[Invalid ECC curve in th_ecdsa_destroy]\r\n");
            break;
    }
}

typedef struct
{
    union
    {
        ecc_key ecc;
        ed25519_key ed25519;
    } key;
    WC_RNG rng;
    ecc_curve_id curve;
} ctx_t;

void ee_printmemline(uint8_t *p_addr, uint_fast32_t len, char *p_user_header);

#define CHK1(x) { ret = x; if (ret < 0) { goto error; }}

ee_status_t
th_ecdsa_xcreate(void **pp_context, ee_ecdh_group_t group)
{
    ctx_t *ctx = (ctx_t *)th_malloc(sizeof(ctx_t));
    int ret;

    wc_InitRng_ex(&(ctx->rng), HEAP_HINT, DEVID);
    /* Switch from EEMBC group enums to SDK enums for consistency, make key. */
    switch (group)
    {
        case EE_P256R1:
            ctx->curve = ECC_SECP256R1;
            CHK1(wc_ecc_init_ex(&(ctx->key.ecc), HEAP_HINT, DEVID));
            CHK1(wc_ecc_make_key(&(ctx->rng), 32, &(ctx->key.ecc)));
            CHK1(wc_ecc_set_deterministic(&(ctx->key.ecc), 1));
            break;
        case EE_P384:
            ctx->curve = ECC_SECP384R1;
            CHK1(wc_ecc_init_ex(&(ctx->key.ecc), HEAP_HINT, DEVID));
            CHK1(wc_ecc_make_key(&(ctx->rng), 48, &(ctx->key.ecc)));
            CHK1(wc_ecc_set_deterministic(&(ctx->key.ecc), 1));
            break;
        case EE_C25519:
            ctx->curve = ECC_X25519; /* [sic], should be C25519? */
            CHK1(wc_ed25519_init_ex(&(ctx->key.ed25519), HEAP_HINT, DEVID));
            CHK1(wc_ed25519_make_key(&(ctx->rng), 32, &(ctx->key.ed25519)));
            break;
        default:
            th_printf("e-[th_ecdsa_xcreate: invalid group %d]\r\n", group);
            return EE_STATUS_ERROR;
    }
    *pp_context = ctx;
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_xcreate: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdsa_xsign(void *p_context, uint8_t *p_msg, uint_fast32_t msglen, uint8_t *p_sig, uint_fast32_t *p_siglen)
{
    ctx_t *c = (ctx_t *)p_context;
    int ret;

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_sign_hash(p_msg, msglen, p_sig, p_siglen, &(c->rng), &(c->key.ecc)));
            break;
        case ECC_X25519:
            CHK1(wc_ed25519_sign_msg(p_msg, msglen, p_sig, p_siglen, &(c->key.ed25519)));
            break;
        default:
            th_printf("e-[th_ecdsa_xsign: invalid curve %d]\r\n", c->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_xsign: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}


ee_status_t
th_ecdsa_xverify(void *p_context, uint8_t *p_msg, uint_fast32_t msglen, uint8_t *p_sig, uint_fast32_t siglen)
{
    ctx_t *c = (ctx_t *)p_context;
    int ret;
    int verify = 0;

    ee_printmemline(p_sig, siglen, "sig: ");
    ee_printmemline(p_msg, msglen, "msg: ");

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            ret = wc_ecc_verify_hash(p_sig, siglen, p_msg, msglen, &verify, &(c->key.ecc));
            if (ret != 0 || verify != 1)
            {
                th_printf("e-[wc_ecc_verify_hash: %d, verify %d]\r\n", ret, verify);
                return EE_STATUS_ERROR;
            }
            break;
        case ECC_X25519:
            ret = wc_ed25519_verify_msg(p_sig, siglen, p_msg, msglen, &verify, &(c->key.ed25519));
            if (ret != 0 || verify != 1)
            {
                th_printf("e-[wc_ed25519_verify_msg: %d]\r\n", ret);
                return EE_STATUS_ERROR;
            }            break;
        default:
            th_printf("e-[th_ecdsa_xsign: invalid curve %d]\r\n", c->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}


ee_status_t
th_ecdsa_xget_public_key(void *p_context, uint8_t *p_out, uint_fast32_t *p_outlen)
{
    ctx_t *c = (ctx_t *)p_context;
    int ret;

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_export_x963(&(c->key.ecc), p_out, p_outlen));
            break;
        case ECC_X25519:
            CHK1(wc_ed25519_export_public(&(c->key.ed25519), p_out, p_outlen));
            break;
        default:
            th_printf("e-[th_ecdsa_xget_public_key: invalid curve %d]\r\n", c->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_xget_public_key: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdsa_xset_public(void *p_context, uint8_t *p_pub, uint_fast32_t publen)
{
    ctx_t *c = (ctx_t *)p_context;
    int ret;

    ee_printmemline(p_pub, publen, "pub: ");

    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            CHK1(wc_ecc_import_x963(p_pub, publen, &(c->key.ecc)));
            break;
        case ECC_X25519:
            CHK1(wc_ed25519_import_public(p_pub, publen, &(c->key.ed25519)));
            break;
        default:
            th_printf("e-[th_ecdsa_xset_public: invalid curve %d]\r\n", c->curve);
            return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
error:
    th_printf("e-[th_ecdsa_xset_public: error %d]\r\n", ret);
    return EE_STATUS_ERROR;
}

ee_status_t
th_ecdsa_xdestroy(void *p_context)
{
    ctx_t *c = (ctx_t *)p_context;

    if (NULL == c)
    {
        return EE_STATUS_OK;
    }
    switch (c->curve)
    {
        case ECC_SECP256R1:
        case ECC_SECP384R1:
            wc_ecc_free(&(c->key.ecc));
            break;
        case ECC_X25519:
            wc_ed25519_free(&(c->key.ed25519));
            break;
        default:
            th_printf("e-[th_ecdsa_xdestroy: invalid curve %d]\r\n", c->curve);
            /* still need to free ctx! ... return EE_STATUS_ERROR; */
            break;
    }
    wc_FreeRng(&(c->rng));
    th_free(c);

    c = NULL;

    return EE_STATUS_OK;
}