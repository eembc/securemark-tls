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

#include "ee_rsa.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>

/* can be set for static memory use */
#define HEAP_HINT NULL

/* used with crypto callbacks and async */
#define DEVID -1

typedef struct rsa_context_t
{
    RsaKey *prikey;
    RsaKey *pubkey;
    WC_RNG *rng;
} rsa_context_t;

#define FREE(x)         \
    {                   \
        if (x)          \
        {               \
            th_free(x); \
            x = NULL;   \
        }               \
    }

/**
 * @brief Creates a portable context structure for RSA operations.
 *
 * @param pp_context Pointer to portable context pointer.
 * @return ee_status_t EE_STATUS_OK or EE_STATUS_FAIL
 */
ee_status_t
th_rsa_create(void **pp_context)
{
    rsa_context_t *ctx;

    ctx = (rsa_context_t *)th_malloc(sizeof(rsa_context_t));
    if (!ctx)
    {
        th_printf("e-[th_rsa_create failed to malloc]\r\n");
        return EE_STATUS_ERROR;
    }

    th_memset(ctx, 0, sizeof(rsa_context_t));

    ctx->prikey = (RsaKey *)th_malloc(sizeof(RsaKey));
    ctx->pubkey = (RsaKey *)th_malloc(sizeof(RsaKey));
    ctx->rng    = (WC_RNG *)th_malloc(sizeof(WC_RNG));
    if (!ctx->prikey || !ctx->pubkey || !ctx->rng)
    {
        th_printf("e-[th_rsa_create failed to malloc]\r\n");
        FREE(ctx->prikey);
        FREE(ctx->pubkey);
        FREE(ctx->rng);
        FREE(ctx);
        return EE_STATUS_ERROR;
    }

    *pp_context = ctx;

    return EE_STATUS_OK;
}

/**
 * @brief Initialize structures created ruing `th_rsa_create` and setup and
 * library or hardware functionality. Typically loads the private and public
 * keys, and inititalizes and RNGs or configuration options.
 *
 * @param p_context Portable context.
 * @param id Size of the modulus, an `rsa_id_t` enum
 * @param p_pri Private key buffer, as quintuple ASN.1/DER RFC 8017 Sec 3.2
 * @param prilen Private key buffer length
 * @param p_pub Public key buffer, as N/E ASN.1/DER RFC 8017 Sec 3.1.2
 * @param publen Public key buffer length
 * @return ee_status_t EE_STATUS_OK or EE_STATUS_FAIL
 */
ee_status_t
th_rsa_init(void *         p_context,
            rsa_id_t       id,
            const uint8_t *p_prikey,
            uint_fast32_t  prilen,
            const uint8_t *p_pubkey,
            uint_fast32_t  publen)
{
    int            ret;
    word32         inOutIdx;
    rsa_context_t *ctx = (rsa_context_t *)p_context;

    ret = wc_InitRsaKey_ex(ctx->prikey, HEAP_HINT, DEVID);
    if (ret)
    {
        th_printf("e-[wc_InitRsaKey_ex on private: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    ret = wc_InitRsaKey_ex(ctx->pubkey, HEAP_HINT, DEVID);
    if (ret)
    {
        th_printf("e-[wc_InitRsaKey_ex on public: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    inOutIdx = 0;
    ret      = wc_RsaPrivateKeyDecode(p_prikey, &inOutIdx, ctx->prikey, prilen);
    if (ret)
    {
        th_printf("e-[wc_RsaPrivateKeyDecode: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    inOutIdx = 0;
    ret      = wc_RsaPublicKeyDecode(p_pubkey, &inOutIdx, ctx->pubkey, publen);
    if (ret)
    {
        th_printf("e-[wc_RsaPublicKeyDecode: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    wc_InitRng_ex(ctx->rng, HEAP_HINT, DEVID);

    return EE_STATUS_OK;
}

/**
 * @brief Perform an RSA verify (exp mod n) of a hash, and return the raw
 * (decrypted) signature. The validity of the output will be checked by the
 * host application. This function must perform PKCS1v15 padding as
 * described in RFC 8017 9.2.
 *
 * @param p_context Portable context
 * @param p_sig Pointer to signature octet buffer, raw bytes
 * @param slen Length of signature buffer
 * @param p_outbuf Pointer to an output buffer
 * @param olen Length of provided output buffer
 * @return ee_status_t
 */
ee_status_t
th_rsa_sign(void *         p_context,
            const uint8_t *p_hash,
            uint_fast32_t  hlen,
            uint8_t *      p_sig,
            uint_fast32_t *p_slen)
{
    int            ret;
    rsa_context_t *ctx = (rsa_context_t *)p_context;

    ret = wc_RsaSSL_Sign(p_hash, hlen, p_sig, *p_slen, ctx->prikey, ctx->rng);
    if (ret < 0)
    {
        th_printf("e-[wc_RsaSSL_Sign: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    *p_slen = ret;

    return EE_STATUS_OK;
}

/**
 * @brief Perform an RSA verify (exp mod n) of a hash, and return the raw
 * (decrypted) signature. The validity of the output will be checked by the
 * host application.
 *
 * @param p_context Portable context
 * @param p_sig Pointer to signature octet buffer, raw bytes
 * @param slen Length of signature buffer
 * @param p_outbuf Pointer to an output buffer
 * @param olen Length of provided output buffer
 * @return ee_status_t
 */
ee_status_t
th_rsa_verify(void *         p_context,
              const uint8_t *p_sig,
              uint_fast32_t  slen,
              uint8_t *      p_outbuf,
              uint_fast32_t  olen)
{
    int            ret;
    rsa_context_t *ctx = (rsa_context_t *)p_context;

    ret = wc_RsaSSL_Verify(p_sig, slen, p_outbuf, olen, ctx->pubkey);
    if (ret < 0)
    {
        th_printf("e-[wc_RsaSSL_Verify: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * @brief De-initialize and destroy and context created, and free up any
 * memory allocated during `th_rsa_create`.
 *
 * @param p_context Portable context pointer
 */
void
th_rsa_destroy(void *p_context)
{
    rsa_context_t *ctx = (rsa_context_t *)p_context;
    FREE(ctx->prikey);
    FREE(ctx->pubkey);
    FREE(ctx->rng);
    FREE(ctx);
}
