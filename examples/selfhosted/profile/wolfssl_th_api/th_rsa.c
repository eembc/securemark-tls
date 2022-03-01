
#include "ee_rsa.h"
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
    uint8_t enc[MAX_ENCODED_SIG_SZ];
    uint8_t xdigest[SHA256_DIGEST_SIZE];
    wc_Sha256 *dctx;
} rsa_context_t;

#define FREE(x) { if (x) { th_free(x); x = NULL; }}

ee_status_t
th_rsa_create(void **pp_context // output: portable context
) {
    rsa_context_t *ctx = NULL;

    ctx = (rsa_context_t *)th_malloc(sizeof(rsa_context_t));
    if (!ctx) {
        th_printf("th_rs_create failed to malloc]\r\n");
        return EE_STATUS_ERROR;
    }
    th_memset(ctx, 0, sizeof(rsa_context_t));
    ctx->prikey = (RsaKey *)th_malloc(sizeof(RsaKey));
    ctx->pubkey = (RsaKey *)th_malloc(sizeof(RsaKey));
    ctx->rng = (WC_RNG *)th_malloc(sizeof(WC_RNG));
    ctx->dctx = (wc_Sha256 *)th_malloc(sizeof(wc_Sha256));
    if (!ctx->prikey || !ctx->pubkey || !ctx->rng) {
        th_printf("e-[th_rsa_create failed to malloc]\r\n");
        FREE(ctx->prikey);
        FREE(ctx->pubkey);
        FREE(ctx->rng);
        FREE(ctx->dctx);
        FREE(ctx);
        return EE_STATUS_ERROR;
    }
    *pp_context = ctx;
    return EE_STATUS_OK;
}

ee_status_t th_rsa_init(void *        p_context, // input: portable context
                        rsa_id_t      id,        // input: enum of RSA types
                        uint8_t *     p_prikey,
                        uint_fast32_t prilen,
                        uint8_t *     p_pubkey,
                        uint_fast32_t publen
) {
    int ret;
    word32 inOutIdx;
    rsa_context_t *ctx;

    ctx = (rsa_context_t *)p_context;
    ret = wc_InitRsaKey_ex(ctx->prikey, HEAP_HINT, DEVID);
    if (ret) {
        th_printf("e-[wc_InitRsaKey_ex on private: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_InitRsaKey_ex(ctx->pubkey, HEAP_HINT, DEVID);
    if (ret) {
        th_printf("e-[wc_InitRsaKey_ex on public: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    wc_InitRng_ex(ctx->rng, HEAP_HINT, DEVID);
    inOutIdx = 0;
    ret = wc_RsaPrivateKeyDecode(p_prikey, &inOutIdx, ctx->prikey, prilen);
    if (ret) {
        th_printf("e-[wc_RsaPrivateKeyDecode: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(p_pubkey, &inOutIdx, ctx->pubkey, publen);
    if (ret) {
        th_printf("e-[wc_RsaPublicKeyDecode: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    ret = wc_InitSha256(ctx->dctx);
    if (ret) {
        th_printf("e-[wc_InitSha256: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

void th_rsa_deinit(
    void *   p_context // input: portable context
) {
    rsa_context_t *ctx = (rsa_context_t *)p_context;

    if (ctx->prikey) {
        wc_FreeRsaKey(ctx->prikey);
    }
    if (ctx->prikey) {
        wc_FreeRsaKey(ctx->pubkey);
    }
    if (ctx->rng) {
        wc_FreeRng(ctx->rng);
    }
}

ee_status_t th_rsa_sign(void *         p_context,
                        uint8_t *      p_msg,
                        uint_fast32_t  mlen,
                        uint8_t *      p_sig,
                        uint_fast32_t  *slen)
{
    int ret;
    int enclen;
    printf("pule %d\n", __LINE__);
    rsa_context_t *ctx = (rsa_context_t *)p_context;
    ret = wc_Sha256Update(ctx->dctx, p_msg, mlen);
    if (ret < 0) {
        th_printf("e-[wc_Sha256Update: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    printf("pule %d\n", __LINE__);
    ret = wc_Sha256Final(ctx->dctx, &(ctx->xdigest)); 
    if (ret < 0) {
        th_printf("e-[wc_Sha256Final: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    printf("pule %d\n", __LINE__);
    enclen = wc_EncodeSignature(ctx->enc, &(ctx->xdigest), SHA256_DIGEST_SIZE, SHA256h);
    if (enclen < 0) {
        th_printf("e-[wc_EncodeSignature: %d]\r\n", enclen);
        return EE_STATUS_ERROR;
    }
    printf("pule %d\n", __LINE__);
    ret = wc_RsaSSL_Sign(ctx->enc, enclen, p_sig, *slen, ctx->prikey, ctx->rng);
    if (ret < 0) {
        th_printf("e-[wc_RsaSSL_Sign: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    *slen = ret;
    wc_Sha256Free(ctx->dctx);
    return EE_STATUS_OK;
}

ee_status_t th_rsa_verify(void *        p_context,
                          uint8_t *     p_msg,
                          uint_fast32_t mlen,
                          uint8_t *     p_sig,
                          uint_fast32_t slen,
                          uint8_t *     p_verify) {
#warning "th_rsa_verify not implemented"
}

void th_rsa_destroy(void *p_context)
{
    rsa_context_t *ctx = (rsa_context_t *)p_context;

    //FREE(ctx->prikey);
    //FREE(ctx->pubkey);
    //FREE(ctx->rng);
    //FREE(ctx);
}