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

#include "ee_bench.h"

/**
 * @brief This is a bit of a kludge so that we can pre-encrypt data to decrypt
 * without printing excess timestamps and confusing the host.
 *
 * TODO: Perhaps the host should send KEY, IV, and PT/CT, too?
 *
 */
extern bool g_mute_timestamps;

/**
 * @brief Helper function to copy a number of pseudo-random octets to a buffer.
 *
 * @param p_buffer Destination buffer.
 * @param len Number of octets.
 */
static void
fill_rand(uint8_t *p_buffer, size_t len)
{
    for (size_t x = 0; x < len; ++x)
    {
        p_buffer[x] = ee_rand();
    }
}

void
ee_bench_sha(ee_sha_size_t size, uint_fast32_t n, uint_fast32_t i, bool verify)
{
    uint8_t *p_in  = th_buffer_address();
    uint8_t *p_out = p_in + n;

    fill_rand(p_in, n);

    ee_sha(size, p_in, n, p_out, i);

    if (verify)
    {
        ee_printmemline(p_in, n, "m-bench-sha-in");
        ee_printmemline(p_out, size / 8, "m-bench-sha-out");
    }
}

void
ee_bench_aes(ee_aes_mode_t mode,
             ee_aes_func_t func,
             uint_fast32_t keylen,
             uint_fast32_t n,
             uint_fast32_t i,
             bool          verify)
{
    int      ivlen = mode == EE_AES_CTR ? EE_AES_CTR_IVLEN : EE_AES_AEAD_IVLEN;
    uint8_t *p_key = th_buffer_address();
    uint8_t *p_iv  = p_key + keylen;
    uint8_t *p_in  = p_iv + ivlen;
    uint8_t *p_out = p_in + n;
    uint8_t *p_tag = p_out + n;

    fill_rand(p_key, keylen);
    fill_rand(p_iv, ivlen);
    fill_rand(p_in, n);

    if (func == EE_AES_DEC)
    {
        /* Encrypt something for the decrypt loop to decrypt */
        g_mute_timestamps = true;
        ee_aes(mode, EE_AES_ENC, p_key, keylen, p_iv, p_in, n, p_out, p_tag, 1);
        g_mute_timestamps = false;
        th_memcpy(p_in, p_out, n);
        uint8_t *tmp = p_in;
        p_in         = p_out;
        p_out        = tmp;
    }

    ee_aes(mode, func, p_key, keylen, p_iv, p_in, n, p_out, p_tag, i);

    if (verify)
    {
        /* Not all of these are used (ECB, CCM), but print them anyway. */
        ee_printmemline(p_key, keylen, "m-bench-aes-key-");
        ee_printmemline(p_iv, ivlen, "m-bench-aes-iv-");
        ee_printmemline(p_in, n, "m-bench-aes-in-");
        ee_printmemline(p_out, n, "m-bench-aes-out-");
        ee_printmemline(p_tag, EE_AES_TAGLEN, "m-bench-aes-tag-");
    }
}

void
ee_bench_chachapoly(ee_chachapoly_func_t func, int n, int i, bool verify)
{
    uint8_t *p_key = th_buffer_address();
    uint8_t *p_iv  = p_key + EE_CHACHAPOLY_KEYLEN;
    uint8_t *p_in  = p_iv + EE_CHACHAPOLY_IVLEN;
    uint8_t *p_out = p_in + n;
    uint8_t *p_tag = p_out + n;

    fill_rand(p_key, EE_CHACHAPOLY_KEYLEN);
    fill_rand(p_iv, EE_CHACHAPOLY_IVLEN);
    fill_rand(p_in, n);

    if (func == EE_CHACHAPOLY_DEC)
    {
        /* Encrypt something for the decrypt loop to decrypt */
        g_mute_timestamps = true;
        ee_chachapoly(EE_CHACHAPOLY_ENC, p_key, p_iv, p_in, n, p_out, p_tag, 1);
        g_mute_timestamps = false;
        th_memcpy(p_in, p_out, n);
        uint8_t *tmp = p_in;
        p_in         = p_out;
        p_out        = tmp;
    }

    ee_chachapoly(func, p_key, p_iv, p_in, n, p_out, p_tag, i);

    if (verify)
    {
        ee_printmemline(p_key, EE_CHACHAPOLY_KEYLEN, "m-bench-chachapoly-key-");
        ee_printmemline(p_iv, EE_CHACHAPOLY_IVLEN, "m-bench-chachapoly-iv-");
        ee_printmemline(p_in, n, "m-bench-chachapoly-in-");
        ee_printmemline(p_out, n, "m-bench-chachapoly-out-");
        ee_printmemline(p_tag, EE_AES_TAGLEN, "m-bench-chachapoly-tag-");
    }
}

void
ee_bench_ecdh(ee_ecdh_group_t g, uint_fast32_t i, bool verify)
{
    uint32_t *p_publen = (uint32_t *)th_buffer_address();
    /* The host will send data in BE if it is not an octet stream. */
    *p_publen          = EE_FIX_ENDIAN(*p_publen);
    if (*p_publen > 0x80000) {
        th_printf("e-[Possible incorrect endian configuration]\r\n");
        return;
    }
    uint8_t * p_pub    = (uint8_t *)p_publen + sizeof(uint32_t);
    uint32_t *p_seclen = (uint32_t *)(p_pub + *p_publen);
    /* The host will send data in BE if it is not an octet stream. */
    *p_seclen      = EE_FIX_ENDIAN(*p_seclen);
    uint8_t *p_sec = (uint8_t *)p_seclen + sizeof(uint32_t);

    uint8_t *p_dutpub  = p_sec + *p_seclen;
    uint32_t dutpublen = 256;

    void *      p_context = NULL;
    ee_status_t ret       = EE_STATUS_OK;

    th_ecdh_create(&p_context, g);
    th_ecdh_set_peer_public_key(p_context, p_pub, *p_publen);
    th_printf("m-ecdh-%s-iter[%d]\r\n", ee_ecdh_group_names[g], i);
    th_printf("m-ecdh-%s-start\r\n", ee_ecdh_group_names[g]);
    th_timestamp();
    th_pre();
    do
    {
        ret = th_ecdh_calc_secret(p_context, p_sec, p_seclen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    th_timestamp();
    th_printf("m-ecdh-%s-finish\r\n", ee_ecdh_group_names[g]);
    th_ecdh_get_public_key(p_context, p_dutpub, &dutpublen);
    th_ecdh_destroy(p_context);

    if (ret != EE_STATUS_OK)
    {
        th_printf("e-[Failed on ECDH secret]\r\n");
    }

    if (verify)
    {
        ee_printmemline(p_dutpub, dutpublen, "m-bench-ecdh-public-");
        ee_printmemline(p_sec, *p_seclen, "m-bench-ecdh-secret-");
    }
}

void
ee_bench_ecdsa_sign(ee_ecdh_group_t g,
                    uint_fast32_t   n,
                    uint_fast32_t   i,
                    bool            verify)
{
    /* Sig will be ASN.1 so may vary, just put some reasonable values. */
    uint_fast32_t publen = 256;
    uint_fast32_t siglen = 256;

    uint8_t *p_msg = th_buffer_address();
    uint8_t *p_pub = p_msg + n;
    uint8_t *p_sig = p_pub + publen;

    void *      p_context = NULL;
    ee_status_t ret       = EE_STATUS_OK;

    fill_rand(p_msg, n);

    th_ecdsa_create(&p_context, g);
    th_printf("m-ecdsa-%s-sign-iter[%d]\r\n", ee_ecdh_group_names[g], i);
    th_printf("m-ecdsa-%s-sign-start\r\n", ee_ecdh_group_names[g]);
    th_timestamp();
    th_pre();
    do
    {
        ret = th_ecdsa_sign(p_context, p_msg, n, p_sig, &siglen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    th_timestamp();
    th_printf("m-ecdsa-%s-sign-finish\r\n", ee_ecdh_group_names[g]);
    th_ecdsa_get_public_key(p_context, p_pub, &publen);
    th_ecdsa_destroy(p_context);

    if (ret != EE_STATUS_OK)
    {
        th_printf("e-[Failed on ECDSA sign]\r\n");
    }

    if (verify)
    {
        ee_printmemline(p_msg, n, "m-ecdsa-sign-msg-");
        ee_printmemline(p_sig, siglen, "m-ecdsa-sign-signature-");
        ee_printmemline(p_pub, publen, "m-ecdsa-sign-pubkey-");
    }
}

void
ee_bench_ecdsa_verify(ee_ecdh_group_t g,
                      uint_fast32_t   n,
                      uint_fast32_t   i,
                      bool            verify)
{
    uint8_t * p_msg    = th_buffer_address();
    uint32_t *p_publen = (uint32_t *)(p_msg + n);
    /* The host will send data in BE if it is not an octet stream. */
    *p_publen          = EE_FIX_ENDIAN(*p_publen);
    if (*p_publen > 0x80000) {
        th_printf("e-[Possible incorrect endian configuration]\r\n");
        return;
    }
    uint8_t * p_pub    = (uint8_t *)p_publen + sizeof(uint32_t);
    uint32_t *p_siglen = (uint32_t *)(p_pub + *p_publen);
    /* The host will send data in BE if it is not an octet stream. */
    *p_siglen              = EE_FIX_ENDIAN(*p_siglen);
    uint8_t *   p_sig      = (uint8_t *)p_siglen + sizeof(uint32_t);
    uint8_t *   p_passfail = p_sig + *p_siglen;
    void *      p_ctx      = NULL;
    ee_status_t ret        = EE_STATUS_OK;

    th_ecdsa_create(&p_ctx, g);
    th_ecdsa_set_public_key(p_ctx, p_pub, *p_publen);
    th_printf("m-ecdsa-%s-verify-iter[%d]\r\n", ee_ecdh_group_names[g], i);
    th_printf("m-ecdsa-%s-verify-start\r\n", ee_ecdh_group_names[g]);
    th_timestamp();
    th_pre();
    do
    {
        ret = th_ecdsa_verify(p_ctx, p_msg, n, p_sig, *p_siglen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    th_timestamp();
    th_printf("m-ecdsa-%s-verify-finish\r\n", ee_ecdh_group_names[g]);
    th_ecdsa_destroy(p_ctx);

    *p_passfail = ret == EE_STATUS_OK ? 1 : 0;

    if (verify)
    {
        ee_printmemline(p_msg, n, "m-ecdsa-sign-msg-");
        ee_printmemline(p_sig, *p_siglen, "m-ecdsa-sign-signature-");
        ee_printmemline(p_pub, *p_publen, "m-ecdsa-sign-pubkey-");
        th_printf("m-ecdsa-sign-passfail-%d\r\n", *p_passfail);
    }
}

void
ee_bench_rsa_verify(ee_rsa_id_t id, unsigned int n, unsigned int i, bool verify)
{
    uint8_t * p_msg    = th_buffer_address();
    uint32_t *p_publen = (uint32_t *)(p_msg + n);
    /* The host will send data in BE if it is not an octet stream. */
    *p_publen          = EE_FIX_ENDIAN(*p_publen);
    if (*p_publen > 0x80000) {
        th_printf("e-[Possible incorrect endian configuration]\r\n");
        return;
    }
    uint8_t * p_pub    = (uint8_t *)p_publen + sizeof(uint32_t);
    uint32_t *p_siglen = (uint32_t *)(p_pub + *p_publen);
    /* The host will send data in BE if it is not an octet stream. */
    *p_siglen              = EE_FIX_ENDIAN(*p_siglen);
    uint8_t *   p_sig      = (uint8_t *)p_siglen + sizeof(uint32_t);
    uint8_t *   p_passfail = p_sig + *p_siglen;
    void *      p_context  = NULL;
    ee_status_t ret        = EE_STATUS_OK;

    th_rsa_create(&p_context);
    th_rsa_set_public_key(p_context, p_pub, *p_publen);
    th_timestamp();
    th_pre();
    do
    {
        ret = th_rsa_verify(p_context, p_msg, n, p_sig, *p_siglen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    th_timestamp();
    th_rsa_destroy(p_context);

    *p_passfail = ret == EE_STATUS_OK ? 1 : 0;

    if (verify)
    {
        ee_printmemline(p_pub, *p_publen, "m-bench-rsa-pri-");
        ee_printmemline(p_msg, n, "m-bench-rsa-msg-");
        ee_printmemline(p_sig, *p_siglen, "m-bench-rsa-sig-");
        th_printf("m-ecdsa-sign-passfail-%d\r\n", *p_passfail);
    }
}

arg_claimed_t
ee_bench_parse(char *p_command, bool verify)
{
    char *        p_subcmd;
    char *        p_seed;
    char *        p_iter;
    char *        p_size;
    uint_fast32_t i;
    uint_fast32_t n;
    if (th_strncmp(p_command, "bench", EE_CMD_SIZE) != 0)
    {
        return EE_ARG_UNCLAIMED;
    }
    /**
     * Each subcommand takes four paramters:
     *
     * subcmd : the name of the primitive to benchmark
     * seed   : the decimal positive integer seed
     * size   : the number of bytes in the input dataset
     * iter   : the decimal positive integer iteration count
     */
    p_subcmd = th_strtok(NULL, EE_CMD_DELIMITER);
    p_seed   = th_strtok(NULL, EE_CMD_DELIMITER);
    p_size   = th_strtok(NULL, EE_CMD_DELIMITER);
    p_iter   = th_strtok(NULL, EE_CMD_DELIMITER);

    if (p_subcmd == NULL)
    {
        th_printf("e-[Command 'bench' takes a subcommand]\r\n");
        return EE_ARG_CLAIMED;
    }

    if (p_seed != NULL)
    {
        ee_srand((uint8_t)th_atoi(p_seed));
    }
    else
    {
        th_printf("e-[Benchmark seed not specified]\r\n");
        return EE_ARG_CLAIMED;
    }

    if (p_size)
    {
        n = (uint_fast32_t)th_atoi(p_size);
    }
    else
    {
        n = 0;
    }

    if (p_iter)
    {
        i = (uint_fast32_t)th_atoi(p_iter);

        if (i == 0)
        {
            th_printf("e-[Benchmark iterations cannot be zero]\r\n");
            return EE_ARG_CLAIMED;
        }
    }
    else
    {
        th_printf("e-[Benchmark iterations not specified]\r\n");
        return EE_ARG_CLAIMED;
    }

    if (th_strncmp(p_subcmd, "sha256", EE_CMD_SIZE) == 0)
    {
        ee_bench_sha(EE_SHA256, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "sha384", EE_CMD_SIZE) == 0)
    {
        ee_bench_sha(EE_SHA384, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ecb-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_ENC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ecb-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_DEC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ctr-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_ENC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ctr-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_DEC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ccm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_ENC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ccm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_DEC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-gcm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_GCM, EE_AES_ENC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-gcm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_GCM, EE_AES_DEC, EE_AES_128KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ecb-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_ENC, EE_AES_256KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ecb-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_DEC, EE_AES_256KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ctr-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_ENC, EE_AES_256KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ctr-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_DEC, EE_AES_256KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ccm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_ENC, EE_AES_256KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ccm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_DEC, EE_AES_256KEYLEN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "chachapoly-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_chachapoly(EE_CHACHAPOLY_ENC, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "chachapoly-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_chachapoly(EE_CHACHAPOLY_DEC, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdh-p256", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(EE_P256R1, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdh-p384", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(EE_P384, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdh-x25519", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(EE_C25519, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p256-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_sign(EE_P256R1, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p256-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_verify(EE_P256R1, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p384-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_sign(EE_P384, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p384-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_verify(EE_P384, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-ed25519-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_sign(EE_Ed25519, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-ed25519-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_verify(EE_Ed25519, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "rsa2048-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_rsa_verify(EE_RSA_2048, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "rsa3072-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_rsa_verify(EE_RSA_3072, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "rsa4096-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_rsa_verify(EE_RSA_4096, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "var01", EE_CMD_SIZE) == 0)
    {
        ee_variation_001(i);
    }
    else
    {
        th_printf("e-[Unknown benchmark subcommand: %s]\r\n", p_subcmd);
    }
    return EE_ARG_CLAIMED;
}
