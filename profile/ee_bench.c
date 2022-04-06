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
    uint_fast32_t npub = ee_pub_sz[g];
    uint_fast32_t npri = ee_pri_sz[g];
    uint_fast32_t nsec = ee_sec_sz[g];

    /* The th_buffer has been pre-loaded with this data */
    uint8_t *p_pri = th_buffer_address();
    uint8_t *p_pub = p_pri + npri;
    uint8_t *p_sec = p_pub + npub;

    ee_ecdh(g, p_pri, npri, p_pub, npub, p_sec, nsec, i);

    if (verify)
    {
        ee_printmemline(p_pub, npub, "m-bench-ecdh-peer-public-");
        ee_printmemline(p_pri, npri, "m-bench-ecdh-own-private-");
        ee_printmemline(p_sec, nsec, "m-bench-ecdh-shared-");
    }
}

void
ee_bench_ecdsa(ee_ecdh_group_t g,
               ee_ecdsa_func_t func,
               uint_fast32_t   n,
               uint_fast32_t   i,
               bool            verify)
{
    /* These are not in the buffer */
    uint_fast32_t npri = ee_pri_sz[g];
    uint_fast32_t slen;

    /* The th_buffer has been pre-loaded with this data */
    uint8_t *p_pri = th_buffer_address();
    uint8_t *p_msg = p_pri + npri;
    uint8_t *p_sig = p_msg + n;

    if (func == EE_ECDSA_VERIFY)
    {
        if (g == EE_Ed25519)
        {
            /* Ed25519 signatures are raw {R|S} little endian */
            slen = 64;
        }
        else
        {
            /* EcDSA signatures are ASN.1, and are < 256 bytes for our case. */
            slen = p_sig[1] + 2;
        }
    }
    else
    {
        /* Provide max size as entire remaining buffer on sign */
        slen = th_buffer_size() - (p_sig - p_pri) - 1;
    }

    ee_ecdsa(g, func, p_msg, n, p_sig, &slen, p_pri, npri, i);

    if (verify)
    {
        ee_printmemline(p_pri, npri, "m-bench-ecdsa-private-");
        ee_printmemline(p_msg, n, "m-bench-ecdsa-msg-");
        ee_printmemline(p_sig, slen, "m-bench-ecdsa-sig-");
    }
}

void
ee_bench_rsa(ee_rsa_id_t       id,
             ee_rsa_function_t func,
             unsigned int      i,
             bool              verify)
{
    uint32_t *p_prilen;
    uint8_t * p_pri;
    uint32_t *p_msglen;
    uint8_t * p_msg;
    uint32_t *p_siglen;
    uint8_t * p_sig;

    p_prilen = (uint32_t *)th_buffer_address();
    p_pri    = (uint8_t *)p_prilen + sizeof(uint32_t);
    p_msglen = (uint32_t *)(p_pri + *p_prilen);
    p_msg    = (uint8_t *)p_msglen + sizeof(uint32_t);
    p_siglen = (uint32_t *)(p_msg + *p_msglen);
    p_sig    = (uint8_t *)p_siglen + sizeof(uint32_t);

    ee_rsa(id, func, p_pri, *p_prilen, p_msg, *p_msglen, p_sig, p_siglen, i);

    if (verify)
    {
        ee_printmemline(p_pri, *p_prilen, "m-bench-rsa-pri-");
        ee_printmemline(p_msg, *p_msglen, "m-bench-rsa-msg-");
        ee_printmemline(p_sig, *p_siglen, "m-bench-rsa-sig-");
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
    else if (th_strncmp(p_subcmd, "ecdsa-p256-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(EE_P256R1, EE_ECDSA_SIGN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p256-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(EE_P256R1, EE_ECDSA_VERIFY, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p384-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(EE_P384, EE_ECDSA_SIGN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p384-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(EE_P384, EE_ECDSA_VERIFY, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-ed25519-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(EE_Ed25519, EE_ECDSA_SIGN, n, i, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-ed25519-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(EE_Ed25519, EE_ECDSA_VERIFY, n, i, verify);
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
