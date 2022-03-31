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

extern bool g_verify_mode;

/**
 * @brief Helper function to copy a number of pseudo-random octets to a buffer.
 *
 * @param p_buffer Destination buffer.
 * @param len Number of octets.
 */
static void
fill_rand(uint8_t *p_buffer, size_t len)
{
    // We create random data here because it saves Host-to-DUT download time.
    for (size_t x = 0; x < len; ++x)
    {
        p_buffer[x] = ee_rand();
    }
}

void
ee_bench_aes(ee_aes_mode_t mode,   // input: cipher mode
          ee_aes_func_t    func,   // input: func (AES_ENC|EE_AES_DEC)
          uint_fast32_t     keylen, // input: length of key in bytes
          uint_fast32_t     n,      // input: length of input in bytes
          uint_fast32_t     i,      // input: # of test iterations
          bool              verify)
{
    int      ivlen = mode == EE_AES_CTR ? EE_AES_CTR_IVLEN : EE_AES_AEAD_IVLEN;
    uint8_t *p_key = th_buffer_address();
    uint8_t *p_iv  = p_key + keylen;
    uint8_t *p_in  = p_iv + ivlen;
    uint8_t *p_out = p_in + n;
    uint8_t *p_tag = p_out + n;

    // We create random data here because it saves Host-to-DUT download time.
    fill_rand(p_key, keylen);
    fill_rand(p_iv, ivlen);
    fill_rand(p_in, n);

    if (func == EE_AES_DEC)
    {
        // Encrypt something for the decrypt loop to decrypt
        g_verify_mode = true;
        ee_aes(mode,
               EE_AES_ENC,
               p_key,
               keylen,
               p_iv,
               p_in,
               n,
               p_out,
               p_tag,
               NULL,
               0,
               1);
        g_verify_mode = false;
        th_memcpy(p_in, p_out, n);
        uint8_t *tmp = p_in;
        p_in         = p_out;
        p_out        = tmp;
    }
    ee_aes(mode, func, p_key, keylen, p_iv, p_in, n, p_out, p_tag, NULL, 0, i);
    if (verify)
    {
        ee_printmem_hex(p_key, keylen, "m-bench-aesXXX-key-");
        ee_printmem_hex(p_iv, ivlen, "m-bench-aesXXX-iv-");
        ee_printmem_hex(p_in, n, "m-bench-aesXXX-in-");
        ee_printmem_hex(p_out, n, "m-bench-aesXXX-out-");
        ee_printmem_hex(p_tag, EE_AES_TAGLEN, "m-bench-aesXXX-tag-");
    }
}

void
ee_bench_sha(ee_sha_size_t size, uint_fast32_t n, uint_fast32_t i, bool verify)
{
    uint8_t *p_in  = th_buffer_address();
    uint8_t *p_out = p_in + n;

    // We create random data here because it saves Host-to-DUT download time.
    for (size_t x = 0; x < n; ++x)
    {
        p_in[x] = ee_rand();
    }

    ee_sha(size, p_in, n, p_out, i);

    if (verify)
    {
        ee_printmem_hex(p_in, n, "m-bench-sha-in");
        ee_printmem_hex(p_out, size / 8, "m-bench-sha-out");
    }
}

void
ee_bench_ecdh(ee_ecdh_group_t g, uint_fast32_t i, bool verify)
{
    uint_fast32_t npub = ee_pub_sz[g];
    uint_fast32_t npri = ee_pri_sz[g];
    uint_fast32_t nsec = ee_sec_sz[g];

    // The th_buffer has been pre-loaded with this data
    uint8_t *p_pub = th_buffer_address();
    uint8_t *p_pri = p_pub + npub;
    uint8_t *p_sec = p_pri + npri;

    ee_ecdh(g, p_pub, npub, p_pri, npri, p_sec, nsec, i);

    if (verify)
    {
        ee_printmem_hex(p_pub, npub, "m-bench-ecdhXXX-peer-public-");
        ee_printmem_hex(p_pri, npri, "m-bench-ecdhXXX-own-private-");
        ee_printmem_hex(p_sec, nsec, "m-bench-ecdhXXX-shared-");
    }
}

void
ee_bench_ecdsa(ee_ecdh_group_t     g,
            ee_ecdsa_func_t func,
            uint_fast32_t    n,
            uint_fast32_t    i,
            bool             verify)
{
    // The th_buffer has been pre-loaded with this data
    uint8_t *     p_pri = th_buffer_address();
    uint_fast32_t npri  = ee_pri_sz[g];
    uint8_t *     p_msg = p_pri + npri;
    uint8_t *     p_sig = p_msg + n;
    uint_fast32_t slen;

    if (func == EE_ECDSA_VERIFY)
    {
        if (g == EE_Ed25519)
        {
            // Ed25519 signatures are raw {R|S} little endian
            slen = 64;
        }
        else
        {
            // EcDSA signatures are ASN.1, and are < 256 bytes for our case.
            slen = p_sig[1] + 2;
        }
    }
    else
    {
        // Provide max size as entire remaining buffer on sign
        slen = th_buffer_size() - (p_sig - p_pri) - 1;
    }

    ee_ecdsa(g, func, p_msg, n, p_sig, &slen, p_pri, npri, i);

    if (verify)
    {
        ee_printmem_hex(p_pri, npri, "m-bench-ecdsaXXX-private-");
        ee_printmem_hex(p_msg, n, "m-bench-ecdsaXXX-msg-");
        ee_printmem_hex(p_sig, slen, "m-bench-ecdsaXXX-sig-");
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

    // We create random data here because it saves Host-to-DUT download time.
    fill_rand(p_key, EE_CHACHAPOLY_KEYLEN);
    fill_rand(p_iv, EE_CHACHAPOLY_IVLEN);
    fill_rand(p_in, n);

    if (func == EE_CHACHAPOLY_DEC)
    {
        // Encrypt something for the decrypt loop to decrypt
        g_verify_mode = true;
        ee_chachapoly(
            EE_CHACHAPOLY_ENC, p_key, NULL, 0, p_iv, p_in, n, p_tag, p_out, 1);
        g_verify_mode = false;
        th_memcpy(p_in, p_out, n);
        uint8_t *tmp = p_in;
        p_in         = p_out;
        p_out        = tmp;
    }

    ee_chachapoly(func, p_key, NULL, 0, p_iv, p_in, n, p_tag, p_out, i);

    if (verify)
    {
        ee_printmem_hex(
            p_key, EE_CHACHAPOLY_KEYLEN, "m-bench-chachapoly-key-");
        ee_printmem_hex(p_iv, EE_CHACHAPOLY_IVLEN, "m-bench-chachapoly-iv-");
        ee_printmem_hex(p_in, n, "m-bench-chachapoly-in-");
        ee_printmem_hex(p_out, n, "m-bench-chachapoly-out-");
        ee_printmem_hex(p_tag, EE_AES_TAGLEN, "m-bench-chachapoly-tag-");
    }
}

/*
    private key length - 4 bytes, sizeof the pre-computed key in keys.h
    private key        - ASN.1 quintuple
    message length     - 4 bytes
    message            - n bytes
    signature length   - 4 bytes
    signature           - signature length bytes
*/

void
ee_bench_rsa(ee_rsa_id_t       id,
          ee_rsa_function_t func,
          unsigned int      n,
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
        ee_printmem_hex(p_pri, *p_prilen, "m-bench-rsa-pri-");
        ee_printmem_hex(p_msg, *p_msglen, "m-bench-rsa-msg-");
        ee_printmem_hex(p_sig, *p_siglen, "m-bench-rsa-sig-");
    }
}

#if 0

/**
 * Route the 'bench' commands (see the help text in the main parser).
 *
 * bench-KERNELNAME-SRAND-ITERATIONS[-NUMBYTES]
 *
 */
arg_claimed_t
ee_bench_parse(char *p_command, bool verify)
{
    char *        p_subcmd; // Subcommand
    char *        p_seed;   // srand() seed.
    char *        p_iter;   // Requested iterations
    char *        p_size;   // Requested size of dataset in bytes
    uint_fast32_t i;        // iterations
    uint_fast32_t n;        // data size in bytes
    if (th_strncmp(p_command, "bench", EE_CMD_SIZE) != 0)
    {
        return EE_ARG_UNCLAIMED;
    }
    /**
     * Each subcommand takes four paramters:
     *
     * subcmd : the name of the primitive to benchmark
     * seed   : the decimal positive integer seed
     * iter   : the decimal positive integer iteration count
     * size   : the number of bytes in the input dataset
     */
    p_subcmd = th_strtok(NULL, EE_CMD_DELIMITER);
    p_seed   = th_strtok(NULL, EE_CMD_DELIMITER);
    p_iter   = th_strtok(NULL, EE_CMD_DELIMITER);
    p_size   = th_strtok(NULL, EE_CMD_DELIMITER);
    // Test existence of subcommand
    if (p_subcmd == NULL)
    {
        th_printf("e-[Command 'bench' takes a subcommand]\r\n");
        return EE_ARG_CLAIMED;
    }
    // Validated the seed
    if (p_seed != NULL)
    {
        ee_srand((uint8_t)th_atoi(p_seed));
    }
    else
    {
        th_printf("e-[Benchmark seed not specified]\r\n");
        return EE_ARG_CLAIMED;
    }
    // Validate iterations
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

    // Validate datasize
    if (p_size)
    {
        n = (uint_fast32_t)th_atoi(p_size);
    }
    else
    {
        // TODO: Is it OK for datasize to be zero?
        // The only function that doesn't use it is ECDH AFAIK
        n = 0;
    }

    // Now figure out which subcommand was issued...

    if (th_strncmp(p_subcmd, "sha256", EE_CMD_SIZE) == 0)
    {
        bench_sha256(i, n, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128_ecb", EE_CMD_SIZE) == 0)
    {
        bench_aes128_ecb(i, n, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128_ccm", EE_CMD_SIZE) == 0)
    {
        bench_aes128_ccm(i, n, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128_gcm", EE_CMD_SIZE) == 0)
    {
        bench_aes128_gcm(i, n, verify);
    }
    else if (th_strncmp(p_subcmd, "chachapoly", EE_CMD_SIZE) == 0)
    {
        ee_bench_chachapoly(i, n, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdh256", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(i, EE_P256R1, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdh25519", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(i, EE_C25519, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa256", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(i, EE_P256R1, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa25519", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa(i, EE_C25519, verify);
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

#endif // 0
