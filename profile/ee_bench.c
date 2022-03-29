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

void
bench_aes(aes_cipher_mode_t mode,   // input: cipher mode
          aes_function_t    func,   // input: func (AES_ENC|AES_DEC)
          uint_fast32_t     keylen, // input: length of key in bytes
          uint_fast32_t     n,      // input: length of input in bytes
          uint_fast32_t     i,      // input: # of test iterations
          bool              verify)
{
    int      ivlen  = mode == AES_CTR ? AES_CTR_IVSIZE : AES_AEAD_IVSIZE;
    uint8_t *buffer = th_buffer_address();
    uint8_t *key    = buffer;
    uint8_t *iv     = key + keylen;
    uint8_t *in     = iv + ivlen;
    uint8_t *out    = in + n;
    uint8_t *tag    = out + n;

    // We create random data here because it saves Host-to-DUT download time.
    for (size_t x = 0; x < keylen; ++x)
    {
        key[x] = ee_rand();
    }
    for (size_t x = 0; x < ivlen; ++x)
    {
        iv[x] = ee_rand();
    }
    for (size_t x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    if (func == AES_DEC)
    {
        // Encrypt something for the decrypt loop to decrypt
        ee_aes(mode, AES_ENC, key, keylen, iv, in, n, out, tag, NULL, 0, 1);
        th_memcpy(in, out, n);
        //ee_aes(mode, func, key, keylen, iv, out, n, in, tag, NULL, 0, i);
        uint8_t *tmp = in;
        in = out;
        out = tmp;
    }
    //else
    //{
        ee_aes(mode, func, key, keylen, iv, in, n, out, tag, NULL, 0, i);
    //}
    if (verify)
    {
        ee_printmem_hex(key, keylen, "m-bench-aesXXX-key-");
        ee_printmem_hex(iv, ivlen, "m-bench-aesXXX-iv-");
        ee_printmem_hex(in, n, "m-bench-aesXXX-in-");
        ee_printmem_hex(out, n, "m-bench-aesXXX-out-");
        ee_printmem_hex(tag, AES_TAGSIZE, "m-bench-aesXXX-tag-");
    }
}

void
bench_sha(sha_size_t size, uint_fast32_t n, uint_fast32_t i, bool verify)
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
bench_ecdh(ecdh_group_t g, uint_fast32_t i, bool verify)
{
    uint_fast32_t npub = ee_pub_sz[g];
    uint_fast32_t npri = ee_pri_sz[g];
    uint_fast32_t nsec = ee_sec_sz[g];

    // These must be preloaded to the buffer by the host.
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
bench_ecdsa(ecdh_group_t     g,
            ecdsa_function_t func,
            uint_fast32_t    n,
            uint_fast32_t    i,
            bool             verify)
{
    // These must be preloaded to the buffer by the host.
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

#if 0

void
bench_chachapoly(uint_fast32_t i, uint_fast32_t n, bool verify)
{
    uint8_t *     p_buffer;
    uint_fast32_t buflen;
    uint8_t *     p_key;
    uint8_t *     p_iv;
    uint8_t *     p_in;
    uint8_t *     p_tag;
    uint8_t *     p_out;
    uint_fast32_t x;
    //                      key                  iv  in                tag   out
    buflen
        = CHACHAPOLY_KEYSIZE + CHACHAPOLY_IVSIZE + n + CHACHAPOLY_TAGSIZE + n;
    p_buffer = (uint8_t *)th_malloc(buflen);
    if (p_buffer == NULL)
    {
        th_printf("e-[AES128 GCM malloc() failed, size %d]\r\n", buflen);
        return;
    }
    // Assign the helper points to the region of the buffer
    p_key = p_buffer;
    p_iv  = p_key + CHACHAPOLY_KEYSIZE;
    p_in  = p_iv + CHACHAPOLY_IVSIZE;
    p_tag = p_in + n;
    p_out = p_tag + CHACHAPOLY_TAGSIZE;
    // Fill the key, iv, and plaintext with random values
    for (x = 0; x < CHACHAPOLY_KEYSIZE; ++x)
    {
        p_key[x] = ee_rand();
    }
    for (x = 0; x < CHACHAPOLY_IVSIZE; ++x)
    {
        p_iv[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        p_in[x] = ee_rand();
    }
    /**
     * We provide decryption in this conditional because it requires
     * a proper tag, and having the user supply this with buffer-add
     * commands becomes very painful, so let the prim do it for us.
     */
    ee_chachapoly(
        p_key, NULL, 0, p_iv, p_in, n, p_tag, p_out, CHACHAPOLY_ENC, i);
    if (verify)
    {
        ee_printmem_hex(
            p_key, CHACHAPOLY_KEYSIZE, "m-bench-chachapoly_enc-key-");
        ee_printmem_hex(p_iv, CHACHAPOLY_IVSIZE, "m-bench-chachapoly_enc-iv-");
        ee_printmem_hex(p_in, n, "m-bench-chachapoly_enc-in-");
        ee_printmem_hex(
            p_tag, CHACHAPOLY_TAGSIZE, "m-bench-chachapoly_enc-tag-");
        ee_printmem_hex(p_out, n, "m-bench-chachapoly_enc-out-");
    }
    ee_chachapoly(
        p_key, NULL, 0, p_iv, p_out, n, p_tag, p_in, CHACHAPOLY_DEC, i);
    if (verify)
    {
        ee_printmem_hex(
            p_key, CHACHAPOLY_KEYSIZE, "m-bench-chachapoly_dec-key-");
        ee_printmem_hex(p_iv, CHACHAPOLY_IVSIZE, "m-bench-chachapoly_dec-iv-");
        ee_printmem_hex(p_out, n, "m-bench-chachapoly_dec-in-");
        ee_printmem_hex(
            p_tag, CHACHAPOLY_TAGSIZE, "m-bench-chachapoly_dec-tag-");
        ee_printmem_hex(p_in, n, "m-bench-chachapoly_dec-out-");
    }
    th_free(p_buffer);
}

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
        bench_chachapoly(i, n, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdh256", EE_CMD_SIZE) == 0)
    {
        bench_ecdh(i, EE_P256R1, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdh25519", EE_CMD_SIZE) == 0)
    {
        bench_ecdh(i, EE_C25519, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa256", EE_CMD_SIZE) == 0)
    {
        bench_ecdsa(i, EE_P256R1, verify);
    }
    else if (th_strncmp(p_subcmd, "ecdsa25519", EE_CMD_SIZE) == 0)
    {
        bench_ecdsa(i, EE_C25519, verify);
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
