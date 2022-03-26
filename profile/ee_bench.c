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
    uint8_t *buffer = NULL;
    uint8_t *key;
    uint8_t *in;
    uint8_t *out;
    uint8_t *iv;
    uint8_t *tag;
    int      ivlen = mode == AES_CTR ? AES_CTR_IVSIZE : AES_AEAD_IVSIZE;

    buffer = th_buffer_address();
    key    = buffer;
    iv     = key + keylen;
    in     = iv + ivlen;
    out    = in + n;
    tag    = out + n;
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
        ee_aes(mode, func, key, keylen, iv, out, n, in, tag, NULL, 0, i);
        if (verify)
        {
            ee_printmem_hex(key, keylen, "m-bench-aesXXX_ecb_dec-key-");
            ee_printmem_hex(iv, ivlen, "m-bench-aesXXX_ecb_dec-iv-");
            ee_printmem_hex(out, n, "m-bench-aesXXX_ecb_dec-in-");
            ee_printmem_hex(in, n, "m-bench-aesXXX_ecb_dec-out-");
            ee_printmem_hex(tag, AES_TAGSIZE, "m-bench-aesXXX_ecb_dec-tag-");
        }
    }
    else
    {
        ee_aes(mode, func, key, keylen, iv, in, n, out, tag, NULL, 0, i);
        if (verify)
        {
            ee_printmem_hex(key, keylen, "m-bench-aesXXX_ecb_enc-key-");
            ee_printmem_hex(iv, ivlen, "m-bench-aesXXX_ecb_enc-iv-");
            ee_printmem_hex(in, n, "m-bench-aesXXX_ecb_enc-in-");
            ee_printmem_hex(out, n, "m-bench-aesXXX_ecb_enc-out-");
            ee_printmem_hex(tag, AES_TAGSIZE, "m-bench-aesXXX_ecb_enc-tag-");
        }
    }
}

void
bench_sha(sha_size_t size, uint_fast32_t n, uint_fast32_t i, bool verify)
{
    uint8_t *p_in;
    uint8_t *p_out;
    char *   hdr1;
    char *   hdr2;
    switch (size)
    {
        case EE_SHA256:
            hdr1 = "m-bench-sha256-in-";
            hdr2 = "m-bench-sha256-hash-";
            break;
        case EE_SHA384:
            hdr1 = "m-bench-sha384-in-";
            hdr2 = "m-bench-sha384-hash-";
            break;
        default:
            th_printf("e-[bench_sha() invalid size parameter]\r\n");
            break;
    }
    p_in  = th_buffer_address();
    p_out = p_in + n;
    for (size_t x = 0; x < n; ++x)
    {
        p_in[x] = ee_rand();
    }
    ee_sha(size, p_in, n, p_out, i);
    if (verify)
    {
        ee_printmem_hex(p_in, n, hdr1);
        ee_printmem_hex(p_out, size / 8, hdr2);
    }
}

void
bench_ecdh(ecdh_group_t g, uint_fast32_t i, bool verify)
{
    uint_fast32_t npub = ee_pub_sz[g];
    uint_fast32_t npri = ee_pri_sz[g];
    uint_fast32_t nsec = ee_sec_sz[g];
    // These must be preloaded to the buffer by the host.
    uint8_t *p_pub;
    uint8_t *p_pri;
    uint8_t *p_sec;
    p_pub = th_buffer_address();
    p_pri = p_pub + npub;
    p_sec = p_pri + npri;
    ee_ecdh(g, p_pub, npub, p_pri, npri, p_sec, nsec, i);
    if (verify)
    {
        ee_printmem_hex(p_pub, npub, "m-bench-ecdhXXX-peer-public-");
        ee_printmem_hex(p_pri, npri, "m-bench-ecdhXXX-own-private-");
        ee_printmem_hex(p_sec, nsec, "m-bench-ecdhXXX-shared-");
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

void
bench_ecdsa(uint_fast32_t i, ecdh_group_t group, bool verify)
{
    // Note: verify, the parameter is not the ECDSA verify, it is the
    //       function verification mode!
    /**
     * ECDSA Sign & Verify a hash
     *
     * Preload buffer with:
     *
     * Value      Size (Bytes)
     * unused     32
     * unused     32
     * d          32 (Private key uncompressed 32-byte)
     * SHA256     32 (SHA256 Digest to sign)
     */
    uint8_t *     p_pri;
    uint8_t *     p_hmac;
    uint8_t *     p_sig;
    uint_fast32_t slen;
    slen  = 256; // Note: this is also an input to ee_ecdsa_sign
    p_sig = (uint8_t *)th_malloc(slen); // should be 71, 72 B
    if (p_sig == NULL)
    {
        th_printf("e-[ECDSA malloc() failed, size %d]\r\n", 256);
        return;
    }
    p_pri  = th_buffer_address() + 64;
    p_hmac = p_pri + ECC_DSIZE;
    ee_ecdsa_sign(group, p_hmac, HMAC_SIZE, p_sig, &slen, p_pri, ECC_DSIZE, i);
    if (verify)
    {
        ee_printmem_hex(p_pri, ECC_DSIZE, "m-bench-ecdsa-sign-own-private-");
        ee_printmem_hex(p_sig, slen, "m-bench-ecdsa-sign-signature-");
        ee_printmem_hex(p_hmac, HMAC_SIZE, "m-bench-ecdsa-sign-hash-");
    }
    // TODO: The verify function is currently not ... verified!!! BUGBUG
    ee_ecdsa_verify(group, p_hmac, HMAC_SIZE, p_sig, slen, p_pri, ECC_DSIZE, i);
    th_free(p_sig);
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
