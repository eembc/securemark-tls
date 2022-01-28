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

#if EE_CFG_SELFHOSTED != 1

void
bench_sha256(uint_fast32_t i, uint_fast32_t n, bool verify)
{
    uint8_t *     p_buffer;
    uint_fast32_t buflen;
    uint8_t *     p_in;
    uint8_t *     p_out;
    uint_fast32_t x;
    //       in         out
    buflen   = n + SHA_SIZE;
    p_buffer = (uint8_t *)th_malloc(buflen);
    if (p_buffer == NULL)
    {
        th_printf("e-[SHA256 malloc() failed, size %d]\r\n", buflen);
        return;
    }
    // Assign the helper points to the region of the p_buffer
    p_in  = p_buffer;
    p_out = p_in + n;
    for (x = 0; x < n; ++x)
    {
        p_in[x] = ee_rand();
    }
    ee_sha256(p_buffer, n, p_out, i);
    if (verify)
    {
        ee_printmem_hex(p_in, n, "m-bench-sha256-in-");
        ee_printmem_hex(p_out, SHA_SIZE, "m-bench-sha256-hash-");
    }
    th_free(p_buffer);
}

void
bench_aes128_ecb(uint_fast32_t i, uint_fast32_t n, bool verify)
{

    uint8_t *     p_buffer;
    uint_fast32_t buflen;
    uint8_t *     p_key;
    uint8_t *     p_in;
    uint8_t *     p_out;
    uint_fast32_t x;
    //                key   in  out
    buflen   = AES_KEYSIZE + n + n;
    p_buffer = (uint8_t *)th_malloc(buflen);
    if (p_buffer == NULL)
    {
        th_printf("e-[AES128 ECB malloc() failed, size %d]\r\n", buflen);
        return;
    }
    // Assign the helper points to the region of the buffer
    p_key = p_buffer;
    p_in  = p_key + AES_KEYSIZE;
    p_out = p_in + n;
    for (x = 0; x < AES_KEYSIZE; ++x)
    {
        p_key[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        p_in[x] = ee_rand();
    }
    ee_aes128_ecb(p_key, p_in, n, p_out, AES_ENC, i);
    if (verify)
    {
        ee_printmem_hex(p_key, 16, "m-bench-aes128_ecb_enc-key-");
        ee_printmem_hex(p_in, n, "m-bench-aes128_ecb_enc-in-");
        ee_printmem_hex(p_out, n, "m-bench-aes128_ecb_enc-out-");
    }
    ee_aes128_ecb(p_key, p_out, n, p_in, AES_DEC, i);
    if (verify)
    {
        ee_printmem_hex(p_key, 16, "m-bench-aes128_ecb_dec-key-");
        ee_printmem_hex(p_out, n, "m-bench-aes128_ecb_dec-in-");
        ee_printmem_hex(p_in, n, "m-bench-aes128_ecb_dec-out-");
    }
    th_free(p_buffer);
}

// TODO: What are we doing about AAD and AADLEN?

void
bench_aes128_ccm(uint_fast32_t i, uint_fast32_t n, bool verify)
{
    uint8_t *     p_buffer;
    uint_fast32_t buflen;
    uint8_t *     p_key;
    uint8_t *     p_iv;
    uint8_t *     p_in;
    uint8_t *     p_tag;
    uint8_t *     p_out;
    uint_fast32_t x;
    //                key           iv  in           tag   out
    buflen   = AES_KEYSIZE + AES_IVSIZE + n + AES_TAGSIZE + n;
    p_buffer = (uint8_t *)th_malloc(buflen);
    if (p_buffer == NULL)
    {
        th_printf("e-[AES128 CCM malloc() failed, size %d]\r\n", buflen);
        return;
    }
    // Assign the helper points to the region of the buffer
    p_key = p_buffer;
    p_iv  = p_key + AES_KEYSIZE;
    p_in  = p_iv + AES_IVSIZE;
    p_tag = p_in + n;
    p_out = p_tag + AES_TAGSIZE;
    // Fill the key, iv, and plaintext with random values
    for (x = 0; x < AES_KEYSIZE; ++x)
    {
        p_key[x] = ee_rand();
    }
    for (x = 0; x < AES_IVSIZE; ++x)
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
    ee_aes128_ccm(p_key, NULL, 0, p_iv, p_in, n, p_tag, p_out, AES_ENC, i);
    if (verify)
    {
        ee_printmem_hex(p_key, AES_KEYSIZE, "m-bench-aes128_ccm_enc-key-");
        ee_printmem_hex(p_iv, AES_IVSIZE, "m-bench-aes128_ccm_enc-iv-");
        ee_printmem_hex(p_in, n, "m-bench-aes128_ccm_enc-in-");
        ee_printmem_hex(p_tag, AES_TAGSIZE, "m-bench-aes128_ccm_enc-tag-");
        ee_printmem_hex(p_out, n, "m-bench-aes128_ccm_enc-out-");
    }
    ee_aes128_ccm(p_key, NULL, 0, p_iv, p_out, n, p_tag, p_in, AES_DEC, i);
    if (verify)
    {
        ee_printmem_hex(p_key, AES_KEYSIZE, "m-bench-aes128_ccm_dec-key-");
        ee_printmem_hex(p_iv, AES_IVSIZE, "m-bench-aes128_ccm_dec-iv-");
        ee_printmem_hex(p_out, n, "m-bench-aes128_ccm_dec-in-");
        ee_printmem_hex(p_tag, AES_TAGSIZE, "m-bench-aes128_ccm_dec-tag-");
        ee_printmem_hex(p_in, n, "m-bench-aes128_ccm_dec-out-");
    }
    th_free(p_buffer);
}

void
bench_aes128_gcm(uint_fast32_t i, uint_fast32_t n, bool verify)
{
    uint8_t *     p_buffer;
    uint_fast32_t buflen;
    uint8_t *     p_key;
    uint8_t *     p_iv;
    uint8_t *     p_in;
    uint8_t *     p_tag;
    uint8_t *     p_out;
    uint_fast32_t x;
    //                key           iv  in           tag   out
    buflen   = AES_KEYSIZE + AES_IVSIZE + n + AES_TAGSIZE + n;
    p_buffer = (uint8_t *)th_malloc(buflen);
    if (p_buffer == NULL)
    {
        th_printf("e-[AES128 GCM malloc() failed, size %d]\r\n", buflen);
        return;
    }
    // Assign the helper points to the region of the buffer
    p_key = p_buffer;
    p_iv  = p_key + AES_KEYSIZE;
    p_in  = p_iv + AES_IVSIZE;
    p_tag = p_in + n;
    p_out = p_tag + AES_TAGSIZE;
    // Fill the key, iv, and plaintext with random values
    for (x = 0; x < AES_KEYSIZE; ++x)
    {
        p_key[x] = ee_rand();
    }
    for (x = 0; x < AES_IVSIZE; ++x)
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
    ee_aes128_gcm(p_key, NULL, 0, p_iv, p_in, n, p_tag, p_out, AES_ENC, i);
    if (verify)
    {
        ee_printmem_hex(p_key, AES_KEYSIZE, "m-bench-aes128_gcm_enc-key-");
        ee_printmem_hex(p_iv, AES_IVSIZE, "m-bench-aes128_gcm_enc-iv-");
        ee_printmem_hex(p_in, n, "m-bench-aes128_gcm_enc-in-");
        ee_printmem_hex(p_tag, AES_TAGSIZE, "m-bench-aes128_gcm_enc-tag-");
        ee_printmem_hex(p_out, n, "m-bench-aes128_gcm_enc-out-");
    }
    ee_aes128_gcm(p_key, NULL, 0, p_iv, p_out, n, p_tag, p_in, AES_DEC, i);
    if (verify)
    {
        ee_printmem_hex(p_key, AES_KEYSIZE, "m-bench-aes128_gcm_dec-key-");
        ee_printmem_hex(p_iv, AES_IVSIZE, "m-bench-aes128_gcm_dec-iv-");
        ee_printmem_hex(p_out, n, "m-bench-aes128_gcm_dec-in-");
        ee_printmem_hex(p_tag, AES_TAGSIZE, "m-bench-aes128_gcm_dec-tag-");
        ee_printmem_hex(p_in, n, "m-bench-aes128_gcm_dec-out-");
    }
    th_free(p_buffer);
}

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
 * Note: For all ECC functions, understand the following:
 *
 * We require the ability to send our own key to the ECC functions to
 * prevent cheating the test. Some APIs make it very difficult to
 * provide our own secret, but they do offer a way to load keys. So,
 * we use the generic th_buffer to load the keys using buffer-add
 * commands on the host.
 *
 * The th_buffer MUST be preloaded with the following values.
 *
 * Value      Size (Bytes)
 * Q.X        32 (Peer public key uncompressed 32-byte X valid coord)
 * Q.Y        32 (Peer public key uncompressed 32-byte Y valid coord)
 * d          32 (Private key uncompressed 32-byte)
 * SHA256     32 (SHA256 Digest to sign)
 */

void
bench_ecdh(uint_fast32_t i, ecdh_group_t group, bool verify)
{
    /**
     * ECDH Key mixing
     *
     * Preload buffer with:
     *
     * Value      Size (Bytes)
     * Q.X        32 (Peer public key uncompressed 32-byte X valid coord)
     * Q.Y        32 (Peer public key uncompressed 32-byte Y valid coord)
     * d          32 (Private key uncompressed 32-byte)
     */
    uint8_t *p_pub;
    uint8_t *p_pri;
    uint8_t  p_shared[ECDH_SIZE]; // don't blow away the th_buffer!
    // These were preloaded
    p_pub = th_buffer_address();
    p_pri = p_pub + ECC_QSIZE;
    ee_ecdh(p_pub, group, ECC_QSIZE, p_pri, ECC_DSIZE, p_shared, ECDH_SIZE, i);
    if (verify)
    {
        ee_printmem_hex(p_pub, 64, "m-bench-ecdh-peer-public-");
        ee_printmem_hex(p_pri, 32, "m-bench-ecdh-own-private-");
        ee_printmem_hex(p_shared, 32, "m-bench-ecdh-shared-");
    }
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

#endif /* EE_CFG_SELFHOSTED */
