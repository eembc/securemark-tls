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

#include "ee_variations.h"

// A macro to make the code easier to read
#define CHECK(x)               \
    {                          \
        if (x != EE_STATUS_OK) \
        {                      \
            goto error_exit;   \
        }                      \
    }
// profile/ee_profile.c
uint8_t ee_rand(void);

/**
 * For tests where expliclty calling the primitive's wrapper benchmark
 * function is insufficient, these "variations" serve as more sophisticated
 * scenarios.
 */

/**
 * Variation #001 interleaves two AES and two SHA contexts similar to what
 * we see in the TLS handshake. This function does not need validation since
 * the primitives are validated through the host UI.
 */
#define VAR001_SESSION_SIZE 1495
#define VAR001_AES_SIZE     16
void
ee_variation_001(uint_fast32_t iterations)
{
    void *        p_csha1 = NULL;          // SHA context 1
    void *        p_csha2 = NULL;          // SHA context 2
    void *        p_caes  = NULL;          // AES context
    uint8_t *     p_msg;                   // All bytes to hash
    uint8_t *     p_buf1;                  // SHA1's buffer
    uint8_t *     p_buf2;                  // SHA2's buffer
    uint8_t       p_digest[EE_SHA256 / 8]; // SHA digest
    uint8_t       p_pt[VAR001_AES_SIZE];   // AES plaintext
    uint8_t       p_ct[VAR001_AES_SIZE];   // AES ciphertext
    uint8_t       p_key[16];               // AES key, forcing AES128
    uint_fast32_t idx;                     // Loop index

    // Total number of bytes in the TLS handshake session-hash
    p_msg = (uint8_t *)th_malloc(VAR001_SESSION_SIZE);
    if (p_msg == NULL)
    {
        th_printf("e-variation-001-[malloc() fail]\r\n");
        return;
    }

    /**
     * Fill the input data with random bits since free memory tends to be 0x00
     * and toggle pattern does impact power.
     */
    for (idx = 0; idx < VAR001_SESSION_SIZE; ++idx)
    {
        p_msg[idx] = ee_rand();
        if (idx < 16)
        {
            p_key[idx] = ee_rand();
        }
        if (idx < VAR001_AES_SIZE)
        {
            p_pt[idx] = ee_rand();
        }
    }

    th_printf("m-variation-001-start\r\n");
    th_timestamp();
    th_pre();
    while (iterations-- > 0)
    {
        p_buf1 = p_msg; // p_buf1 creeps through the p_msg data
        p_buf2 = p_msg; // p_buf2 never moves, but use a diff name for clarity

        CHECK(th_sha_create(&p_csha1, EE_SHA256));
        CHECK(th_sha_init(p_csha1, EE_SHA256));

        // NOTE: All of these "magic numbers" are based on handshake analysis

        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 115));
        p_buf1 += 115;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 91));
        p_buf1 += 91;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 425));
        p_buf1 += 425;

        CHECK(th_sha_create(&p_csha2, EE_SHA256));
        CHECK(th_sha_init(p_csha2, EE_SHA256));
        CHECK(th_sha_process(p_csha2, EE_SHA256, p_buf2, 384));
        CHECK(th_sha_done(p_csha2, EE_SHA256, p_digest));
        th_sha_destroy(p_csha2, EE_SHA256);

        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 149));
        p_buf1 += 149;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 109));
        p_buf1 += 109;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 4));
        p_buf1 += 4;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 422));
        p_buf1 += 422;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 70));
        p_buf1 += 70;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 78));
        p_buf1 += 78;

        CHECK(th_aes_create(&p_caes, AES_ECB));
        CHECK(
            th_aes_init(p_caes, p_key, 16, NULL, AES_ROUNDS, AES_ENC, AES_ECB));
        CHECK(th_aes_ecb_encrypt(p_caes, p_pt, p_ct));
        th_aes_destroy(p_caes, AES_ECB);

        CHECK(th_aes_create(&p_caes, AES_ECB));
        CHECK(
            th_aes_init(p_caes, p_key, 16, NULL, AES_ROUNDS, AES_ENC, AES_ECB));
        CHECK(th_aes_ecb_encrypt(p_caes, p_pt, p_ct));
        th_aes_destroy(p_caes, AES_ECB);

        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 16));
        p_buf1 += 16;
        CHECK(th_sha_process(p_csha1, EE_SHA256, p_buf1, 16));
        p_buf1 += 16;

        CHECK(th_aes_create(&p_caes, AES_ECB));
        CHECK(
            th_aes_init(p_caes, p_key, 16, NULL, AES_ROUNDS, AES_ENC, AES_ECB));
        CHECK(th_aes_ecb_encrypt(p_caes, p_pt, p_ct));
        th_aes_destroy(p_caes, AES_ECB);

        CHECK(th_sha_done(p_csha1, EE_SHA256, p_digest));
        th_sha_destroy(p_csha1, EE_SHA256);
    }
    th_post();
    th_timestamp();
    goto exit;

error_exit:
    th_post();
    // TODO: Hard to be more descriptive here.
    th_printf("e-variation-001\r\n");
    // These are NULL safe
    th_aes_destroy(p_caes, AES_ECB);
    th_sha_destroy(p_csha1, EE_SHA256);
    th_sha_destroy(p_csha2, EE_SHA256);

exit:
    th_free(p_msg);
    th_printf("m-variation-001-finish\r\n");
}
