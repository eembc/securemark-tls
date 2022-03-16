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

#include "ee_aes.h"

// This is an aesthetic decoder for log messages; must match aes_cipher_mode_t
static const char *aes_cipher_mode_text[] = { "ecb", "ctr", "ccm", "gcm" };

// All-purpose AES wrapper for all modes & keysizes.
void
ee_aes(aes_cipher_mode_t mode,   // input: cipher mode
       aes_function_t    func,   // input: func (AES_ENC|AES_DEC)
       const uint8_t *   p_key,  // input: key
       uint_fast32_t     keylen, // input: length of key in bytes
       const uint8_t *   p_iv,   // input: initialization vector
       const uint8_t *   p_in,   // input: pointer to source input (pt or ct)
       uint_fast32_t     len,    // input: length of input in bytes
       uint8_t *         p_out,  // output: pointer to output buffer
       uint8_t *         p_tag,  // inout: output in encrypt, input on decrypt
       const uint8_t *   p_add,  // input: additional authentication data
       uint_fast32_t     addlen, // input: length of AAD in bytes
       uint_fast32_t     iter    // input: # of test iterations
)
{
    void *        p_context; // Generic context if needed by implementation
    uint_fast32_t numblocks; // This wrapper uses fixed-size blocks
    uint_fast32_t i;         // iteration index
    uint_fast32_t j;         // iteration index
    uint_fast16_t bits = keylen * 8;
    const char *  m    = aes_cipher_mode_text[mode];
    ee_status_t   ret;

    numblocks = 0;
    if (mode == AES_ECB)
    {
        if (len < AES_BLOCKLEN)
        {
            th_printf("e-aes%d_%s-[Input must be >=16 bytes]\r\n", bits, m);
            return;
        }
        numblocks = len / AES_BLOCKLEN;
        if (len % AES_BLOCKLEN != 0) // Note: No padding
        {
            th_printf("e-aes%d_%s-[Input must be modulo 16]\r\n", bits, m);
            return;
        }
    }

    if (th_aes_create(&p_context, mode) != EE_STATUS_OK)
    {
        th_printf("e-aes%d_%s-[Failed to create context]\r\n", bits, m);
        return;
    }

    th_printf("m-aes%d_%s-iter-%d\r\n", bits, m, iter);
    th_printf("m-aes%d_%s-message-length-%d\r\n", bits, m, len);

    if (func == AES_ENC)
    {
        th_printf("m-aes%d_%s-encrypt-start\r\n", bits, m);
        th_timestamp();
        th_pre();
        while (iter-- > 0)
        {
            if (th_aes_init(
                    p_context, p_key, keylen, p_iv, AES_ROUNDS, func, mode)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes%d_%s-[Failed to initialize]\r\n", bits, m);
                goto exit;
            }
            switch (mode)
            {
                case AES_ECB:
                    for (i = 0, j = 0; j < numblocks; ++j)
                    {
                        i = j * AES_BLOCKLEN;
                        if (th_aes_ecb_encrypt(
                                p_context, &(p_in[i]), &(p_out[i]))
                            != EE_STATUS_OK)
                        {
                            goto err_enc_exit;
                        }
                    }
                    break;
                case AES_CTR:
                    ret = th_aes_ctr_encrypt(p_context, p_in, len, p_out);
                    break;
                case AES_CCM:
                    ret = th_aes_ccm_encrypt(p_context,
                                             p_add,
                                             addlen,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             AES_TAGSIZE,
                                             p_iv,
                                             AES_AEAD_IVSIZE);
                    break;
                case AES_GCM:
                    ret = th_aes_gcm_encrypt(p_context,
                                             p_add,
                                             addlen,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             AES_TAGSIZE,
                                             p_iv,
                                             AES_AEAD_IVSIZE);
                    break;
                default:
                    th_post();
                    th_printf("e-[Invalid AES enum: %d]\r\n", mode);
                    goto exit;
            }
            if (ret != EE_STATUS_OK)
            {
                goto err_enc_exit;
            }
            th_aes_deinit(p_context, mode);
        }
        th_post();
        th_timestamp();
        th_printf("m-aes%d_%s-encrypt-finish\r\n", bits, m);
    }
    else
    {
        th_printf("m-aes%d_%s-decrypt-start\r\n", bits, m);
        th_timestamp();
        th_pre();
        while (iter-- > 0)
        {
            if (th_aes_init(
                    p_context, p_key, keylen, p_iv, AES_ROUNDS, func, mode)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes%d_%s-[Failed to initialize]\r\n", bits, m);
                goto exit;
            }
            switch (mode)
            {
                case AES_ECB:
                    for (i = 0, j = 0; j < numblocks; ++j)
                    {
                        i = j * AES_BLOCKLEN;
                        if (th_aes_ecb_decrypt(
                                p_context, &(p_in[i]), &(p_out[i]))
                            != EE_STATUS_OK)
                        {
                            goto err_dec_exit;
                        }
                    }
                    break;
                case AES_CTR:
                    ret = th_aes_ctr_decrypt(p_context, p_in, len, p_out);
                    break;
                case AES_CCM:
                    ret = th_aes_ccm_decrypt(p_context,
                                             p_add,
                                             addlen,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             AES_TAGSIZE,
                                             p_iv,
                                             AES_AEAD_IVSIZE);
                    break;
                case AES_GCM:
                    ret = th_aes_gcm_decrypt(p_context,
                                             p_add,
                                             addlen,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             AES_TAGSIZE,
                                             p_iv,
                                             AES_AEAD_IVSIZE);
                    break;
                default:
                    th_post();
                    th_printf("e-[Invalid AES enum: %d]\r\n", mode);
                    goto exit;
            }
            if (ret != EE_STATUS_OK)
            {
                goto err_dec_exit;
            }
            th_aes_deinit(p_context, mode);
        }
        th_post();
        th_timestamp();
        th_printf("m-aes%d_%s-decrypt-finish\r\n", bits, m);
    }
    goto exit;
err_enc_exit:
    th_post();
    th_printf("e-aes%d_%s-[Failed to encrypt]\r\n", bits, m);
    goto exit;
err_dec_exit:
    th_post();
    th_printf("e-aes%d_%s-[Failed to decrypt]\r\n", bits, m);
    goto exit;
exit:
    th_aes_destroy(p_context, mode);
}
