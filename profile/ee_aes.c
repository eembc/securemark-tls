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

/* This is an aesthetic decoder for log messages; must match ee_aes_mode_t */
static const char *aes_cipher_mode_text[] = { "ecb", "ctr", "ccm", "gcm" };

void
ee_aes(ee_aes_mode_t  mode,
       ee_aes_func_t  func,
       const uint8_t *p_key,
       uint_fast32_t  keylen,
       const uint8_t *p_iv,
       const uint8_t *p_in,
       uint_fast32_t  len,
       uint8_t *      p_out,
       uint8_t *      p_tag,
       uint_fast32_t  iter)
{
    void *        p_context;
    uint_fast32_t numblocks;
    uint_fast32_t i;
    uint_fast32_t j;
    uint_fast16_t bits = keylen * 8;
    const char *  m    = aes_cipher_mode_text[mode];
    ee_status_t   ret;

    numblocks = 0;
    if (mode == EE_AES_ECB)
    {
        if (len < EE_AES_BLOCKLEN)
        {
            th_printf("e-aes%d_%s-[Input must be >=16 bytes]\r\n", bits, m);
            return;
        }
        numblocks = len / EE_AES_BLOCKLEN;
        if (len % EE_AES_BLOCKLEN != 0)
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

    if (func == EE_AES_ENC)
    {
        th_printf("m-aes%d_%s-encrypt-start\r\n", bits, m);
        th_timestamp();
        th_pre();
        while (iter-- > 0)
        {
            if (th_aes_init(p_context, p_key, keylen, p_iv, func, mode)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes%d_%s-[Failed to initialize]\r\n", bits, m);
                goto exit;
            }
            switch (mode)
            {
                case EE_AES_ECB:
                    for (i = 0, j = 0; j < numblocks; ++j)
                    {
                        i = j * EE_AES_BLOCKLEN;
                        if (th_aes_ecb_encrypt(
                                p_context, &(p_in[i]), &(p_out[i]))
                            != EE_STATUS_OK)
                        {
                            goto err_enc_exit;
                        }
                    }
                    break;
                case EE_AES_CTR:
                    ret = th_aes_ctr_encrypt(p_context, p_in, len, p_out);
                    break;
                case EE_AES_CCM:
                    ret = th_aes_ccm_encrypt(p_context,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             EE_AES_TAGLEN,
                                             p_iv,
                                             EE_AES_AEAD_IVLEN);
                    break;
                case EE_AES_GCM:
                    ret = th_aes_gcm_encrypt(p_context,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             EE_AES_TAGLEN,
                                             p_iv,
                                             EE_AES_AEAD_IVLEN);
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
            if (th_aes_init(p_context, p_key, keylen, p_iv, func, mode)
                != EE_STATUS_OK)
            {
                th_post();
                th_printf("e-aes%d_%s-[Failed to initialize]\r\n", bits, m);
                goto exit;
            }
            switch (mode)
            {
                case EE_AES_ECB:
                    for (i = 0, j = 0; j < numblocks; ++j)
                    {
                        i = j * EE_AES_BLOCKLEN;
                        if (th_aes_ecb_decrypt(
                                p_context, &(p_in[i]), &(p_out[i]))
                            != EE_STATUS_OK)
                        {
                            goto err_dec_exit;
                        }
                    }
                    break;
                case EE_AES_CTR:
                    ret = th_aes_ctr_decrypt(p_context, p_in, len, p_out);
                    break;
                case EE_AES_CCM:
                    ret = th_aes_ccm_decrypt(p_context,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             EE_AES_TAGLEN,
                                             p_iv,
                                             EE_AES_AEAD_IVLEN);
                    break;
                case EE_AES_GCM:
                    ret = th_aes_gcm_decrypt(p_context,
                                             p_in,
                                             len,
                                             p_out,
                                             p_tag,
                                             EE_AES_TAGLEN,
                                             p_iv,
                                             EE_AES_AEAD_IVLEN);
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
    th_aes_destroy(p_context);
}
