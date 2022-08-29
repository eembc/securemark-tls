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

void fill_rand(uint8_t *, size_t);
/* These are to make the verification messages more clear. */
static char *ee_ecdh_group_names[] = { "p256r1", "p384", "c25519", "ed25519" };

uint32_t
ee_bench_sha(ee_sha_size_t size, uint32_t i, bool verify)
{
    uint32_t *p32;            /* Helper construction pointer */
    uint8_t * p8;             /* Helper construction pointer */
    void *    p_message_list; /* A pointer to the message list */
    uint32_t  count;          /* The number of messages to hash */
    uint32_t  length;         /* The length of each message */
    uint32_t  dt;             /* Runtime in microseconds */
    size_t    x;              /* Generic loop index */

    /* Extract data from the scratchpad, and fixup endian */
    p32 = (uint32_t *)th_buffer_address();
    /* Host endian does not always match target endian */
    count          = EE_FIX_ENDIAN(*p32++);
    /* Save where we are as the start of the message list */
    p_message_list = (void *)p32;
    /* Host endian does not always match target endian, fix it here */
    for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
    {
        length = EE_FIX_ENDIAN(*p32);
        *p32++ = length;
        p8     = ((uint8_t *)p32 + length);
        p32    = (uint32_t *)p8;
    }
    /* Run the number of iterations */
    dt = ee_sha(size, count, p_message_list, i);
    /* Print verification messages used by the host for proof-of-work */
    if (verify)
    {
        for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
        {
            length = *p32++;
            p8     = (uint8_t *)p32;
            ee_printmemline(p8, length, "m-bench-sha-msg-");
            p8 += length;
            p32 = (uint32_t *)p8;
        }
        ee_printmemline(p8, size / 8, "m-bench-sha-out-");
    }
    return dt;
}

uint32_t
ee_bench_aes(ee_aes_mode_t mode, ee_aes_func_t func, uint32_t iter, bool verify)
{
    uint32_t *p32;            /* Helper construction pointer */
    uint8_t * p8;             /* Helper construction pointer */
    uint32_t  keylen;         /* Key length from the host */
    uint32_t  ivlen;          /* IV length from the host */
    uint8_t * p_key;          /* Pointer to the key */
    uint8_t * p_iv;           /* Pointer to the IV */
    void *    p_message_list; /* A pointer to the message list */
    uint32_t  count;          /* The number of messages to en{de}crypt */
    uint32_t  length;         /* The length of each message */
    uint32_t  dt;             /* Runtime in microseconds */
    size_t    x;              /* Generic loop index */

    /* Set up the scratchpad buffer values */
    p32 = (uint32_t *)th_buffer_address();
    /* Host endian does not always match target endian */
    keylen = EE_FIX_ENDIAN(*p32++);
    ivlen  = EE_FIX_ENDIAN(*p32++);
    count  = EE_FIX_ENDIAN(*p32++);
    /* Switch to a byte pointer for the key and IV pointers */
    p8    = (uint8_t *)p32;
    p_key = p8;
    p8 += keylen;
    p_iv = p8;
    p8 += ivlen;
    /* Switch back to a 32-bit pointer for setting up the message list */
    p32 = (uint32_t *)p8;
    /* Save where we are as the start of the message list */
    p_message_list = (void *)p32;
    /* Host endian does not always match target endian, fix it here */
    for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
    {
        /* Host endian does not always match target endian, fix it here */
        length = EE_FIX_ENDIAN(*p32);
        *p32++ = length;
        p8     = (uint8_t *)p32;
        /* Skip to next operation block (input + output + tag) */
        p8 += length + length + EE_AES_TAGLEN;
        p32 = (uint32_t *)p8;
    }
    /* If decrypting, encrypt something for the decrypt loop to decrypt */
    if (func == EE_AES_DEC)
    {
        /* Don't confuse the host with bogus timestamps! */
        g_mute_timestamps = true;
        ee_aes(mode, EE_AES_ENC, p_key, keylen, p_iv, count, p_message_list, 1);
        g_mute_timestamps = false;
        /* Now swap all the encrypted outputs to the input space. */
        for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
        {
            length = *p32++;
            p8     = (uint8_t *)p32;
            th_memcpy(p8, p8 + length, length);
            p8 += length + length + EE_AES_TAGLEN;
            p32 = (uint32_t *)p8;
        }
    }
    /* Run the number of iterations */
    dt = ee_aes(mode, func, p_key, keylen, p_iv, count, p_message_list, iter);
    /* Print verification messages used by the host for proof-of-work */
    if (verify)
    {
        for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
        {
            length = *p32++;
            p8     = (uint8_t *)p32;
            /* Not all of these are used (ECB, CCM), but print them anyway. */
            ee_printmemline(p_key, keylen, "m-bench-aes-key-");
            ee_printmemline(p_iv, ivlen, "m-bench-aes-iv-");
            ee_printmemline(p8, length, "m-bench-aes-in-");
            p8 += length;
            ee_printmemline(p8, length, "m-bench-aes-out-");
            p8 += length;
            ee_printmemline(p8, EE_AES_TAGLEN, "m-bench-aes-tag-");
            p8 += EE_AES_TAGLEN;
            p32 = (uint32_t *)p8;
        }
    }
    return dt;
}

uint32_t
ee_bench_chachapoly(ee_chachapoly_func_t func, uint32_t iter, bool verify)
{
    uint32_t *p32;            /* Helper construction pointer */
    uint8_t * p8;             /* Helper construction pointer */
    uint32_t  keylen;         /* Key length from the host */
    uint32_t  ivlen;          /* IV length from the host */
    uint8_t * p_key;          /* Pointer to the key */
    uint8_t * p_iv;           /* Pointer to the IV */
    void *    p_message_list; /* A pointer to the message list */
    uint32_t  count;          /* The number of messages to en{de}crypt */
    uint32_t  length;         /* The length of each message */
    uint32_t  dt;             /* Runtime in microseconds */
    size_t    x;              /* Generic loop index */

    /* Set up the scratchpad buffer values */
    p32 = (uint32_t *)th_buffer_address();
    /* Host endian does not always match target endian */
    keylen = EE_FIX_ENDIAN(*p32++);
    ivlen  = EE_FIX_ENDIAN(*p32++);
    count  = EE_FIX_ENDIAN(*p32++);
    /* Switch to a byte pointer for the key and IV pointers */
    p8    = (uint8_t *)p32;
    p_key = p8;
    p8 += keylen;
    p_iv = p8;
    p8 += ivlen;
    /* Switch back to a 32-bit pointer for setting up the message list */
    p32 = (uint32_t *)p8;
    /* Save where we are as the start of the message list */
    p_message_list = (void *)p32;
    /* Host endian does not always match target endian, fix it here */
    for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
    {
        /* Host endian does not always match target endian, fix it here */
        length = EE_FIX_ENDIAN(*p32);
        *p32++ = length;
        p8     = (uint8_t *)p32;
        /* Skip to next operation block (input + output + tag) */
        p8 += length + length + EE_CHACHAPOLY_TAGLEN;
        p32 = (uint32_t *)p8;
    }
    /* If decrypting, encrypt something for the decrypt loop to decrypt */
    if (func == EE_CHACHAPOLY_DEC)
    {
        /* Don't confuse the host with bogus timestamps! */
        g_mute_timestamps = true;
        ee_chachapoly(EE_CHACHAPOLY_ENC, p_key, p_iv, count, p_message_list, 1);
        g_mute_timestamps = false;
        /* Now swap all the encrypted outputs to the input space. */
        for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
        {
            length = *p32++;
            p8     = (uint8_t *)p32;
            th_memcpy(p8, p8 + length, length);
            p8 += length + length + EE_CHACHAPOLY_TAGLEN;
            p32 = (uint32_t *)p8;
        }
    }
    /* Run the number of iterations */
    dt = ee_chachapoly(func, p_key, p_iv, count, p_message_list, iter);
    /* Print verification messages used by the host for proof-of-work */
    if (verify)
    {
        for (p32 = (uint32_t *)p_message_list, x = 0; x < count; ++x)
        {
            length = *p32++;
            p8     = (uint8_t *)p32;
            /* Not all of these are used (ECB, CCM), but print them anyway. */
            ee_printmemline(p_key, keylen, "m-bench-chachapoly-key-");
            ee_printmemline(p_iv, ivlen, "m-bench-chachapoly-iv-");
            ee_printmemline(p8, length, "m-bench-chachapoly-in-");
            p8 += length;
            ee_printmemline(p8, length, "m-bench-chachapoly-out-");
            p8 += length;
            ee_printmemline(p8, EE_CHACHAPOLY_TAGLEN, "m-bench-chachapoly-tag-");
            p8 += EE_CHACHAPOLY_TAGLEN;
            p32 = (uint32_t *)p8;
        }
    }
    return dt;
}
#if 0
uint32_t
ee_bench_chachapolyx(ee_chachapoly_func_t func, int n, int i, bool verify)
{
    uint8_t *p_key = th_buffer_address();
    uint8_t *p_iv  = p_key + EE_CHACHAPOLY_KEYLEN;
    uint8_t *p_in  = p_iv + EE_CHACHAPOLY_IVLEN;
    uint8_t *p_out = p_in + n;
    uint8_t *p_tag = p_out + n;
    uint32_t dt;

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
    dt = ee_chachapoly(func, p_key, p_iv, p_in, n, p_out, p_tag, i);
    if (verify)
    {
        ee_printmemline(p_key, EE_CHACHAPOLY_KEYLEN, "m-bench-chachapoly-key-");
        ee_printmemline(p_iv, EE_CHACHAPOLY_IVLEN, "m-bench-chachapoly-iv-");
        ee_printmemline(p_in, n, "m-bench-chachapoly-in-");
        ee_printmemline(p_out, n, "m-bench-chachapoly-out-");
        ee_printmemline(p_tag, EE_AES_TAGLEN, "m-bench-chachapoly-tag-");
    }
    return dt;
}
#endif
uint32_t
ee_bench_ecdh(ee_ecdh_group_t g, uint32_t i, bool verify)
{
    uint32_t  t0       = 0;
    uint32_t  t1       = 0;
    uint32_t *p_publen = (uint32_t *)th_buffer_address();

    /* Host endian does not always match target endian */
    *p_publen = EE_FIX_ENDIAN(*p_publen);
    if (*p_publen > 0x80000)
    {
        th_printf("e-[Possible incorrect endian configuration]\r\n");
        return 0;
    }
    uint8_t * p_pub    = (uint8_t *)p_publen + sizeof(uint32_t);
    uint32_t *p_seclen = (uint32_t *)(p_pub + *p_publen);
    /* Host endian does not always match target endian */
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
    t0 = th_timestamp();
    th_pre();
    do
    {
        ret = th_ecdh_calc_secret(p_context, p_sec, p_seclen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
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
    return t1 - t0;
}

uint32_t
ee_bench_ecdsa_sign(ee_ecdh_group_t g, uint32_t n, uint32_t i, bool verify)
{
    uint32_t t0 = 0;
    uint32_t t1 = 0;
    /* Sig will be ASN.1 so may vary, just put some reasonable values. */
    uint32_t publen = 256;
    uint32_t siglen = 256;

    uint8_t *p_msg = th_buffer_address();
    uint8_t *p_pub = p_msg + n;
    uint8_t *p_sig = p_pub + publen;

    void *      p_context = NULL;
    ee_status_t ret       = EE_STATUS_OK;

    th_ecdsa_create(&p_context, g);
    th_printf("m-ecdsa-%s-sign-iter[%d]\r\n", ee_ecdh_group_names[g], i);
    th_printf("m-ecdsa-%s-sign-start\r\n", ee_ecdh_group_names[g]);
    t0 = th_timestamp();
    th_pre();
    do
    {
        // reset siglen back to maximum for each round, since output length may
        // vary
        siglen = 256;
        ret    = th_ecdsa_sign(p_context, p_msg, n, p_sig, &siglen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
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

    return t1 - t0;
}

uint32_t
ee_bench_ecdsa_verify(ee_ecdh_group_t g, uint32_t n, uint32_t i, bool verify)
{
    uint32_t  t0       = 0;
    uint32_t  t1       = 0;
    uint8_t * p_msg    = th_buffer_address();
    uint32_t *p_publen = (uint32_t *)(p_msg + n);

    /* Host endian does not always match target endian */
    *p_publen = EE_FIX_ENDIAN(*p_publen);
    if (*p_publen > 0x80000)
    {
        th_printf("e-[Possible incorrect endian configuration]\r\n");
        return 0;
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
    t0 = th_timestamp();
    th_pre();
    do
    {
        ret = th_ecdsa_verify(p_ctx, p_msg, n, p_sig, *p_siglen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
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
    return t1 - t0;
}

uint32_t
ee_bench_rsa_verify(ee_rsa_id_t id, unsigned int n, unsigned int i, bool verify)
{
    uint32_t  t0       = 0;
    uint32_t  t1       = 0;
    uint8_t * p_msg    = th_buffer_address();
    uint32_t *p_publen = (uint32_t *)(p_msg + n);

    /* Host endian does not always match target endian */
    *p_publen = EE_FIX_ENDIAN(*p_publen);
    if (*p_publen > 0x80000)
    {
        th_printf("e-[Possible incorrect endian configuration]\r\n");
        return 0;
    }
    uint8_t * p_pub    = (uint8_t *)p_publen + sizeof(uint32_t);
    uint32_t *p_siglen = (uint32_t *)(p_pub + *p_publen);
    /* Host endian does not always match target endian */
    *p_siglen              = EE_FIX_ENDIAN(*p_siglen);
    uint8_t *   p_sig      = (uint8_t *)p_siglen + sizeof(uint32_t);
    uint8_t *   p_passfail = p_sig + *p_siglen;
    void *      p_context  = NULL;
    ee_status_t ret        = EE_STATUS_OK;

    th_rsa_create(&p_context);
    th_rsa_set_public_key(p_context, p_pub, *p_publen);
    t0 = th_timestamp();
    th_pre();
    do
    {
        ret = th_rsa_verify(p_context, p_msg, n, p_sig, *p_siglen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
    th_rsa_destroy(p_context);

    *p_passfail = ret == EE_STATUS_OK ? 1 : 0;

    if (verify)
    {
        ee_printmemline(p_pub, *p_publen, "m-bench-rsa-pri-");
        ee_printmemline(p_msg, n, "m-bench-rsa-msg-");
        ee_printmemline(p_sig, *p_siglen, "m-bench-rsa-sig-");
        th_printf("m-ecdsa-sign-passfail-%d\r\n", *p_passfail);
    }
    return t1 - t0;
}

arg_claimed_t
ee_bench_parse(char *p_command, bool verify)
{
    char *p_subcmd;
    char *p_seed;
    char *p_iter;
    char *p_size;

    uint32_t i;
    uint32_t n;

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
        n = (uint32_t)th_atoi(p_size);
    }
    else
    {
        n = 0;
    }

    if (p_iter)
    {
        i = (uint32_t)th_atoi(p_iter);

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
        ee_bench_sha(EE_SHA256, i, verify);
    }
    else if (th_strncmp(p_subcmd, "sha384", EE_CMD_SIZE) == 0)
    {
        ee_bench_sha(EE_SHA384, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ecb-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ecb-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ctr-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ctr-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ccm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-ccm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-gcm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_GCM, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes128-gcm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_GCM, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ecb-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ecb-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_ECB, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ctr-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ctr-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CTR, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ccm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-ccm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_CCM, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-gcm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_GCM, EE_AES_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "aes256-gcm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_aes(EE_AES_GCM, EE_AES_DEC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "chachapoly-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_chachapoly(EE_CHACHAPOLY_ENC, i, verify);
    }
    else if (th_strncmp(p_subcmd, "chachapoly-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_chachapoly(EE_CHACHAPOLY_DEC, i, verify);
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
