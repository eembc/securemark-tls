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

/**
 * This file, main.c, is provided as a simple way to run the benchmark without
 * the host GUI framework. The function main() invokes all of the benchmark
 * components in self-timing mode, and then computes the score. The only
 * porting compnents required is th_timestamp(). th_printf() may be ported
 * to observe what is happening during the benchmark, but is not required, so
 * the main() function calls "printf" to present the score. However, output
 * may be modified to suit the particular port needs.
 *
 * The point of this code is to give the user an idea of what the real
 * benchmark looks like. The scores generated here are not official scores
 * since they have not been generated with the test harness.
 *
 * Please contact support@eembc.org for information on obtaining the official
 * test harness.
 */
#include "ee_main.h"
#include "ee_aes.h"
#include "ee_chachapoly.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_sha.h"
#include "ee_rsa.h"
#include "ee_variations.h"
#include "ee_util.h"
#include "ee_bench.h"
#include "ee_buffer.h"
/* Pre-made keys just for this self-hosted main.c */
#include "keys.h"
#include <assert.h>

// There are several POSIX assumptions in this implementation.
#if (__linux__ || __APPLE__)
#include <time.h>
#elif _WIN32
#include <sys\timeb.h>
#else
#error "Operating system not recognized"
#endif

/* Longest time to run each primitive during self-tuning */
#define MIN_RUNTIME_SEC  10u
#define MIN_RUNTIME_USEC (MIN_RUNTIME_SEC * 1000u * 1000u)
/* Minimum number of iterations allowed per primitive */
#define MIN_ITER 10u
/* Stored timestamps (a single primitive may generate multiple stamps) */
#define MAX_TIMESTAMPS 64u
/* `1` to turn on debugging messages */
#define DEBUG_VERIFY 0
/* Only run a single iteration of each task (for debug) */
#define CRC_ONLY 1

/* Wrapper functions fill out a results structure with time and CRC */
typedef struct
{
    uint16_t crc; /* crc16, depends on the primitive */
    uint32_t dt;  /* Delta time in millseconds */
} wres_t;
/* All wrapper functions fit this prototype (dataset octets, iterations, res) */
typedef void wrapper_function_t(void *, uint32_t, uint32_t, wres_t *);
/* For functions that process multiple data records betwee init/free */
/* TODO: Check compiler portability here */
typedef struct ee_array_uint32
{
    uint32_t  size;
    uint32_t *data;
} ee_array_uint32_t;
/* This macro makes a global array structure out of an array */
#define MAKE_ARRAY(PREFIX)              \
    static ee_array_uint32_t g_##PREFIX \
        = { sizeof(ee_##PREFIX) / sizeof(uint32_t), ee_##PREFIX }
/* Medium is used for both Medium and Light in V2 */
/* These are the running SHA values */
static uint32_t ee_single_use[]  = { 0 };
static uint32_t ee_sha_multi_m[] = { 123, 6, 15, 300, 80, 36, 299, 79, 36 };
static uint32_t ee_sha_multi_h[] = { 155, 6, 17, 361, 110, 52, 360, 111, 52 };
static uint32_t ee_aead_e_multi_m[] = { 300, 80, 48 };
static uint32_t ee_aead_e_multi_h[] = { 368, 112, 64 };
static uint32_t ee_aead_d_multi_m[] = { 16, 16, 304, 96, 48 };
static uint32_t ee_aead_d_multi_h[] = { 16, 32, 368, 112, 64 };
MAKE_ARRAY(single_use);
MAKE_ARRAY(sha_multi_m);
MAKE_ARRAY(sha_multi_h);
MAKE_ARRAY(aead_e_multi_m);
MAKE_ARRAY(aead_e_multi_h);
MAKE_ARRAY(aead_d_multi_m);
MAKE_ARRAY(aead_d_multi_h);

/**
 * @brief Generate a timestamp for performance compuation. Since we are running
 * self-hosted, there's no need for GPIO or an output message, just return
 * the elapsedMicroSeconds.
 *
 * @return uint32_t - Elapsed microseconds
 */
uint32_t
th_timestamp(void)
{
    // --- BEGIN USER CODE 1
#if (__linux__ || __APPLE__)
    struct timespec t;
    /*@-unrecog*/
    clock_gettime(CLOCK_REALTIME, &t);
    const unsigned long NSEC_PER_SEC      = 1000000000UL;
    const unsigned long TIMER_RES_DIVIDER = 1000UL;
    uint64_t            elapsedMicroSeconds;
    /*@-usedef*/
    elapsedMicroSeconds = t.tv_sec * (NSEC_PER_SEC / TIMER_RES_DIVIDER)
                          + t.tv_nsec / TIMER_RES_DIVIDER;
#elif _WIN32
    struct timeb t;
    uint64_t     elapsedMicroSeconds;
    ftime(&t);
    elapsedMicroSeconds
        = ((uint64_t)t.time) * 1000 * 1000 + ((uint64_t)t.millitm) * 1000;
#else
#error "Operating system not recognized"
#endif
    return elapsedMicroSeconds;
}

/** ERROR HANDLER **/

void
error_handler(void)
{
    exit(-1);
    // or if embedded: while(1) {};
}

/** PRINTF ********************************************************************/

/**
 * The function th_printf() is used extensively throughout the monitor and
 * profile code. However, for the self-hosted mode, it is not required. You
 * may comment out the content of this function with no consequence.
 */
void
th_printf(const char *fmt, ...)
{
#if (EE_CFG_QUIET != 1) || (DEBUG_VERIFY)
    va_list args;
    va_start(args, fmt);
    /*@-retvalint*/
    th_vprintf(fmt, args);
    va_end(args);
    // Emulate the GUI and fail on error message.
    if (fmt[0] == 'e' && fmt[1] == '-')
    {
        error_handler();
    }
#else
    // If quiet mode is on, at least print the error (see README.md).
    if (fmt[0] == 'e' && fmt[1] == '-')
    {
        va_list args;
        va_start(args, fmt);
        /*@-retvalint*/
        th_vprintf(fmt, args);
        va_end(args);
        error_handler();
    }
#endif
}

/** CRC UTILITY FOR INSURING CORRECTNESS **************************************/

uint16_t
crcu8(uint8_t data, uint16_t crc)
{
    size_t  i;
    uint8_t x16;
    uint8_t carry;

    i     = 0;
    x16   = 0;
    carry = 0;
    for (i = 0; i < 8; i++)
    {
        x16 = (uint8_t)((data & 1) ^ ((uint8_t)crc & 1));
        data >>= 1;

        if (x16 == 1)
        {
            crc ^= 0x4002;
            carry = 1;
        }
        else
            carry = 0;
        crc >>= 1;
        if (carry)
        {
            crc |= 0x8000;
        }
        else
        {
            crc &= 0x7fff;
        }
    }
    return crc;
}

uint16_t
crcu16(uint16_t newval, uint16_t crc)
{
    crc = crcu8((uint8_t)(newval), crc);
    crc = crcu8((uint8_t)((newval) >> 8), crc);
    return crc;
}

/** BENCHMARK PRIMITIVE WRAPPERS **********************************************/

/**
 * The following functions all match the wrapper_function_t typedef by
 * accepting the number of octets in the input data (n), the number of
 * iterations to run (i), and returning a 16-bit CRC of the resulting data.
 *
 * Random data is loaded as plaintext or keys (except for ECC functions). In
 * cases where a valid tag is required, an encryption run is performed first,
 * and the ciphertext and tag from that preparation run is used for the
 * decryption.
 */

void
pre_wrap_sha(ee_sha_size_t size, uint32_t n, uint32_t i, wres_t *res)
{
    uint8_t *p = th_buffer_address();

    res->dt  = ee_bench_sha(size, n, i, DEBUG_VERIFY);
    res->crc = 0;
    for (size_t x = 0; x < (size / 8); ++x)
    {
        res->crc = crcu16(res->crc, (uint8_t)(p + n)[x]);
    }
}

void
pre_wrap_sha_multi(ee_sha_size_t size, uint32_t i, void *ex, wres_t *res)
{
    ee_array_uint32_t *input = (ee_array_uint32_t *)ex;

    uint32_t *p      = (uint32_t *)th_buffer_address();
    uint32_t *p_lens = p + 1;
    uint8_t * p_out  = (uint8_t *)(p_lens + input->size);

    *p = input->size;
    for (size_t x = 0; x < *p; ++x)
    {
        p_lens[x] = input->data[x];
    }
    res->dt  = ee_bench_sha_multi(size, i, DEBUG_VERIFY);
    res->crc = 0;
    /* TODO: Is this only doing the first byte of each output? */
    for (size_t x = 0; x < (size / 8); ++x)
    {
        res->crc = crcu16(res->crc, (uint8_t)(p_out)[x]);
    }
}

#define MAKE_WRAP_SHA(x)                                                    \
    void wrap_sha##x(void *ex, uint32_t n, uint32_t i, wres_t *res)         \
    {                                                                       \
        pre_wrap_sha(EE_SHA##x, n, i, res);                                 \
    }                                                                       \
    void wrap_sha##x##_multi(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                                       \
        pre_wrap_sha_multi(EE_SHA##x, i, ex, res);                          \
    }

MAKE_WRAP_SHA(256)
MAKE_WRAP_SHA(384)

void
pre_wrap_aes(ee_aes_mode_t mode,
             ee_aes_func_t func,
             uint32_t      keylen,
             uint32_t      n, /* n=0 to use ex */
             uint32_t      i,
             void *        ex, /* null if n>0 */
             wres_t *      res)
{
    uint32_t *p32;
    uint32_t *p_list;
    uint8_t * p8;
    uint32_t  ivlen = mode == EE_AES_CTR ? EE_AES_CTR_IVLEN : EE_AES_AEAD_IVLEN;
    uint32_t  msglen;
    ee_array_uint32_t *input = (ee_array_uint32_t *)ex;
    size_t             x, y; /* generic iteration indices */

    /* If single mode, use the premade single-element structure. */
    if (n > 0 && ex == 0)
    {
        g_single_use.data[0] = n;
        input                = &g_single_use;
    }

    /* Setup the generic buffer to contain the test data */
    p32 = (uint32_t *)th_buffer_address();
    /* First the header */
    *p32++ = keylen;
    *p32++ = ivlen;
    *p32++ = input->size;
    /* Then the key and iv (the ee_bench function will fill these). */
    p8 = (uint8_t *)p32;
    p8 += keylen;
    p8 += ivlen;
    /* Then place the length values for each message packet (same as above) */
    p32    = (uint32_t *)p8;
    p_list = p32;
    for (x = 0; x < input->size; ++x)
    {
        *p32++ = input->data[x];
        p8     = (uint8_t *)p32;
        p8 += input->data[x]; /* input */
        p8 += input->data[x]; /* output */
        p8 += EE_AES_TAGLEN;
        p32 = (uint32_t *)p8;
    }

    /* Benchmark the mode/function on the data */
    res->dt  = ee_bench_aes(mode, func, i, DEBUG_VERIFY);
    res->crc = 0;

    /* Calculate the CRC16 over the output */
    for (p32 = p_list, x = 0; x < input->size; ++x)
    {
        msglen = *p32++;
        p8     = (uint8_t *)p32;
        p8 += input->data[x]; /* move to output message */
        for (y = 0; y < msglen; ++y)
        {
            res->crc = crcu16(res->crc, (uint8_t)p8[y]);
        }
        p8 += input->data[x]; /* move to tag */
        p8 += EE_AES_TAGLEN;  /* skip tag */
        p32 = (uint32_t *)p8;
    }
}

#define MAKE_WRAP_AES(bits, MODE, nick)                                   \
    void wrap_aes##bits##_##nick##_encrypt(                               \
        void *ex, uint32_t n, uint32_t i, wres_t *res)                    \
    {                                                                     \
        pre_wrap_aes(EE_AES_##MODE, EE_AES_ENC, bits / 8, n, i, ex, res); \
    }                                                                     \
    void wrap_aes##bits##_##nick##_decrypt(                               \
        void *ex, uint32_t n, uint32_t i, wres_t *res)                    \
    {                                                                     \
        pre_wrap_aes(EE_AES_##MODE, EE_AES_DEC, bits / 8, n, i, ex, res); \
    }

MAKE_WRAP_AES(128, ECB, ecb)
MAKE_WRAP_AES(128, CTR, ctr)
MAKE_WRAP_AES(128, CCM, ccm)
MAKE_WRAP_AES(128, GCM, gcm)
MAKE_WRAP_AES(256, ECB, ecb)
MAKE_WRAP_AES(256, CTR, ctr)
MAKE_WRAP_AES(256, CCM, ccm)
MAKE_WRAP_AES(256, GCM, gcm)

void
pre_wrap_chachapoly(ee_chachapoly_func_t func,
                    uint32_t             n,
                    uint32_t             i,
                    wres_t *             res)
{
    uint8_t *p_out;

    assert(th_buffer_size() > (EE_CHACHAPOLY_KEYLEN + EE_CHACHAPOLY_IVLEN
                               + EE_CHACHAPOLY_TAGLEN + +n));
    p_out
        = th_buffer_address() + EE_CHACHAPOLY_KEYLEN + EE_CHACHAPOLY_IVLEN + n;

    res->dt  = ee_bench_chachapoly(func, n, i, DEBUG_VERIFY);
    res->crc = 0;
    for (size_t x = 0; x < n; ++x)
    {
        res->crc = crcu16(res->crc, (uint8_t)p_out[x]);
    }
}

void
wrap_chachapoly_encrypt(void *ex, uint32_t n, uint32_t i, wres_t *res)
{
    pre_wrap_chachapoly(EE_CHACHAPOLY_ENC, n, i, res);
}

void
wrap_chachapoly_decrypt(void *ex, uint32_t n, uint32_t i, wres_t *res)
{
    pre_wrap_chachapoly(EE_CHACHAPOLY_DEC, n, i, res);
}

void
pre_wrap_ecdh(ee_ecdh_group_t g, uint32_t i, wres_t *res)
{
    uint32_t *p_publen = (uint32_t *)th_buffer_address();
    uint8_t * p_pub;
    uint32_t *p_seclen;
    /*uint8_t * p_sec;*/

    *p_publen = g_ecc_public_key_sizes[g];
    p_pub     = (uint8_t *)p_publen + sizeof(uint32_t);
    p_seclen  = (uint32_t *)(p_pub + *p_publen);
    /*p_sec     = (uint8_t *)p_seclen + sizeof(uint32_t);*/
    th_memcpy(p_pub, g_ecc_public_keys[g], *p_publen);

    *p_seclen = 256; // Reasonably-sized space for the sig.

    res->dt = ee_bench_ecdh(g, i, DEBUG_VERIFY);
    /* TODO: We don't have access to the private key so we cannot verify. */
    res->crc = 0;
}

#define MAKE_WRAP_ECDH(nick, group)                                      \
    void wrap_ecdh_##nick(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                                    \
        pre_wrap_ecdh(group, i, res);                                    \
    }

MAKE_WRAP_ECDH(p256r1, EE_P256R1)
MAKE_WRAP_ECDH(p384, EE_P384)
MAKE_WRAP_ECDH(x25519, EE_C25519)

void
pre_wrap_ecdsa_sign(ee_ecdh_group_t g, uint32_t i, wres_t *res)
{
    uint8_t  msglen = sizeof(g_dsa_message);
    uint8_t *msg    = th_buffer_address();

    th_memcpy(msg, g_dsa_message, msglen);
    res->dt = ee_bench_ecdsa_sign(g, msglen, i, false);
    /* Since the DUT generates a new keypair every run, we can't CRC */
    res->crc = 0;
}

void
pre_wrap_ecdsa_verify(ee_ecdh_group_t g, uint32_t i, wres_t *res)
{
    uint8_t   msglen = sizeof(g_dsa_message);
    uint8_t * msg    = th_buffer_address();
    uint32_t *publen;
    uint8_t * pub;
    uint32_t *siglen;
    uint8_t * sig;
    uint8_t * passfail;

    /* Input message */
    th_memcpy(msg, g_dsa_message, msglen);
    /* Length of public key TODO: Raw for now ... */
    publen  = (uint32_t *)(msg + msglen);
    *publen = g_ecc_public_key_sizes[g];
    /* Public key */
    pub = (uint8_t *)publen + sizeof(uint32_t);
    th_memcpy(pub, g_ecc_public_keys[g], *publen);
    /* Length of signature */
    siglen  = (uint32_t *)(pub + *publen);
    *siglen = g_dsa_signatures_sizes[g];
    /* Signature */
    sig = (uint8_t *)siglen + sizeof(uint32_t);
    th_memcpy(sig, g_ecc_signatures[g], *siglen);
    /* Results of verification */
    passfail  = sig + *siglen;
    *passfail = 0;
    /* This function calls the primitives and manages the buffer. */
    res->dt = ee_bench_ecdsa_verify(g, msglen, i, false);
    /* No CRC here, just pass/fail, e.g. 1/0 */
    res->crc = *passfail;
}

#define MAKE_WRAP_ECDSA(nick, group)                                           \
    void wrap_ecdsa_sign_##nick(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                                          \
        pre_wrap_ecdsa_sign(group, i, res);                                    \
    }                                                                          \
    void wrap_ecdsa_verify_##nick(                                             \
        void *ex, uint32_t n, uint32_t i, wres_t *res)                         \
    {                                                                          \
        pre_wrap_ecdsa_verify(group, i, res);                                  \
    }

MAKE_WRAP_ECDSA(p256r1, EE_P256R1)
MAKE_WRAP_ECDSA(p384, EE_P384)
MAKE_WRAP_ECDSA(ed25519, EE_Ed25519)

void
pre_wrap_rsa_verify(ee_rsa_id_t id, uint32_t i, wres_t *res)
{
    uint8_t   msglen = sizeof(g_dsa_message);
    uint8_t * msg    = th_buffer_address();
    uint32_t *publen;
    uint8_t * pub;
    uint32_t *siglen;
    uint8_t * sig;
    uint8_t * passfail;

    /* Input message */
    th_memcpy(msg, g_dsa_message, msglen);
    /* Length of public key TODO: Raw for now ... */
    publen  = (uint32_t *)(msg + msglen);
    *publen = g_rsa_public_key_sizes[id];
    /* Public key */
    pub = (uint8_t *)publen + sizeof(uint32_t);
    th_memcpy(pub, g_rsa_public_keys[id], *publen);
    /* Length of signature */
    siglen  = (uint32_t *)(pub + *publen);
    *siglen = g_rsa_signature_sizes[id];
    /* Signature */
    sig = (uint8_t *)siglen + sizeof(uint32_t);
    th_memcpy(sig, g_rsa_signatures[id], *siglen);
    /* Results of verification */
    passfail  = sig + *siglen;
    *passfail = 0;
    /* This function calls the primitives and manages the buffer. */
    res->dt = ee_bench_rsa_verify(id, msglen, i, false);
    /* No CRC here, just pass/fail, e.g. 1/0 */
    res->crc = *passfail;
}

#define MAKE_WRAP_RSA(nick, id)                                                \
    void wrap_rsa_verify_##nick(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                                          \
        pre_wrap_rsa_verify(id, i, res);                                       \
    }

MAKE_WRAP_RSA(2048, EE_RSA_2048)
MAKE_WRAP_RSA(3072, EE_RSA_3072)
MAKE_WRAP_RSA(4096, EE_RSA_4096)

void
wrap_variation_001(void *ex, uint32_t n, uint32_t i, wres_t *res)
{
    n       = 0; /* unused */
    res->dt = ee_variation_001(i);
    /**
     * There is no way to compute CRC without touching deeper code, but since
     * we've already exercised the primitives in the variation, we don't
     * actually need a CRC.
     */
    res->crc = 0;
}

/**
 * @brief Find a number of iterations that meets both the minimum iteration
 * requirement and the minimum runtime requirement.
 *
 * @param n - Data size (if used by the function)
 * @param func - The function pointer
 * @return uint32_t - The number of iterations required
 */
uint64_t
tune_iterations(void *ex, uint32_t n, wrapper_function_t *func)
{
    uint32_t eps   = 1;
    uint32_t mint  = 0;
    uint32_t dt1   = 0;
    uint32_t dt2   = 0;
    uint64_t guess = 1;
    wres_t   res;
    /* This converges faster than previous method. */
    do
    {
        guess *= 10;
        (*func)(ex, n, guess, &res);
        dt1 = res.dt / 1e3;
        (*func)(ex, n, guess, &res);
        dt2  = res.dt / 1e3;
        eps  = (dt1 > dt2) ? (dt1 - dt2) : (dt2 - dt1);
        mint = (dt1 < dt2) ? dt1 : dt2;
    } while (eps > guess || dt1 < 100 || guess < MIN_ITER);
    /* Integer div will floor <10, so multiply by 10%, but before the division
       in order to add more precision to the integer divide). */
    return (guess * 11000) / mint;
}

/* This structure and macros facilitates a more readable task list. */
typedef struct
{
    wrapper_function_t *func;         /* The primitive for this task */
    uint32_t            n;            /* Number of octets for input data */
    float               ips;          /* iterations-per-second */
    float               weight;       /* equation scaling weight */
    uint16_t            actual_crc;   /* CRC computed for 1 iter. seed 0 */
    uint16_t            expected_crc; /* Precomputed CRC by EEMBC */
    char *              name;         /* Name of the task */
    void *              ex;           /* Extra data */
} task_entry_t;

#define TASK(name, n, w, crc) \
    { wrap_##name, n, 0.0, (float)w, 0x0, crc, #name, (void *)0 },

/* TODO: Is there a portable variadic macro? Use an "extra" struct. */
#define TASKEX(name, w, crc, data) \
    { wrap_##name, 0, 0.0, (float)w, 0x0, crc, #name, (void *)data },

/**
 * The weights are used for scoring and are defined by the EEMBC working group.
 *
 * The expected_crc values were computed by EEMBC for the given parameters.
 * The CRC of the resulting output should be the same regardless of the
 * software or hardware implementation. Changing the random seed, the number
 * of input bytes, or any of the values in keys.h will cause CRC errors.
 *
 * Note: The deterministic K function must use SHA256 to get the right CRC
 * Note: All sign/verify operations must be 32-byte messages; Ed25519 will
 *       hash this *again* with SHA512. This is unavoidable.
 */

// clang-format off
static task_entry_t g_task[] =
{
    TASKEX(aes128_gcm_encrypt, 1.0f, 0x954b, &g_aead_e_multi_m)
    TASKEX(aes256_gcm_encrypt, 1.0f, 0x9f97, &g_aead_e_multi_h)
    TASKEX(aes128_ccm_encrypt, 1.0f, 0xb9d9, &g_aead_e_multi_m)
    TASKEX(aes256_ccm_encrypt, 1.0f, 0xf16d, &g_aead_e_multi_h)

    TASKEX(aes128_gcm_decrypt, 1.0f, 0x7b96, &g_aead_d_multi_m)
    TASKEX(aes256_gcm_decrypt, 1.0f, 0x56f1, &g_aead_d_multi_h)
    TASKEX(aes128_ccm_decrypt, 1.0f, 0x7b96, &g_aead_d_multi_m)
    TASKEX(aes256_ccm_decrypt, 1.0f, 0x56f1, &g_aead_d_multi_h)

    /*
     *   Macro nickname       ,Bytes, weight, crc
     */
    // V1 - TLS 1.2 (note CRCs changed due to new keys & wrappers)
    // For Medium
    TASK(aes128_ecb_encrypt   ,  320,  1.0f, 0x0b7a)
    TASK(aes128_ccm_encrypt   ,   52,  1.0f, 0xd82d)
    TASK(aes128_ccm_decrypt   ,  168,  1.0f, 0x9a42)
    TASK(ecdh_p256r1          ,    0,  1.0f, 0)
    TASK(ecdsa_sign_p256r1    ,   32,  1.0f, 0)
    TASK(ecdsa_verify_p256r1  ,   32,  1.0f, 1)
    TASK(sha256               ,   23,  3.0f, 0x2151)
    TASK(sha256               ,   57,  1.0f, 0x3b3c)
    TASK(sha256               ,  384,  1.0f, 0x1d3f)
    // TODO: need a variation 001 for Light and Heavy
    TASK(variation_001        ,    0,  3.0f, 0x0000)
    TASK(sha256               , 4224,  4.0f, 0x9284)
    TASK(aes128_ecb_encrypt   , 2048, 10.0f, 0xc380)
    // For Light
    TASK(chachapoly_encrypt   ,   52,  1.0f, 0xa7f5)
    TASK(chachapoly_decrypt   ,  168,  1.0f, 0x44be)
    // For Heavy
    TASK(aes256_ecb_encrypt   ,  320,  1.0f, 0xba50)
    TASK(aes256_ccm_encrypt   ,   52,  1.0f, 0xd195)
    TASK(aes256_ccm_decrypt   ,  168,  1.0f, 0x0dc3)
    // NOTE: WolfCrypt has a problem here, compute CRC with mbedTLS
    TASK(ecdsa_sign_p384      ,   32,  1.0f, 0)
    TASK(ecdsa_verify_p384    ,   32,  1.0f, 1)
    TASK(sha384               ,   23,  3.0f, 0x9f68)
    TASK(sha384               ,   57,  1.0f, 0x8a5c)
    TASK(sha384               ,  384,  1.0f, 0xb5e8)
    TASK(sha384               , 4224,  4.0f, 0xb146)
    TASK(aes256_ecb_encrypt   , 2048, 10.0f, 0x2364)
    // V2 - TLS 1.3 & Secure Boot Components
    TASKEX(sha256_multi       , 1.0f, 0x2be9, &g_sha_multi_m)
    TASKEX(sha384_multi       , 1.0f, 0x806c, &g_sha_multi_h)
    // Additional Key Exchange
    TASK(ecdh_p384            ,    0,  1.0f, 0)
    TASK(ecdh_x25519          ,    0,  1.0f, 0)
    // Additional ECDSA Sign & Hashes
    TASK(sha256               , 1539,  1.0f, 0xb48c)
    TASK(sha384               , 1539,  1.0f, 0x7cbc)
    TASK(ecdsa_sign_ed25519   ,   32,  1.0f, 0)
    // Additional ECDSA Verify & Hashes
    TASK(sha256               , 4104,  2.0f, 0x39c9)
    TASK(sha384               , 4104,  2.0f, 0xa424)
    TASK(ecdsa_verify_ed25519 ,   32,  1.0f, 1)
    // AEAD
    TASK(aes128_ccm_encrypt   ,  416,  1.0f, 0x286a)
    TASK(aes128_ccm_decrypt   ,  444,  1.0f, 0x11b7)
    TASK(aes128_ccm_encrypt   ,   38,  1.0f, 0x5137)
    TASK(aes128_ccm_decrypt   ,  136,  1.0f, 0xab71)
    // -
    TASK(aes256_ccm_encrypt   ,  416,  1.0f, 0x28dd)
    TASK(aes256_ccm_decrypt   ,  444,  1.0f, 0x06f9)
    TASK(aes256_ccm_encrypt   ,   38,  1.0f, 0xd879)
    TASK(aes256_ccm_decrypt   ,  136,  1.0f, 0xc310)
    // -
    TASK(aes128_gcm_encrypt   ,  416,  1.0f, 0xa22f)
    TASK(aes128_gcm_decrypt   ,  444,  1.0f, 0x11b7)
    TASK(aes128_gcm_encrypt   ,   38,  1.0f, 0x9970)
    TASK(aes128_gcm_decrypt   ,  136,  1.0f, 0xab71)
    // -
    TASK(chachapoly_encrypt   ,  416,  1.0f, 0x47fa)
    TASK(chachapoly_decrypt   ,  444,  1.0f, 0x066a)
    TASK(chachapoly_encrypt   ,   38,  1.0f, 0x5dbb)
    TASK(chachapoly_decrypt   ,  136,  1.0f, 0xffab)
    // Ciphers
    TASK(aes128_ecb_encrypt   ,  288,  1.0f, 0x859a)
    TASK(aes256_ecb_encrypt   ,  288,  1.0f, 0x0ebc)
    TASK(aes128_ctr_encrypt   ,  288,  1.0f, 0x3afb)
    TASK(aes256_ctr_encrypt   ,  288,  1.0f, 0xa675)
    // Digests
    TASK(sha256               , 1132,  1.0f, 0x9c1f)
    TASK(sha256               ,  204, 15.0f, 0x0e57)
    TASK(sha256               ,  176, 14.0f, 0x3bd6)
    TASK(sha256               ,  130,  2.0f, 0xbaed)
    // -
    TASK(sha384               , 1132,  1.0f, 0x7839)
    TASK(sha384               ,  204, 15.0f, 0x4b8a)
    TASK(sha384               ,  176, 14.0f, 0x660b)
    TASK(sha384               ,  130,  2.0f, 0x445b)
    // Secure boot verify only
    TASK(rsa_verify_2048      ,   32,  1.0f, 1)
    TASK(rsa_verify_3072      ,   32,  1.0f, 1)
    TASK(rsa_verify_4096      ,   32,  1.0f, 1)
};
// clang-format on
static const size_t g_numtasks = sizeof(g_task) / sizeof(task_entry_t);

int
main(void)
{
    char   namebuf[30];
    float  score;
    wres_t res;
#if DEBUG_VERIFY == 0
    float component_score;
#if CRC_ONLY == 0
    uint64_t iterations;
#endif
#endif

    setbuf(stdout, 0);

    /* N.B.: We use printf here rather than th_printf because we mute it to
       keep things less messy. If you can't use printf, use th_printf and turn
       off QUIET in the CMakeLists.txt file. */
    printf("Running each primitive for at least %us or %u iterations.\n",
           MIN_RUNTIME_SEC,
           MIN_ITER);

    printf("Heap buffer is %u bytes\n", th_buffer_size());
    printf("Number of subtests: %zu\n", g_numtasks);
    score = 0.0f;
    printf(" # Component                  data   w    iterations/s\n");
    printf("-- ------------------------- ----- --- ---------------\n");
    for (size_t i = 0; i < g_numtasks; ++i)
    {
        if (g_task[i].ex == 0)
        {
            printf("%2zu %-25s %5d %3.0f ",
                   i + 1,
                   g_task[i].name,
                   g_task[i].n,
                   g_task[i].weight);
        }
        else
        {
            sprintf(namebuf, "%s_multi", g_task[i].name);
            printf("%2zu %-25s %5d %3.0f ",
                   i + 1,
                   namebuf,
                   ((ee_array_uint32_t *)g_task[i].ex)->size,
                   g_task[i].weight);
        }
#if DEBUG_VERIFY == 1
        printf("\n");
#endif
        /* CRC's are always computed with seed 0 */
        ee_srand(0);
        (*g_task[i].func)(g_task[i].ex, g_task[i].n, 1, &res);
        g_task[i].actual_crc = res.crc;
#if DEBUG_VERIFY == 0
#if CRC_ONLY == 0
        /* First, compute the correct # of iterations for each primitive. */
        iterations = tune_iterations(g_task[i].ex, g_task[i].n, g_task[i].func);
        g_task[i].actual_crc = res.crc;
        /* Now do a run with the correct number of iterations to get ips */
        (*g_task[i].func)(g_task[i].ex, g_task[i].n, iterations, &res);
        g_task[i].ips = (float)iterations / (res.dt / 1e6f);
#endif
        /**
         * Generate the component and final scores.
         *
         * As stated in the User Guide, the score of the benchmark is the sum of
         * the weighted runtimes, inverted (so that decreasing time indicates
         * increasing score), and then multiplied by 1000 to scale into an
         * integer range.
         */
        component_score = g_task[i].weight / g_task[i].ips;
        score += component_score;
        printf("%15.3f", g_task[i].ips);
        if (g_task[i].actual_crc != g_task[i].expected_crc)
        {
            printf(" ***ERROR: CRCs did not match, expected 0x%04x, got 0x%04x",
                   g_task[i].expected_crc,
                   g_task[i].actual_crc);
        }
#if CRC_ONLY == 0
        if (res.dt < MIN_RUNTIME_USEC)
        {
            printf(" ***ERROR: Not enough runtime %.3f sec.", res.dt / 1.0e6f);
        }
#endif
        printf("\n");
#endif /* DEBUG_VERIFY */
    }
    score = 1000.0f / score;
    printf("\n");
    printf("SecureMark-TLS Score is %.3f marks\n", score);
    printf(
        "Disclaimer: this is not an official score. In order to submit an\n"
        "official score, please contact support@eembc.org.\n");
    return 0;
}
