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
// Pre-made keys just for this self-hosted main.c
#include "keys.h"
#include <stdint.h>
#include <assert.h>

// There are several POSIX assumptions in this implementation.
#if (__linux__ || __APPLE__)
#include <time.h>
#elif _WIN32
#include <sys\timeb.h>
#else
#error "Operating system not recognized"
#endif

// Longest time to run each primitive during self-tuning
#define MIN_RUNTIME_SEC  10u
#define MIN_RUNTIME_USEC (MIN_RUNTIME_SEC * 1000u * 1000u)
// Minimum number of iterations allowed per primitive
#define MIN_ITER 10u
// Stored timestamps (a single primitive may generate multiple stamps)
#define MAX_TIMESTAMPS 64u
// `true` to turn on debugging messages
#define DEBUG_VERIFY false
// Only run a single iteration of each task (for debug)
#define DO_SINGLE
// All wrapper functions fit this prototype (n=dataset octets, i=iterations)
typedef uint16_t wrapper_function_t(unsigned int n, unsigned int i);
/**
 * This variable indicates that timestamps should be ignored. It is used when
 * performing composite operations with multiple primitives that generate
 * multiple timestamps. For example, encrypting before a decrypt. Porting
 * developers do not need to worry about this.
 */
// defined in profile/ee_profile.c
extern bool g_verify_mode;
/**
 * We always create pseudo-random keys and plaintext for benchmarking purposes;
 * this is not the same as entropy, this is just for reproducable (seed-able)
 * testing.
 */
// defined in profile/ee_profile.c
void ee_srand(unsigned char);

/** TIMESTAMP IMPLEMENTATION **************************************************/

/**
 * The framework expects an external agent to monitor the timestamp message.
 * Since there is no external agent, create a local stack of stamps.
 */
static uint64_t g_timestamps[MAX_TIMESTAMPS];
static size_t   g_stamp_idx = 0;

void
push_timestamp(uint64_t us)
{
    assert(g_stamp_idx < MAX_TIMESTAMPS);
    g_timestamps[g_stamp_idx] = us;
    ++g_stamp_idx;
}

void
clear_timestamps(void)
{
    g_stamp_idx = 0;
    /*@-redef*/ /*@-retvalother*/
    th_memset(g_timestamps, 0, MAX_TIMESTAMPS * sizeof(uint64_t));
}

/**
 * Here we have completely redfined th_timestamp. Instead of generating a
 * GPIO, it issues a string (optional, since there is nothing to read it),
 * but it also pushes a timestamp to the g_timestamps array for later
 * retrieval.
 *
 * This example uses POSIX clock_gettime(). If your platform does not
 * support this function, implement something with at LEAST millisecond
 * accuracy. Do not remove the verify conditional or the push.
 *
 * In order to ensure the basic functionality remains untouched, only edit
 * the code in the "USER CODE" segments.
 */
void
th_timestamp(void)
{
    // --- BEGIN USER CODE 1
#if (__linux__ || __APPLE__)
    struct timespec t;
    /*@-unrecog*/
    clock_gettime(CLOCK_REALTIME, &t);
#elif _WIN32
    struct timeb t;
    uint64_t     elapsedMicroSeconds;

    ftime(&t);
#else
#error "Operating system not recognized"
#endif
    // --- END USER CODE 1
    if (g_verify_mode)
    {
        return;
    }
    else
    {
        // --- BEGIN USER CODE 2
#if (__linux__ || __APPLE__)
        const unsigned long NSEC_PER_SEC      = 1000000000UL;
        const unsigned long TIMER_RES_DIVIDER = 1000UL;
        uint64_t            elapsedMicroSeconds;
        /*@-usedef*/
        elapsedMicroSeconds = t.tv_sec * (NSEC_PER_SEC / TIMER_RES_DIVIDER)
                              + t.tv_nsec / TIMER_RES_DIVIDER;
#elif _WIN32
        elapsedMicroSeconds
            = ((uint64_t)t.time) * 1000 * 1000 + ((uint64_t)t.millitm) * 1000;
#else
#error "Operating system not recognized"
#endif
        // --- END USER CODE 2
        th_printf(EE_MSG_TIMESTAMP, elapsedMicroSeconds);
        push_timestamp(elapsedMicroSeconds);
    }
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
    uint8_t i;
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

uint16_t
pre_wrap_sha(sha_size_t size, unsigned int n, unsigned int i)
{
    uint8_t *p = th_buffer_address();
    size_t   x;
    uint16_t crc;

    // Emulate host by using the buffer
    assert(th_buffer_size() > (n + (size / 8)));

    bench_sha(size, n, i, DEBUG_VERIFY);

    for (crc = 0, x = 0; x < (size / 8); ++x)
    {
        crc = crcu16(crc, (uint8_t)(p + n)[x]);
    }
    return crc;
}

#define MAKE_WRAP_SHA(x)                                 \
    uint16_t wrap_sha##x(unsigned int n, unsigned int i) \
    {                                                    \
        return pre_wrap_sha(EE_SHA##x, n, i);            \
    }

MAKE_WRAP_SHA(256)
MAKE_WRAP_SHA(384)

uint16_t
pre_wrap_aes(aes_cipher_mode_t mode,   // input: cipher mode
             aes_function_t    func,   // input: func (AES_ENC|AES_DEC)
             uint32_t          keylen, // input: length of key in bytes
             uint32_t          n,      // input: length of input in bytes
             uint32_t          i       // input: # of test iterations
)
{
    uint8_t *p_out;
    int      ivlen = mode == AES_CTR ? AES_CTR_IVSIZE : AES_AEAD_IVSIZE;
    uint16_t crc;
    size_t   x;

    // Emulate host by using the buffer
    assert(th_buffer_size() > (keylen + ivlen + keylen /*tag*/ + n + n));
    p_out = th_buffer_address() + keylen + ivlen + n;

    bench_aes(mode, func, keylen, n, i, DEBUG_VERIFY);

    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)p_out[x]);
    }
    return crc;
}

#define MAKE_WRAP_AES(bits, MODE, nick)                                        \
    uint16_t wrap_aes##bits##_##nick##_encrypt(unsigned int n, unsigned int i) \
    {                                                                          \
        return pre_wrap_aes(AES_##MODE, AES_ENC, bits / 8, n, i);              \
    }                                                                          \
    uint16_t wrap_aes##bits##_##nick##_decrypt(unsigned int n, unsigned int i) \
    {                                                                          \
        return pre_wrap_aes(AES_##MODE, AES_DEC, bits / 8, n, i);              \
    }

MAKE_WRAP_AES(128, ECB, ecb)
MAKE_WRAP_AES(128, CTR, ctr)
MAKE_WRAP_AES(128, CCM, ccm)
MAKE_WRAP_AES(128, GCM, gcm)
MAKE_WRAP_AES(256, ECB, ecb)
MAKE_WRAP_AES(256, CTR, ctr)
MAKE_WRAP_AES(256, CCM, ccm)

uint16_t
pre_wrap_chachapoly(chachapoly_func_t func, unsigned int n, unsigned int i)
{
    uint8_t *p_out;
    uint16_t crc;
    size_t   x;

    // Emulate host by using the buffer
    assert(th_buffer_size() > (EE_CHACHAPOLY_KEYSIZE + EE_CHACHAPOLY_IVSIZE
                               + EE_CHACHAPOLY_TAGSIZE + +n));
    p_out = th_buffer_address() + EE_CHACHAPOLY_KEYSIZE + EE_CHACHAPOLY_IVSIZE
            + n;

    bench_chachapoly(func, n, i, DEBUG_VERIFY);

    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)p_out[x]);
    }
    return crc;
}

uint16_t
wrap_chachapoly_encrypt(unsigned int n, unsigned int i)
{
    return pre_wrap_chachapoly(EE_CHACHAPOLY_ENC, n, i);
}
uint16_t
wrap_chachapoly_decrypt(unsigned int n, unsigned int i)
{
    return pre_wrap_chachapoly(EE_CHACHAPOLY_DEC, n, i);
}

uint16_t
pre_wrap_ecdh(ecdh_group_t g, unsigned int n, unsigned int i)
{
    uint8_t *p = th_buffer_address();
    size_t   x;
    uint16_t crc;

    // Emulate host download by copying our local keys into the buffer
    assert(th_buffer_size() > (ee_pub_sz[g] + ee_pri_sz[g] + ee_sec_sz[g]));
    th_memcpy(p, g_ecc_peer_public_keys[g], ee_pub_sz[g]);
    p += ee_pub_sz[g];
    th_memcpy(p, g_ecc_private_keys[g], ee_pri_sz[g]);
    p += ee_pri_sz[g];

    bench_ecdh(g, i, DEBUG_VERIFY);

    for (crc = 0, x = 0; x < ee_sec_sz[g]; ++x)
    {
        crc = crcu16(crc, (uint8_t)p[x]);
    }
    return crc;
}

#define MAKE_WRAP_ECDH(nick, group)                           \
    uint16_t wrap_ecdh_##nick(unsigned int n, unsigned int i) \
    {                                                         \
        return pre_wrap_ecdh(group, n, i);                    \
    }

MAKE_WRAP_ECDH(p256r1, EE_P256R1)
MAKE_WRAP_ECDH(p384, EE_P384)
MAKE_WRAP_ECDH(x25519, EE_C25519)

uint16_t
pre_wrap_ecdsa(ecdh_group_t g, ecdsa_function_t func, uint32_t n, uint32_t i)
{
    uint8_t *p = th_buffer_address();
    size_t   x;
    uint16_t crc;

    // We ALWAYS sign a SHA256 hash, regardless of the algorithm.
    assert(n == 32);
    // Emulate host download by copying our local keys into the buffer
    // ASN.1 adds 3 encode bytes, 3 size bytes, and up to two pad bytes
    assert(th_buffer_size() > (ee_pri_sz[g] + n + (ee_sig_sz[g] + 8)));

    ee_buffer_fill(0);
    th_memcpy(p, g_ecc_private_keys[g], ee_pri_sz[g]);
    p += ee_pri_sz[g];
    th_memcpy(p, g_dsa_message, 32);
    p += 32;

    if (func == EE_ECDSA_VERIFY)
    {
        // Can't use the DUT to create the verify to check against. We are
        if (g == EE_Ed25519)
        {
            // Ed25519 signatures are raw {R|S} little endianm 64 byte
            th_memcpy(p, g_dsa_signatures[g], 64);
        }
        else
        {
            // EcDSA signatures are ASN.1, and are < 256 bytes for our case.
            // Byte 1 of the ASN.1 signature contains the size of the sig.
            th_memcpy(p, g_dsa_signatures[g], g_dsa_signatures[g][1] + 2);
        }
    }

    bench_ecdsa(g, func, n, i, DEBUG_VERIFY);

    // Since bench_ecdsa doesn't return slen, we CRC 512 bytes of the buffer,
    // which we already zeroed, and 512 is definitely more than we used.
    for (crc = 0, x = 0, p = th_buffer_address(); x < 512; ++x)
    {
        crc = crcu16(crc, (uint8_t)p[x]);
    }
    return crc;
}

#define MAKE_WRAP_ECDSA(nick, group)                                  \
    uint16_t wrap_ecdsa_sign_##nick(unsigned int n, unsigned int i)   \
    {                                                                 \
        return pre_wrap_ecdsa(group, EE_ECDSA_SIGN, n, i);            \
    }                                                                 \
    uint16_t wrap_ecdsa_verify_##nick(unsigned int n, unsigned int i) \
    {                                                                 \
        return pre_wrap_ecdsa(group, EE_ECDSA_VERIFY, n, i);          \
    }

MAKE_WRAP_ECDSA(p256r1, EE_P256R1)
MAKE_WRAP_ECDSA(p384, EE_P384)
MAKE_WRAP_ECDSA(ed25519, EE_Ed25519)

#define MAX_MODULUS 512
uint16_t
pre_wrap_rsa(ee_rsa_id_t       id,
             ee_rsa_function_t func,
             unsigned int      n,
             unsigned int      i)
{
    // Emulate host download by copying our local keys into the buffer
    uint32_t *p_prilen = (uint32_t *)th_buffer_address();
    uint8_t * p_pri    = (uint8_t *)p_prilen + sizeof(uint32_t);
    uint32_t *p_msglen;
    uint8_t * p_msg;
    uint32_t *p_siglen;
    uint8_t * p_sig;
    uint16_t  crc;
    size_t    x;

    assert(th_buffer_size() > (MAX_MODULUS + n + sizeof(g_rsa_private_key_4096)
                               + (2 * sizeof(uint32_t))));
    assert(n == 32);

    switch (id)
    {
        case EE_RSA_2048:
            *p_prilen = sizeof(g_rsa_private_key_2048);
            th_memcpy(p_pri, g_rsa_private_key_2048, *p_prilen);
            break;
        case EE_RSA_3072:
            *p_prilen = sizeof(g_rsa_private_key_3072);
            th_memcpy(p_pri, g_rsa_private_key_3072, *p_prilen);
            break;
        case EE_RSA_4096:
            *p_prilen = sizeof(g_rsa_private_key_4096);
            th_memcpy(p_pri, g_rsa_private_key_4096, *p_prilen);
            break;
        default:
            printf("Invalid RSA case\n");
            exit(-1);
            break;
    }

    p_msglen  = (uint32_t *)(p_pri + *p_prilen);
    *p_msglen = sizeof(g_dsa_message);
    p_msg     = (uint8_t *)p_msglen + sizeof(uint32_t);
    th_memcpy(p_msg, g_dsa_message, *p_msglen);
    p_siglen = (uint32_t *)(p_msg + *p_msglen);

    switch (id)
    {
        case EE_RSA_2048:
            *p_siglen = sizeof(g_rsa_sig_2048);
            p_sig     = (uint8_t *)p_siglen + sizeof(uint32_t);
            th_memcpy(p_sig, g_rsa_sig_2048, *p_siglen);
            break;
        case EE_RSA_3072:
            *p_siglen = sizeof(g_rsa_sig_3072);
            p_sig     = (uint8_t *)p_siglen + sizeof(uint32_t);
            th_memcpy(p_sig, g_rsa_sig_3072, *p_siglen);
            break;
        case EE_RSA_4096:
            *p_siglen = sizeof(g_rsa_sig_4096);
            p_sig     = (uint8_t *)p_siglen + sizeof(uint32_t);
            th_memcpy(p_sig, g_rsa_sig_4096, *p_siglen);
            break;
        default:
            printf("Invalid RSA case\n");
            exit(-1);
            break;
    }

    bench_rsa(id, func, n, i, DEBUG_VERIFY);

    for (crc = 0, x = 0; x < *p_siglen; ++x)
    {
        crc = crcu16(crc, (uint8_t)p_sig[x]);
    }
    return crc;
}

#define MAKE_WRAP_RSA(nick, id)                                     \
    uint16_t wrap_rsa_sign_##nick(unsigned int n, unsigned int i)   \
    {                                                               \
        return pre_wrap_rsa(id, EE_RSA_SIGN, n, i);                 \
    }                                                               \
    uint16_t wrap_rsa_verify_##nick(unsigned int n, unsigned int i) \
    {                                                               \
        return pre_wrap_rsa(id, EE_RSA_VERIFY, n, i);               \
    }

MAKE_WRAP_RSA(2048, EE_RSA_2048)
MAKE_WRAP_RSA(3072, EE_RSA_3072)
MAKE_WRAP_RSA(4096, EE_RSA_4096)

uint16_t
wrap_variation_001(unsigned int n, unsigned int i)
{
    n = 0; // unused
    ee_variation_001(i);
    /**
     * There is no way to compute CRC without touching deeper code, but since
     * we've already exercised the primitives in the variation, we don't
     * actually need a CRC.
     */
    return (uint16_t)0;
}

/** TUNING FUNCTION ***********************************************************/

/**
 * The benchmark wrappers all take an datasize, n, and a number of
 * iterations, i. This function increases i by a proportional amount
 * computed from the current iterations per second and returns the number
 * of iterations required by the benchmark.
 */
size_t
tune_iterations(unsigned int n, wrapper_function_t *func)
{
    size_t   iter;
    size_t   total_iter;
    uint64_t total_us;
    float    ipus;
    float    delta;

    iter       = MIN_ITER;
    total_iter = 0;
    total_us   = 0;

    while (total_us < MIN_RUNTIME_USEC)
    {
        clear_timestamps();
        (*func)(n, iter);
        total_iter += iter;
        total_us += g_timestamps[1] - g_timestamps[0];

        if (total_us > 0)
        {
            ipus  = (float)total_iter / total_us;
            delta = (float)MIN_RUNTIME_USEC - total_us;
            iter  = (size_t)(ipus * delta);
            iter  = iter == 0 ? 1 : iter;
        }
        else if (total_us == 0)
        {
            th_printf("e-[Loop time was zero microseconds, unlikely.]\r\n");
            exit(-1);
        }
        else
        {
            iter *= 2;
        }
    }
    return total_iter;
}

// We tune each function independently by using a table entry for each wrapper:
typedef struct
{
    wrapper_function_t *func;         // The primitive for this task
    uint16_t            n;            // Number of octets for input data
    float               ips;          // iterations-per-second
    float               weight;       // equation scaling weight
    uint16_t            actual_crc;   // CRC computed for 1 iter. seed 0
    uint16_t            expected_crc; // Precomputed CRC by EEMBC
    char *              name;
} task_entry_t;

#define TASK(name, n, w, crc) \
    { wrap_##name, n, 0.0, (float)w, 0x0, crc, #name },

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
    /*
     *   Macro nickname       ,Bytes, weight, crc
     */
    // V1 - TLS 1.2 (note CRCs changed due to new keys & wrappers)
    // For Medium
    TASK(aes128_ecb_encrypt   ,  320,  1.0f, 0x0b7a)
    TASK(aes128_ccm_encrypt   ,   52,  1.0f, 0xd82d)
    TASK(aes128_ccm_decrypt   ,  168,  1.0f, 0x005b)
    TASK(ecdh_p256r1          ,    0,  1.0f, 0x32af)
    TASK(ecdsa_sign_p256r1    ,   32,  1.0f, 0xae0a)
    TASK(ecdsa_verify_p256r1  ,   32,  2.0f, 0xae0a)
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
    TASK(aes256_ccm_decrypt   ,  168,  1.0f, 0xd7ff)
    // NOTE: WolfCrypt has a problem here, compute CRC with mbedTLS
    TASK(ecdsa_sign_p384      ,   32,  1.0f, 0xac10)
    TASK(ecdsa_verify_p384    ,   32,  2.0f, 0xfe20)
    TASK(sha384               ,   23,  3.0f, 0x9f68)
    TASK(sha384               ,   57,  1.0f, 0x8a5c)
    TASK(sha384               ,  384,  1.0f, 0xb5e8)
    TASK(sha384               , 4224,  4.0f, 0xb146)
    TASK(aes256_ecb_encrypt   , 2048, 10.0f, 0x2364)
    // V2 - TLS 1.3 & Secure Boot Components
    // Key Exchange
    TASK(ecdh_p256r1          ,    0,  1.0f, 0x32af)
    TASK(ecdh_p384            ,    0,  1.0f, 0xcd83)
    TASK(ecdh_x25519          ,    0,  1.0f, 0xa94c)
    // DSA Sign
    // TASK(ecdsa_sign_p256r1    ,   32,  1.0f, 0x4cc0)
    TASK(sha256               , 1539,  1.0f, 0xb48c)
    // TASK(ecdsa_sign_p384      ,   32,  1.0f, 0x709d)
    TASK(sha384               , 1539,  1.0f, 0x7cbc)
    TASK(ecdsa_sign_ed25519   ,   32,  1.0f, 0x7dbb)
    // DSA Verify
    TASK(sha256               , 4104,  2.0f, 0x39c9)
    TASK(sha384               , 4104,  2.0f, 0xa424)
    TASK(ecdsa_verify_ed25519 ,   32,  2.0f, 0x7dbb)
    // AEAD
    TASK(aes128_ccm_encrypt   ,  416,  1.0f, 0x286a)
    TASK(aes128_ccm_decrypt   ,  444,  1.0f, 0x4256)
    TASK(aes128_ccm_encrypt   ,   38,  1.0f, 0x5137)
    TASK(aes128_ccm_decrypt   ,  136,  1.0f, 0xe8db)
    // -
    TASK(aes256_ccm_encrypt   ,  416,  1.0f, 0x28dd)
    TASK(aes256_ccm_decrypt   ,  444,  1.0f, 0x9dc7)
    TASK(aes256_ccm_encrypt   ,   38,  1.0f, 0xd879)
    TASK(aes256_ccm_decrypt   ,  136,  1.0f, 0xf288)
    // -
    TASK(aes128_gcm_encrypt   ,  416,  1.0f, 0xa22f)
    TASK(aes128_gcm_decrypt   ,  444,  1.0f, 0x7ca3)
    TASK(aes128_gcm_encrypt   ,   38,  1.0f, 0x9970)
    TASK(aes128_gcm_decrypt   ,  136,  1.0f, 0x0e7e)
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
    TASK(rsa_verify_2048      ,   32,  1.0f, 0x8a62)
    TASK(rsa_verify_3072      ,   32,  1.0f, 0x1ed4)
    TASK(rsa_verify_4096      ,   32,  1.0f, 0x7147)
};
// clang-format on
static const size_t g_numtasks = sizeof(g_task) / sizeof(task_entry_t);

int
main(void)
{
    size_t i;
    size_t iterations;
    float  component_score;
    float  score;

    printf("Running each primitive for at least %us or %u iterations.\n",
           MIN_RUNTIME_SEC,
           MIN_ITER);

    printf("Heap buffer is %ld bytes\n", th_buffer_size());
    score = 0.0f;
    printf(" # Component                  data   w    iterations/s\n");
    printf("-- ------------------------- ----- --- ---------------\n");
    for (i = 0; i < g_numtasks; ++i)
    {
#ifdef DO_SINGLE
        iterations = 1;
        ee_srand(0); // CRCs are computed with seed 0
        g_task[i].actual_crc = (*g_task[i].func)(g_task[i].n, iterations);
        clear_timestamps();
#else
        // First, compute the correct # of iterations for each primitive
        iterations = tune_iterations(g_task[i].n, g_task[i].func);
        // Compute a CRC from a single iteration, also warm up the test
        ee_srand(0); // CRCs are computed with seed 0
        g_task[i].actual_crc = (*g_task[i].func)(g_task[i].n, 1);
        // Now do a run with the correct number of iterations to get ips
        clear_timestamps();
        (*g_task[i].func)(g_task[i].n, iterations);
        g_task[i].ips
            = (float)iterations / ((g_timestamps[1] - g_timestamps[0]) / 1e6f);
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
        printf("%2ld %-25s %5d %3.0f %15.3f",
               i + 1,
               g_task[i].name,
               g_task[i].n,
               g_task[i].weight,
               g_task[i].ips);
        if (g_task[i].actual_crc != g_task[i].expected_crc)
        {
            printf(" ***ERROR: CRCs did not match, expected 0x%04x, got 0x%04x",
                   g_task[i].expected_crc,
                   g_task[i].actual_crc);
        }
        printf("\n");
    }
    score = 1000.0f / score;
    printf("SecureMark-TLS Score is %.3f marks\n", score);
    printf(
        "Disclaimer: this is not an official score. In order to submit an\n"
        "official score, please contact support@eembc.org.\n");
    return 0;
}
