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
 * the IoTConnect framework. The function main() invokes all of the benchmark
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
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_sha.h"
#include "ee_variations.h"

#include <inttypes.h>

// There are several POSIX assumptions in this implementation.
#if defined __linux__ || __APPLE__
#include <time.h>
#elif _WIN32
#include <sys\timeb.h>
#else
#error "Operating system not recognized"
#endif
#include <assert.h>

// Longest time to run each primitive during self-tuning
#define MIN_RUNTIME_SEC  10u
#define MIN_RUNTIME_USEC (MIN_RUNTIME_SEC * 1000u * 1000u)
// Minimum number of iterations allowed per primitive
#define MIN_ITER 10u
// Stored timestamps (a single primitive may generate multiple stamps)
#define MAX_TIMESTAMPS 64u

// All wrapper functions fit this prototype (n=dataset octets, i=iterations)
typedef uint16_t wrapper_function_t(unsigned int n, unsigned int i);

// 'Wrappers' are generic enough that we only need dataset and iterations.
wrapper_function_t wrap_aes_ecb_encrypt;
wrapper_function_t wrap_aes_ecb_decrypt;
wrapper_function_t wrap_aes_ccm_encrypt;
wrapper_function_t wrap_aes_ccm_decrypt;
wrapper_function_t wrap_ecdh;
wrapper_function_t wrap_ecdsa_sign;
wrapper_function_t wrap_ecdsa_verify;
wrapper_function_t wrap_sha256;
wrapper_function_t wrap_variation_001;

// We tune each function independently by using a table entry for each wrapper:
typedef struct
{
    wrapper_function_t *func;         // The primitive for this task
    unsigned int        n;            // Number of octets for input data
    float               ips;          // iterations-per-second
    float               weight;       // equation scaling weight
    uint16_t            actual_crc;   // CRC computed for 1 iter. seed 0
    uint16_t            expected_crc; // Precomputed CRC by EEMBC
} task_entry_t;

/**
 * The following task table consists of a list of primitives observed during
 * a TLSv1.2 handshake.
 *
 * The provided datasizes reflect the actual values of a TLSv1.2 handshake using
 * the TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 ciphersuite. These numbers
 * were collected by instrumenting TLS handshake with open_ssl.
 *
 * The weights are used for scoring and were defined by the team in 2018.
 *
 * The expected_crc value was computed by EEMBC using mbedTLS. The intent
 * of this field is to help detected mistakes in the implementation, or errant
 * bugs introduced while porting the firmware.
 *
 * The CRC of the resulting output should be the same regardless of the
 * software or hardware implementation. Changing the seeds or the input
 * Q/d ECC keys will break the CRC.
 */
// clang-format off
static task_entry_t g_task[] =
{
    { wrap_aes_ecb_encrypt,  144, 0.0f,  1.0f, 0x0, 0xc7b0 }, /*  0 */
    { wrap_aes_ecb_encrypt,  224, 0.0f,  1.0f, 0x0, 0x5481 }, /*  1 */
    { wrap_aes_ecb_encrypt,  320, 0.0f,  1.0f, 0x0, 0x998a }, /*  2 */
    { wrap_aes_ccm_encrypt,   52, 0.0f,  1.0f, 0x0, 0xd82d }, /*  3 */
    { wrap_aes_ccm_decrypt,  168, 0.0f,  1.0f, 0x0, 0x005b }, /*  4 */
    { wrap_ecdh           ,    0, 0.0f,  1.0f, 0x0, 0xb659 }, /*  5 */
    { wrap_ecdsa_sign     ,    0, 0.0f,  1.0f, 0x0, 0x3a47 }, /*  6 */
    { wrap_ecdsa_verify   ,    0, 0.0f,  2.0f, 0x0, 0x3a47 }, /*  7 */
    { wrap_sha256         ,   23, 0.0f,  3.0f, 0x0, 0x2151 }, /*  8 */
    { wrap_sha256         ,   57, 0.0f,  1.0f, 0x0, 0x3b3c }, /*  9 */
    { wrap_sha256         ,  384, 0.0f,  1.0f, 0x0, 0x1d3f }, /* 10 */
    { wrap_variation_001  ,    0, 0.0f,  3.0f, 0x0, 0x0000 }, /* 11 */
    { wrap_sha256         , 4224, 0.0f,  4.0f, 0x0, 0x9284 }, /* 12 */
    { wrap_aes_ecb_encrypt, 2048, 0.0f, 10.0f, 0x0, 0x989e }, /* 13 */
};
// clang-format on
static const size_t g_numtasks = sizeof(g_task) / sizeof(task_entry_t);

/**
 * Use this variable to suppress certain timestamps. For example, before
 * running AES decryption, we first must encrypt the plaintext. If we didn't
 * turn off timestamps on the encrypt, we would end up with four timestamps
 * in the g_timestamps array; whereas we only need two because of how we
 * implement self-hosted performance analysis.
 */
// defined in profile/ee_profile.c
extern bool g_verify_mode;
/**
 * We always create pseudo-random keys and plaintext for benchmarking purposes;
 * this is not the same as entropy, this is just for reproducable (seed-able)
 * testing.
 */
// defined in profile/ee_profile.c
unsigned char ee_rand(void);
void          ee_srand(unsigned char);

/** PRE-GENERATED ECC POINTS **************************************************/

/**
 * These are the keys taken from the Host GUI when running benchmark mode.
 * This assumes 'char' is always an octet (probably safe for today's MCUs).
 */
// clang-format off
// Peer public key, 'Q'
static unsigned char g_ecc_peer_public_key[] =
{
// Q.X
0x01,0x2a,0x23,0x0e,0xbe,0xfc,0x7e,0x6d,0xc6,0xe2,0x8f,0x4f,0xc3,0xba,0x66,0x0f,
0xba,0x40,0xef,0xa7,0x7c,0xd9,0xf3,0x0d,0xdc,0xc7,0x2c,0x57,0x2f,0x67,0xfa,0x0f,
// Q.Y
0xfc,0x58,0xaf,0x84,0xac,0xdc,0x46,0xfc,0x05,0xf9,0xba,0x84,0xfb,0x60,0xb7,0xb5,
0xd8,0x9b,0xb2,0xa6,0x76,0x1f,0xce,0x8e,0x06,0x73,0x28,0x7e,0x6d,0x7b,0xbb,0x46
};
// Private key, 'd'
static unsigned char g_ecc_private_key[] =
{
0x6e,0x24,0x26,0x96,0x5f,0x12,0x90,0x18,0xbe,0x06,0xf7,0x09,0x2c,0xdf,0x83,0x22,
0x33,0x8e,0x3e,0x65,0x74,0x61,0x61,0x03,0x6d,0x61,0x55,0xf9,0xcb,0x14,0x44,0x70
};
// clang-format on

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
#if defined __linux__ || __APPLE__
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
#if defined __linux__ || __APPLE__
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

/** PRINTF ********************************************************************/

/**
 * The function th_printf() is used extensively throughout the monitor and
 * profile code. However, for the self-hosted mode, it is not required. You
 * may comment out the content of this function with no consequence.
 */
void
th_printf(const char *fmt, ...)
{
#if EE_CFG_QUIET != 1
    va_list args;
    va_start(args, fmt);
    /*@-retvalint*/
    th_vprintf(fmt, args);
    va_end(args);
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
wrap_sha256(unsigned int n, unsigned int i)
{
    unsigned char *buffer;
    unsigned int   buflen;
    unsigned char *in;
    unsigned char *out;
    unsigned int   x;
    uint16_t       crc;

    buflen = n + SHA_SIZE;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    in  = buffer;
    out = in + n;
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    g_verify_mode = false;
    ee_sha256(buffer, n, out, i);
    for (crc = 0, x = 0; x < SHA_SIZE; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_aes_ccm_encrypt(unsigned int n, unsigned int i)
{
    unsigned char *buffer;
    unsigned int   buflen;
    unsigned char *key;
    unsigned char *iv;
    unsigned char *in;
    unsigned char *tag;
    unsigned char *out;
    unsigned int   x;
    uint16_t       crc;

    buflen = AES_KEYSIZE + AES_IVSIZE + n + AES_TAGSIZE + n;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    key = buffer;
    iv  = key + AES_KEYSIZE;
    in  = iv + AES_IVSIZE;
    tag = in + n;
    out = tag + AES_TAGSIZE;
    // Fill the key, iv, and plaintext with random values
    for (x = 0; x < AES_KEYSIZE; ++x)
    {
        key[x] = ee_rand();
    }
    for (x = 0; x < AES_IVSIZE; ++x)
    {
        iv[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    g_verify_mode = false;
    ee_aes128_ccm(key, iv, in, n, tag, out, AES_ENC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_aes_ccm_decrypt(unsigned int n, unsigned int i)
{
    unsigned char *buffer;
    unsigned int   buflen;
    unsigned char *key;
    unsigned char *iv;
    unsigned char *in;
    unsigned char *tag;
    unsigned char *out;
    unsigned int   x;
    uint16_t       crc;

    buflen = AES_KEYSIZE + AES_IVSIZE + n + AES_TAGSIZE + n;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    key = buffer;
    iv  = key + AES_KEYSIZE;
    in  = iv + AES_IVSIZE;
    tag = in + n;
    out = tag + AES_TAGSIZE;
    // Fill the key, iv, and plaintext with random values
    for (x = 0; x < AES_KEYSIZE; ++x)
    {
        key[x] = ee_rand();
    }
    for (x = 0; x < AES_IVSIZE; ++x)
    {
        iv[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    // Do NOT record timestamps during encrypt! (see th_timestamp())
    g_verify_mode = true;
    // Only need one iteration to create the ciphertext; save time!
    ee_aes128_ccm(key, iv, in, n, tag, out, AES_ENC, 1);
    // Turn on recording timestamps
    g_verify_mode = false;
    ee_aes128_ccm(key, iv, out, n, tag, in, AES_DEC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_aes_ecb_encrypt(unsigned int n, unsigned int i)
{
    unsigned char *buffer;
    unsigned int   buflen;
    unsigned char *key;
    unsigned char *in;
    unsigned char *out;
    unsigned int   x;
    uint16_t       crc;

    buflen = AES_KEYSIZE + n + n;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    // Assign the helper points to the region of the buffer
    key = buffer;
    in  = key + AES_KEYSIZE;
    out = in + n;
    for (x = 0; x < AES_KEYSIZE; ++x)
    {
        key[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    g_verify_mode = false;
    ee_aes128_ecb(key, in, n, out, AES_ENC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_aes_ecb_decrypt(unsigned int n, unsigned int i)
{
    unsigned char *buffer;
    unsigned int   buflen;
    unsigned char *key;
    unsigned char *in;
    unsigned char *out;
    unsigned int   x;
    uint16_t       crc;

    buflen = AES_KEYSIZE + n + n;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    // Assign the helper points to the region of the buffer
    key = buffer;
    in  = key + AES_KEYSIZE;
    out = in + n;
    for (x = 0; x < AES_KEYSIZE; ++x)
    {
        key[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    // Do NOT record timestamps during encrypt! (see th_timestamp())
    g_verify_mode = true;
    // Only need one iteration to create the ciphertext; save time!
    ee_aes128_ecb(key, in, n, out, AES_ENC, 1);
    // Turn on recording timestamps
    g_verify_mode = false;
    ee_aes128_ecb(key, out, n, in, AES_DEC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_ecdh(unsigned int n, unsigned int i)
{
    unsigned char *peerPublicXY;
    unsigned char *privkey;
    unsigned char  shared[ECC_DSIZE];
    unsigned int   x;
    uint16_t       crc;

    n             = 0; // unused
    peerPublicXY  = g_ecc_peer_public_key;
    privkey       = g_ecc_private_key;
    g_verify_mode = false;
    ee_ecdh(peerPublicXY, ECC_QSIZE, privkey, ECC_DSIZE, shared, ECC_DSIZE, i);
    for (crc = 0, x = 0; x < ECC_DSIZE; ++x)
    {
        crc = crcu16(crc, (uint8_t)shared[x]);
    }
    return crc;
}

uint16_t
wrap_ecdsa_sign(unsigned int n, unsigned int i)
{
    n = 0; // unused
    /**
     * ECDSA Sign & Verify a hash
     *
     * Preload buffer with:
     *
     * Value      Size (Bytes)
     * d          32 (Private key uncompressed 32-byte)
     * SHA256     32 (SHA256 Digest to sign)
     */
    unsigned char *privkey;
    unsigned char  hash[HMAC_SIZE];
    unsigned char *sig;
    unsigned int   slen;
    unsigned int   x;
    uint16_t       crc;

    for (x = 0; x < HMAC_SIZE; ++x)
    {
        hash[x] = ee_rand();
    }
    slen = 256; // Note: this is also an input to ee_ecdsa_sign
    sig  = (unsigned char *)th_malloc(slen); // should be 71, 72 B
    assert(sig != NULL);
    privkey       = g_ecc_private_key;
    g_verify_mode = false;
    ee_ecdsa_sign(hash, HMAC_SIZE, sig, &slen, privkey, ECC_DSIZE, i);
    for (crc = 0, x = 0; x < slen; ++x)
    {
        crc = crcu16(crc, (uint8_t)sig[x]);
    }
    th_free(sig);
    return crc;
}

uint16_t
wrap_ecdsa_verify(unsigned int n, unsigned int i)
{
    /**
     * ECDSA Sign & Verify a hash
     *
     * Preload buffer with:
     *
     * Value      Size (Bytes)
     * d          32 (Private key uncompressed 32-byte)
     * SHA256     32 (SHA256 Digest to sign)
     */
    unsigned char *privkey;
    unsigned char  hash[HMAC_SIZE];
    unsigned char *sig;
    unsigned int   slen;
    unsigned int   x;
    uint16_t       crc;

    n = 0; // unused

    for (x = 0; x < HMAC_SIZE; ++x)
    {
        hash[x] = ee_rand();
    }
    slen = 256; // Note: this is also an input to ee_ecdsa_sign
    sig  = (unsigned char *)th_malloc(slen); // should be 71, 72 B
    assert(sig != NULL);
    privkey = g_ecc_private_key;
    // Do NOT record timestamps during encrypt! (see th_timestamp())
    g_verify_mode = true;
    // Only need one iteration to create the signature; save time!
    ee_ecdsa_sign(hash, HMAC_SIZE, sig, &slen, privkey, ECC_DSIZE, 1);
    // Turn on recording timestamps
    g_verify_mode = false;
    ee_ecdsa_verify(hash, HMAC_SIZE, sig, slen, privkey, ECC_DSIZE, i);
    for (crc = 0, x = 0; x < slen; ++x)
    {
        crc = crcu16(crc, (uint8_t)sig[x]);
    }
    th_free(sig);
    return crc;
}

uint16_t
wrap_variation_001(unsigned int n, unsigned int i)
{
    n             = 0; // unused
    g_verify_mode = false;
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
        else
        {
            iter *= 2;
        }
    }
    return total_iter;
}

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

    score = 0.0f;
    for (i = 0; i < g_numtasks; ++i)
    {
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
        /**
         * Generate the component and final scores.
         *
         * As stated in the User Guide, the score of the benchmark is the sum of
         * the weighted runtimes, inverted (so that decreasing time indicates
         * increasing score), and then multiplied by 1000 to scale into an
         * integer range.
         */
        // BUGBUG: If ips=inf due to bug, component score = 0 
        component_score = g_task[i].weight / g_task[i].ips;
        score += component_score;
        printf("Component #%02zu ips=%15.3f crc=0x%04x expected_crc=0x%04x",
               i,
               g_task[i].ips,
               g_task[i].actual_crc,
               g_task[i].expected_crc);
        if (g_task[i].actual_crc != g_task[i].expected_crc)
        {
            printf(" ***ERROR: CRCs did not match");
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
