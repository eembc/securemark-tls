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
#include "ee_chachapoly.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_sha.h"
#include "ee_variations.h"

#include <inttypes.h>
void ee_printmem_be(uint8_t *p_addr, uint_fast32_t len, char *p_user_header);
// There are several POSIX assumptions in this implementation.
#if (__linux__ || __APPLE__)
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
// TODO: V2 wrappers, preliminary (work in progress, this is for testing)
wrapper_function_t wrap_aes_gcm_encrypt;
wrapper_function_t wrap_aes_gcm_decrypt;
wrapper_function_t wrap_chachapoly_seal;
wrapper_function_t wrap_chachapoly_read;
wrapper_function_t wrap_ecdh_ed25519;
wrapper_function_t wrap_ecdsa_sign_ed25519;
wrapper_function_t wrap_ecdsa_verify_ed25519;

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
#define TASK(name, n, w, crc) { name, n, 0.0, (float)w, 0x0, crc, #name },
static task_entry_t g_task[] =
{
    TASK(wrap_ecdh_ed25519         ,    0,  1.0f, 0xb659)
    /*
    TASK(wrap_aes_ecb_encrypt      ,  320,  1.0f, 0x998a)
    TASK(wrap_aes_ccm_encrypt      ,   52,  1.0f, 0xd82d)
    TASK(wrap_aes_ccm_decrypt      ,  168,  1.0f, 0x005b)
    TASK(wrap_ecdh                 ,    0,  1.0f, 0xb659)
    TASK(wrap_ecdh_ed25519         ,    0,  1.0f, 0xb659)
    TASK(wrap_ecdsa_sign           ,    0,  1.0f, 0x3a47)
    TASK(wrap_ecdsa_verify         ,    0,  2.0f, 0x3a47)
    TASK(wrap_sha256               ,   23,  3.0f, 0x2151)
    TASK(wrap_sha256               ,   57,  1.0f, 0x3b3c)
    TASK(wrap_sha256               ,  384,  1.0f, 0x1d3f)
    TASK(wrap_variation_001        ,    0,  3.0f, 0x0000)
    TASK(wrap_sha256               , 4224,  4.0f, 0x9284)
    TASK(wrap_aes_ecb_encrypt      , 2048, 10.0f, 0x989e)
    // TODO: V2 preliminary
    TASK(wrap_aes_gcm_encrypt      ,  256,  1.0f, 0x325b)
    TASK(wrap_aes_gcm_decrypt      ,  256,  1.0f, 0x325b)
    TASK(wrap_chachapoly_seal      ,  256,  1.0f, 0xd80d)
    TASK(wrap_chachapoly_read      ,  256,  1.0f, 0xd80d)
    TASK(wrap_ecdsa_sign_ed25519   ,    0,  1.0f, 0x209d)
    TASK(wrap_ecdsa_verify_ed25519 ,    0,  1.0f, 0x209d)
    */
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

// Peer public key, 'Q' (Raw X & Y)
static uint8_t g_ecc_peer_public_key_p256r1[] =
{
0xc5,0x41,0x62,0xcd,0x04,0xcd,0x4f,0x85,0xbd,0xe5,0x53,0x84,0xf9,0x69,0x03,0x9d,
0xc8,0x0f,0xb5,0x3f,0xf6,0x48,0x99,0x11,0x6e,0x9d,0x0f,0x2c,0x26,0x99,0x34,0xf4,
0x69,0x21,0xb9,0x1c,0x19,0x79,0xfc,0xc4,0xe0,0x9b,0xec,0x00,0xf7,0x7e,0xa7,0xdc,
0x4a,0x1a,0xec,0x3a,0x07,0x9f,0x46,0x99,0xf9,0x22,0x28,0x77,0x13,0x9a,0xf4,0xec,
};

static uint8_t g_ecc_peer_public_key_c25519[] =
{
// Taken from RFC7748 Section 6.1
0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f,
/* Associated private key
0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb,
*/
};

/*
0x4c,0x12,0x26,0xfe,0xac,0xe0,0xd8,0x8b,0xe0,0xe2,0x2c,0xb3,0x82,0x8f,0x99,0x35,
0x01,0x5b,0xa9,0x39,0x21,0x81,0xf5,0x61,0x26,0x2c,0xb9,0x52,0x55,0x53,0xc1,0x98,

*/

/*
0xc4,0x8e,0x2e,0x35,0x88,0xa7,0x2e,0xd9,0xb8,0x68,0x76,0x1f,0xf3,0x98,0x14,0x33,
0x44,0xca,0x2d,0xb4,0x32,0x5f,0x2a,0xfe,0x05,0x3d,0xc8,0x96,0xc7,0x74,0x83,0xcf,
// Associated private key
0x36,0x9b,0xd7,0x54,0xcd,0x57,0x51,0xd0,0x06,0x7e,0x5d,0xd2,0x33,0x50,0xdc,0x9b,
0xd6,0x01,0x3d,0x79,0x30,0x4f,0xf8,0x6c,0x56,0x67,0xcf,0x17,0xa5,0x12,0xd8,0x05,
*/

static uint8_t *g_ecc_peer_public_keys[] = {
    g_ecc_peer_public_key_p256r1,
    g_ecc_peer_public_key_c25519
};

static uint8_t g_ecc_private_key_p256r1[] =
{
0x9e,0x75,0x7e,0x99,0x64,0x28,0xf8,0xfe,0x35,0xbd,0xbd,0xeb,0x07,0x21,0xd7,0xa0,
0xe9,0xa8,0x75,0xcf,0x69,0xea,0xd2,0xa6,0xe5,0xd8,0x77,0x09,0x01,0x78,0x02,0x8d,
// Associated public key
/*
0x75,0x64,0xfd,0x3f,0x96,0xe8,0x79,0x84,0x9b,0xf9,0x7c,0xc8,0xbb,0x28,0x5d,0xa1,
0x27,0x01,0xfb,0x4f,0xd5,0xff,0x4b,0xab,0x7e,0x52,0x17,0xbf,0x09,0x15,0xe9,0x48,
0xb0,0x54,0xbe,0x64,0x70,0xe5,0x28,0xd9,0xe1,0x45,0xfc,0xbc,0xdc,0x01,0x6f,0x6a,
0x4a,0xa1,0x55,0x8b,0x89,0xc8,0xe1,0x6f,0x90,0x1e,0xe1,0xc3,0xd4,0x60,0xa8,0xcc,
*/
};

static uint8_t g_ecc_private_key_c25519[] =
{
// Taken from RFC7748 Section 6.1
0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
/* Associated public key
0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a,
*/
};

static uint8_t *g_ecc_private_keys[] = {
    g_ecc_private_key_p256r1,
    g_ecc_private_key_c25519
};

// HMAC. This is an HMAC generated from a test message to use for sign/verify.
// Message: "EEMBC hash test" -> PKCS1v15/SHA256 -> hex
static uint8_t g_hmac[] = {
0x93,0x75,0xa3,0x23,0xed,0x69,0x76,0x17,0x0e,0x8c,0x01,0xd1,0xdf,0xcb,0xfc,0x6f,
0x38,0x3e,0xf4,0x04,0x04,0xc1,0x4a,0xd0,0xc7,0xc6,0x84,0xde,0x66,0xa2,0x3f,0xd5,
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
    // Emulate the GUI and fail on error message.
    if (fmt[0] == 'e' && fmt[1] == '-')
    {
        exit(1);
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
        exit(1);
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

    buflen = AES_KEYSIZE + AES_IVSIZE + n + n + AES_TAGSIZE;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    key = buffer;
    iv  = key + AES_KEYSIZE;
    in  = iv + AES_IVSIZE;
    out = in + n;
    tag = out + n;

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

    ee_aes128_ccm(key, NULL, 0, iv, in, n, tag, out, AES_ENC, i);
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

    buflen = AES_KEYSIZE + AES_IVSIZE + n + n + AES_TAGSIZE;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    memset(buffer, 0x0, buflen);
    key = buffer;
    iv  = key + AES_KEYSIZE;
    in  = iv + AES_IVSIZE;
    out = in + n;
    tag = out + n;

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
    ee_aes128_ccm(key, NULL, 0, iv, in, n, tag, out, AES_ENC, 1);
    // Turn on recording timestamps
    g_verify_mode = false;
    ee_aes128_ccm(key, NULL, 0, iv, out, n, tag, in, AES_DEC, i);
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
    memset(buffer, 0x0, buflen);
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
    memset(buffer, 0x0, buflen);
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
    peerPublicXY  = g_ecc_peer_public_keys[0];
    privkey       = g_ecc_private_keys[0];
    g_verify_mode = false;
    ee_ecdh(peerPublicXY,
            EE_P256R1,
            ECC_QSIZE,
            privkey,
            ECC_DSIZE,
            shared,
            ECC_DSIZE,
            i);
    for (crc = 0, x = 0; x < ECC_DSIZE; ++x)
    {
        crc = crcu16(crc, (uint8_t)shared[x]);
    }
    return crc;
}

uint16_t
wrap_ecdh_ed25519(unsigned int n, unsigned int i)
{
    unsigned char *public;
    unsigned char *privkey;
    unsigned char  shared[ECC_DSIZE];
    unsigned int   x;
    uint16_t       crc;

    n             = 0; // unused
    public        = g_ecc_peer_public_keys[1];
    privkey       = g_ecc_private_keys[1];
    g_verify_mode = false;
    ee_printmem_be(public, ECC_DSIZE, "public: ");
    ee_printmem_be(privkey, ECC_DSIZE, "privkey: ");
    ee_ecdh(public,
            EE_C25519,
            32,
            privkey,
            32,
            shared,
            32,
            i);
    ee_printmem_be(shared, ECC_DSIZE, "shared: ");
    for (crc = 0, x = 0; x < ECC_DSIZE; ++x)
    {
        crc = crcu16(crc, (uint8_t)shared[x]);
    }
    return crc;
}
uint16_t
wrap_ecdsa_sign_base(ecdh_group_t group, unsigned int n, unsigned int i)
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
    unsigned char *sig;
    uint_fast32_t  slen;
    unsigned int   x;
    uint16_t       crc;

    slen = 256; // Note: this is also an input to ee_ecdsa_sign
    sig  = (unsigned char *)th_malloc(slen);
    assert(sig != NULL);
    memset(sig, 0x0, slen);
    privkey       = g_ecc_private_keys[group];
    g_verify_mode = false;
    ee_ecdsa_sign(group, g_hmac, HMAC_SIZE, sig, &slen, privkey, ECC_DSIZE, i);
    for (crc = 0, x = 0; x < slen; ++x)
    {
        crc = crcu16(crc, (uint8_t)sig[x]);
    }
    th_free(sig);
    return crc;
}

uint16_t
wrap_ecdsa_verify_base(ecdh_group_t group, unsigned int n, unsigned int i)
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
    unsigned char *sig;
    uint_fast32_t  slen;
    unsigned int   x;
    uint16_t       crc;

    n = 0; // unused

    slen = 256; // Note: this is also an input to ee_ecdsa_sign
    sig  = (unsigned char *)th_malloc(slen);
    assert(sig != NULL);
    memset(sig, 0x0, slen);
    privkey = g_ecc_private_keys[group];
    // Do NOT record timestamps during encrypt! (see th_timestamp())
    g_verify_mode = true;
    // Only need one iteration to create the signature; save time!
    ee_printmem_be(privkey, ECC_DSIZE, "secret: ");
    ee_printmem_be(g_hmac, HMAC_SIZE, "hmac: ");
    ee_ecdsa_sign(group, g_hmac, HMAC_SIZE, sig, &slen, privkey, ECC_DSIZE, 1);
    ee_printmem_be(sig, slen, "sig: ");
    // Turn on recording timestamps
    g_verify_mode = false;
    ee_ecdsa_verify(group, g_hmac, HMAC_SIZE, sig, slen, privkey, ECC_DSIZE, i);
    for (crc = 0, x = 0; x < slen; ++x)
    {
        crc = crcu16(crc, (uint8_t)sig[x]);
    }
    th_free(sig);
    return crc;
}

uint16_t
wrap_ecdsa_sign(unsigned int n, unsigned int i)
{
    return wrap_ecdsa_sign_base(EE_P256R1, n, i);
}

uint16_t
wrap_ecdsa_verify(unsigned int n, unsigned int i)
{
    return wrap_ecdsa_verify_base(EE_P256R1, n, i);
}

uint16_t
wrap_ecdsa_sign_ed25519(unsigned int n, unsigned int i)
{
    return wrap_ecdsa_sign_base(EE_C25519, n, i);
}

uint16_t
wrap_ecdsa_verify_ed25519(unsigned int n, unsigned int i)
{
    return wrap_ecdsa_verify_base(EE_C25519, n, i);
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

uint16_t
wrap_aes_gcm_encrypt(unsigned int n, unsigned int i)
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

    buflen = AES_KEYSIZE + AES_IVSIZE + n + n + AES_TAGSIZE;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    key = buffer;
    iv  = key + AES_KEYSIZE;
    in  = iv + AES_IVSIZE;
    out = in + n;
    tag = out + n;

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

    ee_aes128_gcm(key, NULL, 0, iv, in, n, tag, out, AES_ENC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_aes_gcm_decrypt(unsigned int n, unsigned int i)
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

    buflen = AES_KEYSIZE + AES_IVSIZE + n + n + AES_TAGSIZE;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    memset(buffer, 0x0, buflen);
    key = buffer;
    iv  = key + AES_KEYSIZE;
    in  = iv + AES_IVSIZE;
    out = in + n;
    tag = out + n;

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
    ee_aes128_gcm(key, NULL, 0, iv, in, n, tag, out, AES_ENC, 1);
    // Turn on recording timestamps
    g_verify_mode = false;
    ee_aes128_gcm(key, NULL, 0, iv, out, n, tag, in, AES_DEC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}


uint16_t
wrap_chachapoly_seal(unsigned int n, unsigned int i)
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

    buflen
        = CHACHAPOLY_KEYSIZE + CHACHAPOLY_IVSIZE + n + n + CHACHAPOLY_TAGSIZE;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    memset(buffer, 0x0, buflen);
    key = buffer;
    iv  = key + CHACHAPOLY_KEYSIZE;
    in  = iv + CHACHAPOLY_IVSIZE;
    out = in + n;
    tag = out + n;

    // Fill the key, iv, and plaintext with random values
    for (x = 0; x < CHACHAPOLY_KEYSIZE; ++x)
    {
        key[x] = ee_rand();
    }
    for (x = 0; x < CHACHAPOLY_IVSIZE; ++x)
    {
        iv[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    g_verify_mode = false;

    ee_chachapoly(key, NULL, 0, iv, in, n, tag, out, CHACHAPOLY_ENC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_chachapoly_read(unsigned int n, unsigned int i)
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

    buflen
        = CHACHAPOLY_KEYSIZE + CHACHAPOLY_IVSIZE + n + n + CHACHAPOLY_TAGSIZE;
    buffer = (unsigned char *)th_malloc(buflen);
    assert(buffer != NULL);
    memset(buffer, 0x0, buflen);
    key = buffer;
    iv  = key + CHACHAPOLY_KEYSIZE;
    in  = iv + CHACHAPOLY_IVSIZE;
    out = in + n;
    tag = out + n;

    // Fill the key, iv, and plaintext with random values
    for (x = 0; x < CHACHAPOLY_KEYSIZE; ++x)
    {
        key[x] = ee_rand();
    }
    for (x = 0; x < CHACHAPOLY_IVSIZE; ++x)
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
    ee_chachapoly(key, NULL, 0, iv, in, n, tag, out, CHACHAPOLY_ENC, 1);
    // Turn on recording timestamps
    g_verify_mode = false;
    ee_chachapoly(key, NULL, 0, iv, out, n, tag, in, CHACHAPOLY_DEC, i);
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
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
        //iterations = tune_iterations(g_task[i].n, g_task[i].func);
        iterations = 1;
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
        component_score = g_task[i].weight / g_task[i].ips;
        score += component_score;
        printf("Component #%02ld: %25s ips=%15.3f crc=0x%04x expected=0x%04x",
               i + 1,
               g_task[i].name,
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
