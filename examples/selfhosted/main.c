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
#include "ee_util.h"
#include <inttypes.h>

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

// clang-format off

static uint8_t g_ecc_peer_public_key_p256r1[] =
{
// Peer public key, 'Q' (Raw X & Y)
0x34,0xaf,0x0f,0xef,0x6a,0xeb,0xa7,0x10,0x0a,0x78,0x7c,0xa4,0xe2,0xff,0xe9,0xd0,
0x64,0xa0,0x6b,0x0a,0x0f,0xb9,0xc2,0xaf,0x8a,0x6b,0xef,0x5f,0xf2,0x60,0xf0,0x03,
0x71,0xc0,0x09,0x54,0x8c,0x07,0x5d,0xe7,0xa7,0xf1,0x92,0x57,0x22,0x11,0xaa,0x3c,
0x97,0xa8,0x01,0x5e,0x3c,0x9e,0x9e,0x4f,0xe2,0x8d,0xa3,0x15,0x4f,0x5b,0xa8,0x34,
/*
// Associated private key
0x3e,0xfd,0x56,0x58,0xe8,0xd9,0x15,0x8c,0x97,0x0b,0xc1,0x12,0xe6,0x6a,0x4d,0xb3,
0x93,0xa0,0x78,0xf6,0x13,0xfa,0x0e,0xb8,0x6a,0xf0,0x68,0xf0,0x3f,0x4d,0x41,0x23,
*/
};

static uint8_t g_ecc_peer_public_key_p384[] =
{
// Peer public key, 'Q' (Raw X & Y)
0x9c,0x2e,0xfb,0x43,0xcd,0x1c,0x6c,0xa2,0x3b,0x07,0xb6,0x24,0x36,0x0c,0xb7,0x6e,
0x67,0xc0,0x77,0x3c,0xf1,0x58,0x85,0xa3,0x57,0x41,0x37,0xcd,0xf3,0x7e,0x40,0x62,
0x99,0xa4,0x17,0xe1,0x69,0x6a,0x58,0x94,0xa5,0x48,0x73,0x53,0x3b,0x16,0x94,0xc8,
0xca,0x4d,0xa5,0xf1,0x44,0x14,0xea,0x51,0x57,0xed,0x97,0x45,0x75,0xaf,0xbe,0xc2,
0xe0,0xaa,0x03,0x81,0x41,0xb8,0x18,0x21,0xa8,0x4c,0x81,0xba,0xa0,0x69,0xab,0xee,
0x77,0x5a,0x50,0x43,0x60,0x11,0x66,0x3d,0xfb,0x9d,0xd2,0xcf,0xd0,0xfb,0xa9,0xc5,
/*
// Associated private key
0xf6,0x5e,0x08,0x0e,0xff,0xdf,0x48,0xe4,0x51,0x1e,0xd1,0x78,0x4e,0x8b,0x55,0x79,
0x66,0x87,0x6a,0x95,0xf5,0x08,0x4e,0x30,0x97,0x64,0xd1,0x7b,0xc1,0x20,0x70,0x11,
0x4e,0x43,0x03,0xd1,0x71,0xa8,0x28,0xcc,0x40,0x91,0x61,0xe6,0x36,0xdd,0x88,0x51,
*/
};

static uint8_t g_ecc_peer_public_key_c25519[] =
{
// Taken from RFC7748 Section 6.1
// LITTLE-ENDIAN
0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f,
/* Associated private key
// LITTLE-ENDIAN
0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb,
*/
};

static uint8_t g_ecc_peer_public_key_ed25519[] =
{
// Taken from RFC7748 Section 6.1
// LITTLE-ENDIAN
/* Associated private key
// LITTLE-ENDIAN
*/
};

// Order must follow ecdh_group_t in profile/ee_ecdh.h
static uint8_t *g_ecc_peer_public_keys[] = {
    g_ecc_peer_public_key_p256r1,
    g_ecc_peer_public_key_p384,
    g_ecc_peer_public_key_c25519,
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

static uint8_t g_ecc_private_key_p384[] =
{
0x94,0x6a,0xd1,0x2d,0x40,0x8c,0x5a,0x20,0x96,0x86,0xeb,0x21,0x2b,0xc6,0x2c,0x59,
0xdc,0x94,0xe1,0x6b,0xf5,0x01,0xef,0x81,0xa6,0x75,0x4b,0xc1,0xf6,0xc3,0xc3,0xac,
0x83,0x7c,0x7a,0x8a,0x2d,0x47,0xb4,0x98,0x1d,0xb9,0xae,0x77,0xf3,0xb8,0x28,0x19,
// Associated public key
/*
0xee,0x98,0xe9,0xaa,0x26,0x71,0xe8,0x72,0xcd,0x80,0xa9,0x6b,0x26,0x1f,0xb5,0x8d,
0xcf,0x8d,0xe8,0x21,0xd9,0xf8,0x51,0x50,0x3e,0xdc,0x5a,0xa8,0xf6,0x50,0xee,0x7e,
0x11,0xc2,0x24,0x9b,0xe6,0xde,0xe1,0xf3,0x43,0x1d,0x44,0x43,0xd9,0xd7,0x24,0xbf,
0xb3,0xd9,0xea,0xd8,0xd7,0x57,0x4c,0xbc,0x8e,0x6b,0xfa,0x5d,0xb8,0xda,0x9e,0xe6,
0x10,0x91,0x99,0x5d,0x73,0xd4,0x0e,0x4b,0x12,0xa5,0x42,0x9f,0xdc,0xff,0x2b,0x52,
0x55,0xa3,0xf9,0x9f,0x00,0xec,0x9b,0x1b,0x25,0x2d,0xb3,0xaa,0xd7,0x50,0x8b,0x36,
*/
};

static uint8_t g_ecc_private_key_c25519[] =
{
// Taken from RFC7748 Section 6.1
// LITTLE-ENDIAN
0xc8,0xea,0x84,0xfd,0x5d,0x6c,0xa2,0xa4,0x15,0xb3,0x6b,0xb1,0x1d,0x66,0xc8,0x36,
0x0d,0x00,0x6f,0xca,0xf5,0x4a,0x3a,0x6f,0x50,0x65,0xa9,0xc2,0x61,0xb1,0xc0,0x6a,
/* Associated public key
// LITTLE-ENDIAN
0xf8,0x5d,0x06,0x5d,0xd7,0xa4,0xe2,0xb8,0x72,0x27,0xf2,0x38,0x2b,0x44,0x4b,0xf5,
0xd2,0x29,0x60,0x70,0x3c,0xdc,0x86,0xc0,0xef,0xd2,0xd3,0x4d,0x5d,0xe1,0xdb,0x26,
*/
};

// N.B. Ed25519 defines a specific algorithm for key generation
static uint8_t g_ecc_private_key_ed25519[] =
{
// Taken from RFC7748 Section 6.1
// LITTLE-ENDIAN
0x5a,0xb0,0x0d,0x46,0xea,0xd1,0xf3,0xa7,0x8e,0x66,0xde,0x59,0x8a,0xe8,0xbf,0x46,
0x64,0xe4,0xf8,0x05,0xe4,0xe7,0x68,0x0f,0x70,0x67,0xe9,0x82,0x82,0x70,0x56,0xfd,
/* Associated public key
// LITTLE-ENDIAN
0x77,0xee,0xaf,0x7f,0x13,0x65,0xcc,0x5f,0x60,0xcf,0x3d,0x7e,0x08,0xa6,0x2f,0xf0,
0xf8,0x18,0x1a,0xc8,0x1c,0x21,0x29,0xe8,0xf9,0x12,0x7f,0x44,0x26,0xfe,0x58,0x32,
*/
};

// Order must follow ecdh_group_t in profile/ee_ecdh.h
static uint8_t *g_ecc_private_keys[] = {
    g_ecc_private_key_p256r1,
    g_ecc_private_key_p384,
    g_ecc_private_key_c25519,
    g_ecc_private_key_ed25519,
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
#if EE_CFG_QUIET != 1
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
wrap_aes(aes_cipher_mode_t mode,   // input: cipher mode
         aes_function_t    func,   // input: func (AES_ENC|AES_DEC)
         uint_fast32_t     keylen, // input: length of key in bytes
         uint_fast32_t     n,      // input: length of input in bytes
         uint_fast32_t     i       // input: # of test iterations
)
{
    uint8_t *    buffer = NULL;
    unsigned int buflen;
    uint8_t *    key;
    uint8_t *    in;
    uint8_t *    out;
    uint8_t *    iv;
    uint8_t *    tag;
    int          ivlen  = mode == AES_CTR ? AES_CTR_IVSIZE : AES_AEAD_IVSIZE;
    uint8_t      taglen = AES_TAGSIZE;
    uint16_t     crc;
    int          x;

    buflen = keylen + n + n + ivlen + taglen;
    buffer = (uint8_t *)th_malloc(buflen);
    assert(buffer != NULL);
    key = buffer;
    in  = key + keylen;
    out = in + n;
    iv  = out + n;
    tag = iv + ivlen;
    for (x = 0; x < keylen; ++x)
    {
        key[x] = ee_rand();
    }
    for (x = 0; x < ivlen; ++x)
    {
        iv[x] = ee_rand();
    }
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    ee_printmem_hex(key, keylen, "> key :");
    ee_printmem_hex(iv, ivlen, "> iv  :");
    ee_printmem_hex(in, n, "> pt  :");
    if (func == AES_DEC)
    {
        // Encrypt something for the decrypt loop to decrypt
        ee_aes(mode, AES_ENC, key, keylen, iv, in, n, out, tag, NULL, 0, i);
        th_memcpy(in, out, n);
        ee_printmem_hex(in, n, "> pct :");
        ee_printmem_hex(tag, AES_TAGSIZE, "> ptag:");
    }
    ee_aes(mode, func, key, keylen, iv, in, n, out, tag, NULL, 0, i);
    ee_printmem_hex(out, n, "> out :");
    ee_printmem_hex(tag, AES_TAGSIZE, "> tag :");
    for (crc = 0, x = 0; x < n; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

#define MAKE_WRAP_AES(bits, MODE)                                              \
    uint16_t wrap_aes##bits##_##MODE##_encrypt(unsigned int n, unsigned int i) \
    {                                                                          \
        return wrap_aes(AES_##MODE, AES_ENC, bits / 8, n, i);                  \
    }                                                                          \
    uint16_t wrap_aes##bits##_##MODE##_decrypt(unsigned int n, unsigned int i) \
    {                                                                          \
        return wrap_aes(AES_##MODE, AES_DEC, bits / 8, n, i);                  \
    }

MAKE_WRAP_AES(128, ECB)
MAKE_WRAP_AES(128, CTR)
MAKE_WRAP_AES(128, CCM)
MAKE_WRAP_AES(128, GCM)
MAKE_WRAP_AES(256, ECB)
MAKE_WRAP_AES(256, CTR)
MAKE_WRAP_AES(256, CCM)

uint16_t
wrap_sha(sha_size_t size, unsigned int n, unsigned int i)
{
    uint8_t *    buffer;
    unsigned int buflen;
    uint8_t *    in;
    uint8_t *    out;
    unsigned int x;
    unsigned int shalen = size / 8;
    uint16_t     crc;

    buflen = n + shalen;
    buffer = (uint8_t *)th_malloc(buflen);
    assert(buffer != NULL);
    in  = buffer;
    out = in + n;
    for (x = 0; x < n; ++x)
    {
        in[x] = ee_rand();
    }
    g_verify_mode = false;
    ee_sha(size, buffer, n, out, i);
    ee_printmem_hex(in, n, "> in  :");
    ee_printmem_hex(out, shalen, "> out :");
    for (crc = 0, x = 0; x < shalen; ++x)
    {
        crc = crcu16(crc, (uint8_t)out[x]);
    }
    th_free(buffer);
    return crc;
}

#define MAKE_WRAP_SHA(x)                                 \
    uint16_t wrap_sha##x(unsigned int n, unsigned int i) \
    {                                                    \
        return wrap_sha(EE_SHA##x, n, i);               \
    }

MAKE_WRAP_SHA(256)
MAKE_WRAP_SHA(384)

uint16_t
wrap_ecdh(ecdh_group_t group, unsigned int n, unsigned int i)
{
    uint8_t *    pubkey;
    uint8_t *    prikey;
    uint8_t      shared[ee_sec_sz[group]];
    unsigned int x;
    uint16_t     crc;
    n             = 0; // unused
    pubkey        = g_ecc_peer_public_keys[group];
    prikey        = g_ecc_private_keys[group];
    g_verify_mode = false;
    ee_printmem_hex(pubkey, ee_pub_sz[group], "pub : ");
    ee_printmem_hex(prikey, ee_pri_sz[group], "pri : ");
    ee_ecdh(group,
            pubkey,
            ee_pub_sz[group],
            prikey,
            ee_pri_sz[group],
            shared,
            ee_sec_sz[group],
            i);
    ee_printmem_hex(shared, ee_sec_sz[group], "sec : ");
    for (crc = 0, x = 0; x < ee_sec_sz[group]; ++x)
    {
        crc = crcu16(crc, (uint8_t)shared[x]);
    }
    return crc;
}

#define MAKE_WRAP_ECDH(nick, group)                           \
    uint16_t wrap_ecdh_##nick(unsigned int n, unsigned int i) \
    {                                                         \
        return wrap_ecdh(group, n, i);                        \
    }

MAKE_WRAP_ECDH(p256r1, EE_P256R1)
MAKE_WRAP_ECDH(p384, EE_P384)
MAKE_WRAP_ECDH(x25519, EE_C25519)

uint16_t
wrap_ecdsa_sign(ecdh_group_t group, unsigned int n, unsigned int i)
{
    uint8_t *    buffer;
    unsigned int buflen;
    uint8_t *    privkey;
    uint8_t *    sig;
    // Note this is an in/out to slen, as input it is the max siglen
    unsigned int slen = 256;
    unsigned int x;
    uint16_t     crc;
    size_t       keydex;

    // This is a hack because the keys for Ed25519 are not the same as keys
    // made on Curve25519 by mod math.
    keydex = group == EE_C25519 ? 3 : group;

    buflen = n + slen;
    buffer = (uint8_t *)th_malloc(buflen);
    assert(buffer != NULL);
    sig = buffer + n;
    memset(sig, 0x0, slen);
    for (x = 0; x < n; ++x)
    {
        buffer[x] = ee_rand();
    }
    privkey       = g_ecc_private_keys[keydex];
    g_verify_mode = false;
    ee_printmem_hex(privkey, ee_pri_sz[group], "pri ");
    ee_printmem_hex(buffer, n, "msg ");
    ee_ecdsa_sign(group, buffer, n, sig, &slen, privkey, ee_pri_sz[group], i);
    ee_printmem_hex(sig, slen, "sig ");
    for (crc = 0, x = 0; x < slen; ++x)
    {
        crc = crcu16(crc, (uint8_t)sig[x]);
    }
    th_free(buffer);
    return crc;
}

uint16_t
wrap_ecdsa_verify(ecdh_group_t group, unsigned int n, unsigned int i)
{
    uint8_t *    buffer;
    unsigned int buflen;
    uint8_t *    privkey;
    uint8_t *    sig;
    // Note this is an in/out to slen, as input it is the max siglen
    unsigned int slen = 256;
    unsigned int x;
    uint16_t     crc;
    size_t       keydex;

    // This is a hack because the keys for Ed25519 are not the same as keys
    // made on Curve25519 by mod math.
    keydex = group == EE_C25519 ? 3 : group;

    buflen = n + slen;
    buffer = (uint8_t *)th_malloc(buflen);
    assert(buffer != NULL);
    sig = buffer + n;
    memset(sig, 0x0, slen);
    for (x = 0; x < n; ++x)
    {
        buffer[x] = ee_rand();
    }
    privkey       = g_ecc_private_keys[keydex];
    g_verify_mode = false;
    ee_ecdsa_sign(group, buffer, n, sig, &slen, privkey, ee_pri_sz[group], i);
    ee_printmem_hex(privkey, ee_pri_sz[group], "pri ");
    ee_printmem_hex(buffer, n, "msg ");
    ee_printmem_hex(sig, slen, "sig ");
    ee_ecdsa_verify(group, buffer, n, sig, slen, privkey, ee_pri_sz[group], i);
    for (crc = 0, x = 0; x < slen; ++x)
    {
        crc = crcu16(crc, (uint8_t)sig[x]);
    }
    th_free(buffer);
    return crc;
}

#define MAKE_WRAP_ECC_DSA(nick, group) \
    uint16_t wrap_ecdsa_sign_##nick(unsigned int n, unsigned int i) \
    { \
        return wrap_ecdsa_sign(group, n, i); \
    } \
    uint16_t wrap_ecdsa_verify_##nick(unsigned int n, unsigned int i) \
    { \
        return wrap_ecdsa_verify(group, n, i); \
    }

MAKE_WRAP_ECC_DSA(p256r1, EE_P256R1)
MAKE_WRAP_ECC_DSA(p384, EE_P384)
MAKE_WRAP_ECC_DSA(ed25519, EE_C25519)

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
    ee_printmem_hex(key, CHACHAPOLY_KEYSIZE, "key: ");
    ee_printmem_hex(iv, CHACHAPOLY_IVSIZE, "iv : ");
    ee_printmem_hex(in, n, "in : ");
    ee_chachapoly(key, NULL, 0, iv, in, n, tag, out, CHACHAPOLY_ENC, i);
    ee_printmem_hex(out, n, "out: ");
    ee_printmem_hex(tag, CHACHAPOLY_TAGSIZE, "tag: ");
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
 * The weights are used for scoring and were defined by the team in 2018.
 *
 * The expected_crc value was computed by EEMBC using wolfSSL. The intent
 * of this field is to help detected mistakes in the implementation, or errant
 * bugs introduced while porting the firmware.
 *
 * The CRC of the resulting output should be the same regardless of the
 * software or hardware implementation. Changing the seeds or the input
 * Q/d ECC keys will break the CRC.
 *
 * Note 1: This CRC is based on the signature in ASN1 encoding.
 * Note 3: This CRC is based on the signature as raw little-endian bytes.
 * Note 4: All ECDSA is done according to RFC6979 with SHA256
 */
// clang-format off
static task_entry_t g_task[] =
{
    /*   nicname              , data, weight, crc  */
    /*
    TASK(sha256               ,   16,   1.0f, 0x998a)
    TASK(sha384               ,   16,   1.0f, 0x998a)
    TASK(aes128_ECB_encrypt   ,   16,   1.0f, 0x998a)
    TASK(aes128_ECB_decrypt   ,   16,   1.0f, 0x998a)
    TASK(aes256_ECB_encrypt   ,   16,   1.0f, 0x998a)
    TASK(aes256_ECB_decrypt   ,   16,   1.0f, 0x998a)
    TASK(aes128_CTR_encrypt   ,   16,   1.0f, 0x998a)
    TASK(aes128_CTR_decrypt   ,   16,   1.0f, 0x998a)
    TASK(aes256_CTR_encrypt   ,   16,   1.0f, 0x998a)
    TASK(aes256_CTR_decrypt   ,   16,   1.0f, 0x998a)
    TASK(aes128_CCM_encrypt   ,   16,   1.0f, 0x998a)
    TASK(aes128_CCM_decrypt   ,   16,   1.0f, 0x998a)
    TASK(aes256_CCM_encrypt   ,   16,   1.0f, 0x998a)
    TASK(aes256_CCM_decrypt   ,   16,   1.0f, 0x998a)
    TASK(aes128_GCM_encrypt   ,   16,   1.0f, 0x998a)
    TASK(aes128_GCM_decrypt   ,   16,   1.0f, 0x998a)
    TASK(chachapoly_seal      ,   16,   1.0f, 0xd80d)
    TASK(chachapoly_read      ,   16,   1.0f, 0xd80d)
    TASK(ecdh_p256r1          ,    0,   1.0f, 0x7bdc)
    TASK(ecdh_p384            ,    0,   1.0f, 0x7bdc)
    TASK(ecdh_x25519          ,    0,   1.0f, 0x7bdc)
    TASK(ecdsa_sign_p256r1    ,   32,   1.0f, 0x3a47) // Note [1,4]
    TASK(ecdsa_verify_p256r1  ,   32,   1.0f, 0x3a47) // Note [1,4]
    TASK(ecdsa_sign_p256r1    ,   32,   1.0f, 0x3a47) // Note [1,4]
    */
    TASK(ecdsa_sign_p256r1    ,   32,   1.0f, 0x3a47) // Note [1,4]
    TASK(ecdsa_sign_p384      ,   32,   1.0f, 0x3a47) // Note [1,4]
    //TASK(ecdsa_verify_p384    ,   32,   1.0f, 0x3a47) // Note [1,4]
    /*
    TASK(ecdsa_sign_ed25519   ,  256,   1.0f, 0x209d) // Note [3]
    TASK(ecdsa_verify_ed25519 ,  256,   1.0f, 0x209d) // Note [3]
    */
    /*
    // V1
    TASK(aes128_ECB_encrypt   ,  320,  1.0f, 0x998a)
    TASK(aes128_CCM_encrypt   ,   52,  1.0f, 0xd82d)
    TASK(aes128_CCM_decrypt   ,  168,  1.0f, 0x005b)
    TASK(ecdh                 ,    0,  1.0f, 0x7531)
    TASK(ecdsa_sign_p256r1    ,   64,  1.0f, 0x3a47) // Note [1,4]
    TASK(ecdsa_verify_p256r1  ,   64,  2.0f, 0x3a47) // Note [1,4]
    TASK(sha256               ,   23,  3.0f, 0x2151)
    TASK(sha256               ,   57,  1.0f, 0x3b3c)
    TASK(sha256               ,  384,  1.0f, 0x1d3f)
    TASK(variation_001        ,    0,  3.0f, 0x0000)
    TASK(sha256               , 4224,  4.0f, 0x9284)
    TASK(aes_ecb_encrypt      , 2048, 10.0f, 0x989e)
    */
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

    score = 0.0f;
    for (i = 0; i < g_numtasks; ++i)
    {
        // First, compute the correct # of iterations for each primitive
        // iterations = tune_iterations(g_task[i].n, g_task[i].func);
        // Compute a CRC from a single iteration, also warm up the test
        ee_srand(0); // CRCs are computed with seed 0
        g_task[i].actual_crc = (*g_task[i].func)(g_task[i].n, 1);
        // Now do a run with the correct number of iterations to get ips
        clear_timestamps();
        //(*g_task[i].func)(g_task[i].n, iterations);
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


// TODO verify in = out for decrypt, seal/read, sign/verify
// TODO rename SIZE to len to be consistent
// TODO check var names in wrappers for consistency
