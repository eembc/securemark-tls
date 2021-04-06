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

#include "ee_main.h"
#include "ee_aes.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_sha.h"
#include "ee_variations.h"
#include "th_util.h"

#define EE_FW_VERSION "SecureMark-TLS Firmware v1.0.4"
#define EE_PRINTMEM_DEFAULT_HEADER "m-hexdump-";

// What mode we are currently in (perf or verf) [see monitor/th_api/th_lib.c]
bool g_verify_mode = false;

// These are used for our PRNG ee_rand()
static uint8_t g_prn = 0x7f;
static uint8_t g_prn_coeff = 0;

/**
 * @brief convert a hexidecimal string to a signed long
 * will not produce or process negative numbers except
 * to signal error.
 *
 * @param hex without decoration, case insensitive.
 *
 * @return -1 on error; but if the result is > size(long)
 * the number is invalid (there is no character counting)
 * and no error generated.
 *
 * Provided by Steve Allen at Dialog Semiconductor
 */
long
ee_hexdec(char *hex)
{
    char c;
    long dec;
    long ret;

    dec = 0;
    ret = 0;
    while (*hex && ret >= 0)
    {
        c = *hex++;
        if (c >= '0' && c <= '9')
        {
            dec = c - '0';
        }
        else if (c >= 'a' && c <= 'f')
        {
            dec = c - 'a' + 10;
        }
        else if (c >= 'A' && c <= 'F')
        {
            dec = c - 'A' + 10;
        }
        else
        {
            return -1;
        }
        ret = (ret << 4) + dec;
    }
    return ret;
}

/**
 * We need a pseudo-rand number generator with an host-provided seed. We don't
 * care about strength of randomness, we just need a repeatable sequence based
 * on a single byte from the host.
 */

void
ee_srand(uint8_t seed)
{
    g_prn = seed;
    g_prn_coeff = 0;
}

// return a byte using xorshift
uint8_t
ee_rand(void)
{
    g_prn ^= g_prn << 3;
    g_prn ^= g_prn >> 5;
    g_prn ^= g_prn_coeff++ >> 2;
    return g_prn;
}

/**
 * Printing utility #1
 *
 * Prints out a number of hex bytes from an address, max 16 per line, in 02x
 * lowercase hexadecimal. User can specify their own line header for debugging.
 */
void
ee_printmem(uint8_t *addr, uint_fast32_t len, char *user_header)
{
    uint_fast32_t i;
    char  *header;
    char   b;

    if (user_header == NULL)
    {
        header = EE_PRINTMEM_DEFAULT_HEADER;
    }
    else
    {
        header = user_header;
    }

    th_printf(header);

    for (i = 0; i < len; ++i)
    {
        // Some libc printf's don't provide padding, e.g., %02x
        b = addr[i];
        if (b <= 0xf)
        {
            th_printf("0%x", b);
        }
        else
        {
            th_printf("%x", b);
        }
        if ((i + 1) % 16 == 0)
        {
            th_printf("\r\n");
            if ((i + 1) < len)
            {
                th_printf(header);
            }
        }
        else if ((i + 1) < len)
        {
            th_printf("-");
        }
    }

    if (i % 16 != 0)
    {
        th_printf("\r\n");
    }
}

/**
 * Printing utility #2
 *
 * Prints out memory as one line in big-endian hex bytes starting with 0x
 */
void
ee_printmem_be(uint8_t *p_addr, uint_fast32_t len, char *p_user_header)
{
    uint_fast32_t   i;
    char    *p_header;
    char     b;

    if (p_user_header == NULL)
    {
        p_header = EE_PRINTMEM_DEFAULT_HEADER;
    }
    else
    {
        p_header = p_user_header;
    }

    th_printf(p_header);
    th_printf("0x");
    for (i = 0; i < len; ++i)
    {
        // Some libc printf's don't provide padding, e.g., %02x
        b = p_addr[i];
        if (b <= 0xf)
        {
            th_printf("0%x", b);
        }
        else
        {
            th_printf("%x", b);
        }
    }
    th_printf("\r\n");
}

#if EE_CFG_SELFHOSTED != 1

// This var is used for the generic buffer ee_buffer_* routines
static uint_fast32_t g_buffer_pos = 0;

/**
 * Some VERY basic buffer manipulation functions for the generic buffer.
 * Adding one byte at a time increments the position pointer, which wraps.
 * Rewinding sets the position pointer to the start. Fill allows you to
 * copy the same byte in the memory.
 */

/**
 * Add a byte to the current index and increment, wrapping if necessary
 */
void
ee_buffer_add(uint8_t byte)
{
    (th_buffer_address())[g_buffer_pos] = byte;
    ++g_buffer_pos;
    if (g_buffer_pos >= th_buffer_size())
    {
        g_buffer_pos = 0;
    }
}

/**
 * Set the index pointer to position 0
 */
void
ee_buffer_rewind(void)
{
    g_buffer_pos = 0;
}

/**
 * Fill the buffer with a byte
 */
void
ee_buffer_fill(uint8_t byte)
{
    uint_fast32_t i;

    ee_buffer_rewind();
    for (i = 0; i < th_buffer_size(); ++i)
    {
        ee_buffer_add(byte);
    }
}

/**
 * This is a debug function because it could print multiple KB of data
 */
void
ee_buffer_print(void)
{
    uint8_t  *buffer;
    uint_fast32_t          buffer_size;
    uint_fast32_t          i;

    buffer = th_buffer_address();
    buffer_size = th_buffer_size();

    th_printf("m-buffer-");
    for (i = 0; i < buffer_size; ++i)
    {
        th_printf("%02x", buffer[i]);
        if ((i + 1) % 16 == 0)
        {
            th_printf("\r\n");
            if ((i + 1) < buffer_size)
            {
                th_printf("m-buffer-");
            }
        }
        else if ((i + 1) < buffer_size)
        {
            th_printf("-");
        }
    }
    if (i % 16 != 0)
    {
        th_printf("\r\n");
    }
}

/**
 * Route the 'bench' commands (see the help text in the main parser).
 *
 * bench-KERNELNAME-SRAND-ITERATIONS[-NUMBYTES]
 *
 */
arg_claimed_t
ee_bench_parse(char *p_command)
{
    char *p_subcmd; // Subcommand

    char *p_seed;   // srand() seed.
    char *p_iter;   // Requested iterations
    char *p_size;   // Requested size of dataset in bytes

    uint_fast32_t i; // iterations
    uint_fast32_t n; // data size in bytes

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
    p_subcmd    = th_strtok(NULL, EE_CMD_DELIMITER);
    p_seed      = th_strtok(NULL, EE_CMD_DELIMITER);
    p_iter      = th_strtok(NULL, EE_CMD_DELIMITER);
    p_size      = th_strtok(NULL, EE_CMD_DELIMITER);

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
        goto error_exit;
    }

    // Validate iterations
    if (p_iter)
    {
        i = (uint_fast32_t)th_atoi(p_iter);

        if (i == 0)
        {
            th_printf("e-[Benchmark iterations cannot be zero]\r\n");
            goto error_exit;
        }
    }
    else
    {
        th_printf("e-[Benchmark iterations not specified]\r\n");
        goto error_exit;
    }

    // Validate datasize
    if (p_size)
    {
        n = (uint_fast32_t)th_atoi(p_size);
    }
    else
    {
        // TODO: Is it OK for datasize to be zero?
        n = 0;
    }

    // Now figure out which subcommand was issued...

    if (th_strncmp(p_subcmd, "sha256", EE_CMD_SIZE) == 0)
    {
        uint8_t *p_buffer;
        uint_fast32_t         buflen;
        uint8_t *p_in;
        uint8_t *p_out;
        uint_fast32_t         x;

        //       in         out
        buflen =  n +  SHA_SIZE;

        p_buffer = (uint8_t *)th_malloc(buflen);

        if (p_buffer == NULL)
        {
            th_printf("e-[SHA256 malloc() failed, size %d]\r\n", buflen);
            goto error_exit;
        }

        // Assign the helper points to the region of the p_buffer
        p_in  = p_buffer;
        p_out = p_in + n;
        for (x = 0; x < n; ++x)
        {
            p_in[x] = ee_rand();
        }
        ee_sha256(p_buffer, n, p_out, i);
        if (g_verify_mode)
        {
            ee_printmem_be(p_in, n, "m-bench-sha256-in-");
            ee_printmem_be(p_out, SHA_SIZE, "m-bench-sha256-hash-");
        }
        th_free(p_buffer);
    }
    else if (th_strncmp(p_subcmd, "aes128_ecb", EE_CMD_SIZE) == 0)
    {
        uint8_t *p_buffer;
        uint_fast32_t         buflen;
        uint8_t *p_key;
        uint8_t *p_in;
        uint8_t *p_out;
        uint_fast32_t         x;

        //                key   in  out
        buflen =  AES_KEYSIZE +  n +  n;

        p_buffer = (uint8_t *)th_malloc(buflen);

        if (p_buffer == NULL)
        {
            th_printf("e-[AES128 ECB malloc() failed, size %d]\r\n", buflen);
            goto error_exit;
        }
        // Assign the helper points to the region of the buffer
        p_key = p_buffer;
        p_in  = p_key + AES_KEYSIZE;
        p_out = p_in + n;
        for (x = 0; x < AES_KEYSIZE; ++x) {
            p_key[x] = ee_rand();
        }
        for (x = 0; x < n; ++x) {
            p_in[x] = ee_rand();
        }

        ee_aes128_ecb(p_key, p_in, n, p_out, AES_ENC, i);

        if (g_verify_mode)
        {
            ee_printmem_be(p_key, 16, "m-bench-aes128_ecb_enc-key-");
            ee_printmem_be(p_in, n, "m-bench-aes128_ecb_enc-in-");
            ee_printmem_be(p_out, n, "m-bench-aes128_ecb_enc-out-");
        }

        ee_aes128_ecb(p_key, p_out, n, p_in, AES_DEC, i);

        if (g_verify_mode)
        {
            ee_printmem_be(p_key, 16, "m-bench-aes128_ecb_dec-key-");
            ee_printmem_be(p_out, n, "m-bench-aes128_ecb_dec-in-");
            ee_printmem_be(p_in, n, "m-bench-aes128_ecb_dec-out-");
        }

        th_free(p_buffer);
    }
    else if (th_strncmp(p_subcmd, "aes128_ccm", EE_CMD_SIZE) == 0) {
        uint8_t *p_buffer;
        uint_fast32_t         buflen;
        uint8_t *p_key;
        uint8_t *p_iv;
        uint8_t *p_in;
        uint8_t *p_tag;
        uint8_t *p_out;
        uint_fast32_t         x;

        //                key           iv  in           tag   out
        buflen =  AES_KEYSIZE + AES_IVSIZE + n + AES_TAGSIZE +   n;

        p_buffer = (uint8_t *)th_malloc(buflen);

        if (p_buffer == NULL) {
            th_printf("e-[AES128 CCM malloc() failed, size %d]\r\n", buflen);
            goto error_exit;
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
        ee_aes128_ccm(p_key, p_iv, p_in, n, p_tag, p_out, AES_ENC, i);

        if (g_verify_mode)
        {
            ee_printmem_be(p_key, AES_KEYSIZE, "m-bench-aes128_ccm_enc-key-");
            ee_printmem_be(p_iv, AES_IVSIZE, "m-bench-aes128_ccm_enc-iv-");
            ee_printmem_be(p_in, n, "m-bench-aes128_ccm_enc-in-");
            ee_printmem_be(p_tag, AES_TAGSIZE, "m-bench-aes128_ccm_enc-tag-");
            ee_printmem_be(p_out, n, "m-bench-aes128_ccm_enc-out-");
        }

        ee_aes128_ccm(p_key, p_iv, p_out, n, p_tag, p_in, AES_DEC, i);

        if (g_verify_mode)
        {
            ee_printmem_be(p_key, AES_KEYSIZE, "m-bench-aes128_ccm_dec-key-");
            ee_printmem_be(p_iv, AES_IVSIZE, "m-bench-aes128_ccm_dec-iv-");
            ee_printmem_be(p_out, n, "m-bench-aes128_ccm_dec-in-");
            ee_printmem_be(p_tag, AES_TAGSIZE, "m-bench-aes128_ccm_dec-tag-");
            ee_printmem_be(p_in, n, "m-bench-aes128_ccm_dec-out-");
        }

        th_free(p_buffer);
    }
    /**
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
    else if (th_strncmp(p_subcmd, "ecdh", EE_CMD_SIZE) == 0)
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

        ee_ecdh(p_pub, ECC_QSIZE, p_pri, ECC_DSIZE, p_shared, ECDH_SIZE, i);

        if (g_verify_mode)
        {
            ee_printmem_be(p_pub, 64, "m-bench-ecdh-peer-public-");
            ee_printmem_be(p_pri, 32, "m-bench-ecdh-own-private-");
            ee_printmem_be(p_shared, 32, "m-bench-ecdh-shared-");
        }
    }
    else if (th_strncmp(p_subcmd, "ecdsa", EE_CMD_SIZE) == 0)
    {
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
        uint8_t *p_pri;
        uint8_t *p_hmac;

        uint8_t *p_sig;
        uint_fast32_t   slen;

        slen = 256; // Note: this is also an input to ee_ecdsa_sign
        p_sig = (uint8_t *)th_malloc(slen); // should be 71, 72 B

        if (p_sig == NULL)
        {
            th_printf("e-[ECDSA malloc() failed, size %d]\r\n", 256);
            goto error_exit;
        }

        p_pri  = th_buffer_address() + 64;
        p_hmac = p_pri + ECC_DSIZE;

        ee_ecdsa_sign(p_hmac, HMAC_SIZE, p_sig, &slen, p_pri, ECC_DSIZE, i);

        if (g_verify_mode) {
            ee_printmem_be(p_pri, ECC_DSIZE, "m-bench-ecdsa-sign-own-private-");
            ee_printmem_be(p_sig, slen, "m-bench-ecdsa-sign-signature-");
            ee_printmem_be(p_hmac, HMAC_SIZE, "m-bench-ecdsa-sign-hash-");
        }

        ee_ecdsa_verify(p_hmac, HMAC_SIZE, p_sig, slen, p_pri, ECC_DSIZE, i);

        th_free(p_sig);
    }
    else if (th_strncmp(p_subcmd, "var01", EE_CMD_SIZE) == 0)
    {
        // Since there is just one "variation", put it here for now
        ee_variation_001(i);
    }
    else
    {
        th_printf("e-[Unknown benchmark subcommand: %s]\r\n", p_subcmd);
    }
error_exit:
    return EE_ARG_CLAIMED;
}

/**
 * Route the 'buffer' commands (see the help text in the main parser).
 */
arg_claimed_t
ee_buffer_parse(char *p_command)
{
    char *p_subcmd; // Subcommand
    char *p_next;   // Next token in subcommand parse
    long  hex;      // String-to-hex byte (see ee_hexdec)

    if (th_strncmp(p_command, "buffer", EE_CMD_SIZE) != 0)
    {
        return EE_ARG_UNCLAIMED;
    }

    p_subcmd = th_strtok(NULL, EE_CMD_DELIMITER);

    if (p_subcmd == NULL)
    {
        th_printf("e-[Command 'buffer' takes a subcommand]\r\n");
        return EE_ARG_CLAIMED;
    }

    if (th_strncmp(p_subcmd, "fill", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);

        if (p_next)
        {
            hex = ee_hexdec(p_next);

            if (hex < 0)
            {
                th_printf("e-[Buffer fill invalid byte: %s]\r\n", p_next);
            }
            else
            {
                ee_buffer_fill( (uint8_t) hex);
            }
        }
        else
        {
            th_printf("e-[Buffer fill missing a byte]\n");
        }
    }
    else if (th_strncmp(p_subcmd, "add", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);

        if (p_next == NULL)
        {
            th_printf("e-[Buffer add expects at least on byte]\r\n");
        }
        else
        {
            while (p_next != NULL)
            {
                hex = ee_hexdec(p_next);

                if (hex < 0)
                {
                    th_printf("e-[Buffer add invalid byte: %s]\r\n", p_next);
                }
                else
                {
                    ee_buffer_add( (uint8_t) hex);
                }

                p_next = th_strtok(NULL, EE_CMD_DELIMITER);
            }
        }
    }
    else if (th_strncmp(p_subcmd, "rewind", EE_CMD_SIZE) == 0)
    {
        ee_buffer_rewind();
    }
    else if (th_strncmp(p_subcmd, "print", EE_CMD_SIZE) == 0)
    {
        ee_buffer_print();
    }
    else
    {
        th_printf("e-[Unknown buffer subcommand: %s]\r\n", p_subcmd);
    }
    return EE_ARG_CLAIMED;
}

/**
 * This is the profile command parser. It is called from the function:
 * monitor/ee_main.c:ee_serial_command_parser_callback(). It claims all
 * commands related to the benchmark profile.
 */
arg_claimed_t
ee_profile_parse(char *p_command)
{
    char *p_next;
    long  hex;

    if (th_strncmp(p_command, "profile", EE_CMD_SIZE) == 0)
    {
        th_printf("m-profile-[%s]\r\n", EE_FW_VERSION);
    }
    else if (th_strncmp(p_command, "verify", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);
        if (p_next)
        {
            g_verify_mode = (th_atoi(p_next) != 0);
        }
        th_printf("m-verify-%s\r\n", g_verify_mode ? "on" : "off");
    }
    else if (th_strncmp(p_command, "srand", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);

        if (p_next == NULL)
        {
            th_printf("e-srand-?missing-byte\r\n");
        }
        else
        {
            hex = ee_hexdec(p_next);

            if (hex < 0)
            {
                th_printf("e-srand-?badhex-%s\r\n", p_next);
            }
            else
            {
                ee_srand( (uint8_t) hex);
            }
        }
    }
    else if (th_strncmp(p_command, "help", EE_CMD_SIZE) == 0)
    {
        th_printf("%s\r\n", EE_FW_VERSION);
        th_printf("\r\n");
        th_printf("help                : Print this information\r\n");
        th_printf("name                : Print the name of this device\r\n");
        th_printf("profile             : Print the benchmark profile and version\r\n");
        th_printf("verify-[0|1]        : Get or set verify mode\r\n");
        th_printf("srand-XX            : Seed the PSRN with a hex byte, e.g 7F\r\n");
        th_printf("bench-SUBCMD        : Issue a 'bench' subcommand and paramters\r\n");
        th_printf("  sha256-*          : SHA256\r\n");
        th_printf("  aes128_ecb-*      : AES128 ECB encrypt and decrypt\r\n");
        th_printf("  aes128_ccm-*      : AES127 CCM encrypt and decrypt\r\n");
        th_printf("  ecdh-*            : ECDH secret generation\r\n");
        th_printf("  ecdsa-*           : ECDSA sign and verify\r\n");
        th_printf("  var01-*           : Varation #1 (mixed contexts)\r\n");
        th_printf("  SEED-ITER-SIZE    : Each subcmd takes a PRNG seed, #iter. & #bytes\r\n");
        th_printf("buffer-SUBCMD       : Issue a 'buffer' subcommand\r\n");
        th_printf("  fill-XX           : File the buffer with XX hex byte\r\n");
        th_printf("  add-XX[-XX]*      : Add hex byte(s) XX to current buffer\r\n");
        th_printf("                      pointer (it will wrap)\r\n");
        th_printf("  rewind            : Rewind the buffer pointer to the start\r\n");
        th_printf("  print             : Print ALL buffer bytes (as hex)\r\n");
    }
    else if (ee_bench_parse(p_command) == EE_ARG_CLAIMED)
    {
    }
    else if (ee_buffer_parse(p_command) == EE_ARG_CLAIMED)
    {
    }
    else
    {
        return EE_ARG_UNCLAIMED;
    }
    return EE_ARG_CLAIMED;
}

void
ee_profile_initialize(void)
{
    th_buffer_initialize();
    g_verify_mode = false;
    if (th_buffer_size() < EE_MINBUF)
    {
        // The host will catch this, rather than returning a value
        th_printf("e-profile-[Buffer must be at least %uB]\r\n", EE_MINBUF);
    }
}

#endif // EE_CFG_SELFHOSTED
