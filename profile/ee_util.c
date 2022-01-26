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

#include "ee_util.h"

// These are used for our PRNG ee_rand()
static uint8_t g_prn       = 0x7f;
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
    g_prn       = seed;
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
    char *        header;
    char          b;

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
    uint_fast32_t i;
    char *        p_header;
    char          b;

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
            th_printf("%02x", (uint8_t)b);
        }
        else
        {
            th_printf("%02x", (uint8_t)b);
        }
    }
    th_printf("\r\n");
}
