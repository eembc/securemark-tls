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

/* These are used for our PRNG `ee_rand()` */
static uint8_t g_prn       = 0x7f;
static uint8_t g_prn_coeff = 0;

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

void
ee_srand(uint8_t seed)
{
    g_prn       = seed;
    g_prn_coeff = 0;
}

uint8_t
ee_rand(void)
{
    g_prn ^= g_prn << 3;
    g_prn ^= g_prn >> 5;
    g_prn ^= g_prn_coeff++ >> 2;
    return g_prn;
}

void
ee_printmem(uint8_t *p_addr, uint_fast32_t len, char *p_user_header)
{
    uint_fast32_t i;
    char *        header;
    char          b;

    if (p_user_header == NULL)
    {
        header = EE_PRINTMEM_DEFAULT_HEADER;
    }
    else
    {
        header = p_user_header;
    }

    th_printf(header);

    for (i = 0; i < len; ++i)
    {
        /* Some libc printf's don't provide padding, e.g., %02x, and force 1
           nibble on libcs that default to two. */
        b = p_addr[i];
        th_printf("%1x%1x", (b & 0xF0) >> 4, b & 0xf);

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

void
ee_printmemline(uint8_t *p_addr, uint_fast32_t len, char *p_user_header)
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
        /* Some libc printf's don't provide padding, e.g., %02x, and force 1
           nibble on libcs that default to two. */
        b = p_addr[i];
        th_printf("%1x%1x", (b & 0xF0) >> 4, b & 0xf);
    }
    th_printf("\r\n");
}

uint32_t
bswap32(uint32_t x)
{
    printf("bswap(%08x)\n", x);
    return ((((x)&0xff000000) >> 24) | (((x)&0x00ff0000) >> 8)
            | (((x)&0x0000ff00) << 8) | (((x)&0x000000ff) << 24));
}
