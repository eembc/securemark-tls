/*
 * Copyright (C) 2015-2017 EEMBC(R). All Rights Reserved
 *
 * All EEMBC Benchmark Software are products of EEMBC and are provided under the
 * terms of the EEMBC Benchmark License Agreements. The EEMBC Benchmark Software
 * are proprietary intellectual properties of EEMBC and its Members and is
 * protected under all applicable laws, including all applicable copyright laws.
 *
 * If you received this EEMBC Benchmark Software without having a currently
 * effective EEMBC Benchmark License Agreement, you must discontinue use.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include "th_util.h"

static unsigned char g_generic_buffer[BUFFER_SIZE];

void
th_pre(void)
{
    wolfCrypt_Init();
}

void
th_post(void)
{
    wolfCrypt_Cleanup();
}

void
th_buffer_initialize(void)
{
}

unsigned char *
th_buffer_address(void)
{
    return g_generic_buffer;
}

uint32_t
th_buffer_size(void)
{
    return BUFFER_SIZE;
}

ee_status_t
th_profile_initialize(void)
{
    // we don't need to do anything extra.
    return EE_STATUS_OK;
}
