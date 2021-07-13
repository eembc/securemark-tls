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

#include "th_util.h"

// NOTE: Feel free to replace the static variable with any allocation scheme
#define BUFFER_SIZE (1024 * 4)
static uint8_t g_generic_buffer[BUFFER_SIZE];

/**
 * Most init can happen prior to ee_main(), but if necessary, this function
 * provides a way to initialize within the ee_* initialization. It is called
 * from: ee_main() > ee_profile_init() > th_profile_init().
 */
ee_status_t
th_profile_init(void)
{
    return EE_STATUS_OK;
}

/**
 * The pre/post hooks are called immediately before the th_timestamp() and
 * immediately after. These hooks give the developer a chance to turn off
 * certain features (like UART) to save power during the loop.
 */

void
th_pre(void)
{
}

void
th_post(void)
{
}

/**
 * PORTME: If you opt to not use the heap, set up the buffer here.
 */
void
th_buffer_initialize(void)
{
}

/**
 * PORTME: Return the address of a region of memory that the the framework
 * can use as a generic place to store data. Should be 1K at least, but profiles
 * will always check to make sure it is suitably sized.
 */
uint8_t *
th_buffer_address(void)
{
    return g_generic_buffer;
}

/**
 * PORTME: If you opt to do a malloc, be sure to return the size here
 */
uint_fast32_t
th_buffer_size(void)
{
    return BUFFER_SIZE;
}
