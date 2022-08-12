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

#include "ee_sha.h"

ee_status_t
th_sha_create(void **pp_context, ee_sha_size_t size)
{
#warning "th_sha_create not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_sha_init(void *p_context)
{
#warning "th_sha_init not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_sha_process(void *p_context, const uint8_t *p_in, uint32_t len)
{
#warning "th_sha_process not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_sha_done(void *p_context, uint8_t *p_result)
{
#warning "th_sha_done not implemented"
    return EE_STATUS_OK;
}

void
th_sha_destroy(void *p_context)
{
#warning "th_sha_destroy not implemented"
}
