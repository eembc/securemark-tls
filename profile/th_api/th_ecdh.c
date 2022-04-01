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

#include "ee_ecdh.h"

ee_status_t
th_ecdh_create(void **p_context, ee_ecdh_group_t group)
{
#warning "th_ecdh_create not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_ecdh_init(void *          p_context,
             ee_ecdh_group_t group,
             uint8_t *       p_private,
             uint_fast32_t   prilen,
             uint8_t *       p_public,
             uint_fast32_t   publen)
{
#warning "th_ecdh_init not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_ecdh_calc_secret(void *          p_context,
                    ee_ecdh_group_t group,
                    uint8_t *       p_secret,
                    uint_fast32_t   slen)
{
#warning "th_ecdh_calc_secret not implemented"
    return EE_STATUS_OK;
}

void
th_ecdh_destroy(void *p_context)
{
#warning "th_ecdh_destroy not implemented"
}
