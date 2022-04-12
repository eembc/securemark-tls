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

#include "ee_ecdsa.h"

ee_status_t
th_ecdsa_create(void **p_context, ee_ecdh_group_t group)
{
#warning "th_ecdsa_create not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_init(void *          p_context,
              ee_ecdh_group_t group,
              uint8_t *       p_private,
              uint_fast32_t   plen)
{
#warning "th_ecdsa_init not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_sign(void *          p_context,
              ee_ecdh_group_t group,
              uint8_t *       p_msg,
              uint_fast32_t   mlen,
              uint8_t *       p_sig,
              uint_fast32_t * p_slen)
{
#warning "th_ecdsa_sign not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_verify(void *          p_context,
                ee_ecdh_group_t group,
                uint8_t *       p_msg,
                uint_fast32_t   mlen,
                uint8_t *       p_sig,
                uint_fast32_t   slen)
{
#warning "th_ecdsa_verify not implemented"
    return EE_STATUS_OK;
}

void
th_ecdsa_destroy(void *p_context, ee_ecdh_group_t group)
{
#warning "th_ecdsa_destroy not implemented"
}
