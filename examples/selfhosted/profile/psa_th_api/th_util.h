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

#ifndef __TH_UTIL_H
#define __TH_UTIL_H

#include <stddef.h>
#include <ee_main.h>

void th_pre(void);
void th_post(void);

ee_status_t   th_profile_initialize(void);

void th_buffer_initialize(void);
unsigned char * th_buffer_address(void);
size_t th_buffer_size(void);

#endif
