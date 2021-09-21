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

#ifndef __EE_BUFFER_H
#define __EE_BUFFER_H

#include <stdint.h>
#include "ee_main.h"
#include "ee_util.h"
#include "th_util.h" // for buffer implementation

void          ee_buffer_add(uint8_t byte);
void          ee_buffer_rewind(void);
void          ee_buffer_fill(uint8_t byte);
void          ee_buffer_print(void);
arg_claimed_t ee_buffer_parse(char *p_command);

#endif /* __EE_BUFFER_H */
