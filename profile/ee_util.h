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
#ifndef __EE_UTIL_H
#define __EE_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include "ee_main.h"

#define EE_PRINTMEM_DEFAULT_HEADER "m-hexdump-";

// Convert a hex string to a long decimal
long ee_hexdec(char *hex);
// Seed our PRNG
void ee_srand(uint8_t seed);
// Return an 8-bit PRN
uint8_t ee_rand(void);
// Memory printer utility #1: standard hex bytes
void ee_printmem(uint8_t *addr, uint_fast32_t len, char *user_header);
// Memory printer utility #2: standard arbitrary-length
void ee_printmem_hex(uint8_t *p_addr, uint_fast32_t len, char *p_user_header);

#endif /* _EE_UTIL_H */
