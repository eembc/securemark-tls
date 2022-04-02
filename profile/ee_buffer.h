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
#include "th_util.h" /* For buffer implementation */

/**
 * @brief These routines provide very basic buffer manipulation to a region
 * of memory that can be accessed through the array operator as a pointer,
 * which wraps if the the buffer size is exceeded.
 *
 */

/**
 * @brief Add a byte to the current positionin the buffer and advance the
 * static buffer pointer.
 *
 * @param byte
 */
void ee_buffer_add(uint8_t byte);

/**
 * @brief Return the static buffer pointer to position zero.
 *
 */
void ee_buffer_rewind(void);

/**
 * @brief Fill the entire buffer with a specified byte.
 *
 * @param byte - Value to fill the bufer with.
 */
void ee_buffer_fill(uint8_t byte);

/**
 * @brief A debugging function for dumping the entire buffer with th_printf.
 * If the buffer is large this can take a while.
 *
 */
void ee_buffer_print(void);

/**
 * @brief Parse a buffer command string from the main parser.
 *
 * @param p_command - Pointer to the command string.
 * @return arg_claimed_t - Return EE_ARG_CLAIMED if valid, else EE_ARG_UNCLAIMED
 */
arg_claimed_t ee_buffer_parse(char *p_command);

#endif /* __EE_BUFFER_H */
