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

#ifndef __TH_UTIL_H
#define __TH_UTIL_H

#include <ee_main.h>
#include <stddef.h>
#include <stdint.h>

/* PORTME: Update this if/elif so that the endina macros are correct. */
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN                    \
    || defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) \
    || defined(__AARCH64EB__) || defined(_MIBSEB) || defined(__MIBSEB)       \
    || defined(__MIBSEB__)
#define EE_FIX_ENDIAN(x) bswap32(x)
#define
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN            \
    || defined(__LITTLE_ENDIAN__) || defined(__ARMEL__)                   \
    || defined(__THUMBEL__) || defined(__AARCH64EL__) || defined(_MIPSEL) \
    || defined(__MIPSEL) || defined(__MIPSEL__)
#define EE_FIX_ENDIAN(x) (x)
#else
#error "I don't know what architecture this is!"
#endif

#define BUFFER_SIZE (1024 * 8)

/**
 * @brief Most init can happen prior to ee_main(), but if necessary, this
 * function provides a way to initialize within the ee_* initialization. It is
 * called from: ee_main() > ee_profile_init() > th_profile_init().
 *
 * @return ee_status_t
 */
ee_status_t th_profile_initialize(void);

/**
 * @brief Perform any power-reducing opportinuties before entering a compute-
 * intensive loop.
 */
void th_pre(void);

/**
 * @brief Undo any power-reducing opportinuties set with `th_pre()`.
 */
void th_post(void);

/**
 * @brief If memory is located somewhere other than a heap, it needs to be
 * content addressible with `[]` operator. This may need to be deprecated,
 * as it has never been used.
 *
 */
void th_buffer_initialize(void);

/**
 * @brief If non-heap memory is used, return a `[]` addressible pointer.
 *
 * @return uint8_t* - Pointer to the start of the generic buffer.
 */
uint8_t *th_buffer_address(void);

/**
 * @brief Returns the size of the buffer.
 *
 * @return uint32_t - The size of the buffer.
 */
uint32_t th_buffer_size(void);

#endif /* __TH_UTIL_H */
