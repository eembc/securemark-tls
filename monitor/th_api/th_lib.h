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

#ifndef __TH_LIB_H
#define __TH_LIB_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "th_libc.h"
#include "ee_main.h"

/* It is crucial to follow EEMBC message syntax for key messages */
#define EE_MSG_TIMESTAMP "m-lap-us-%lu\r\n"

#ifndef EE_CFG_ENERGY_MODE
#define EE_CFG_ENERGY_MODE 1
#endif

#if EE_CFG_ENERGY_MODE == 1
#define EE_MSG_TIMESTAMP_MODE "m-timestamp-mode-energy\r\n"
#else
#define EE_MSG_TIMESTAMP_MODE "m-timestamp-mode-performance\r\n"
#endif

/**
 * This string is used in the "name%" command. When the host UI starts a test,
 * it calles the "name%" command, and the result is captured in the log file.
 * It can be quite useful to have the device's name in the log file for future
 * reference or debug.
 */
#define TH_VENDOR_NAME_STRING "unspecified"

void     th_monitor_initialize(void);
void     th_timestamp_initialize(void);
uint32_t th_timestamp(void);
void     th_serialport_initialize(void);
void     th_printf(const char *fmt, ...);
void     th_command_ready(volatile char *);

#endif /* __TH_LIB_H */
