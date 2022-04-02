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
#ifndef __EE_PROFILE_H
#define __EE_PROFILE_H

#include "ee_bench.h"
#include "ee_buffer.h"
#include "ee_aes.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_main.h"
#include "ee_sha.h"
#include "ee_variations.h"
#include "ee_util.h"
#include "th_util.h"

#define EE_FW_VERSION "SecureMark-TLS Firmware v2.0.0"
/* Minimum buffer size for the benchmark (TODO: What is it for 2.0?) */
#define EE_MINBUF 8192

/**
 * @brief This is the profile command parser. It is called from the function
 * `monitor/ee_main.c:ee_serial_command_parser_callback()` if that parser
 * does not recognize a command from the host. It claims only the commands
 * related to the profile.
 *
 * @param p_command - Command string buffer to parse.
 * @return arg_claimed_t - Returns EE_ARG_CLAIMED or EE_ARG_UNCLAIMED if it
 * encounters a command it does not recognize.
 */
arg_claimed_t ee_profile_parse(char *p_command);

/**
 * @brief Set some initial state required by the profile, especially custom
 * user state for the profile via `th_profile_initialize()`.
 *
 */
void ee_profile_initialize(void);

#endif /* _EE_PROFILE_H */
