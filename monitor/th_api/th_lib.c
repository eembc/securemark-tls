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

#include "th_lib.h"

/**
 * @brief This variable indicates that timestamps should be ignored. It is used
 * when performing composite operations with multiple primitives that generate
 * multiple timestamps. For example, encrypting before a decrypt. Porting
 * developers do not need to worry about this. See `th_timestamp()`, below.
 */
bool g_mute_timestamps;

#if EE_CFG_SELFHOSTED != 1

/**
 * PORTME: If there's anything else that needs to be done on init, do it here,
 * otherwise OK to leave it alone.
 */
void
th_monitor_initialize(void)
{
}

/**
 * PORTME: Set up an OPEN-DRAIN GPIO if it hasn't already been done,
 * otherwise it is OK to leave this alone.
 */
void
th_timestamp_initialize(void)
{
    /* USER CODE 1 BEGIN */
    /* Some BSP/MSP/SDKs initialize the GPIO long before we even get here! */
    /* USER CODE 1 END */
    /* Always print this message, the host needs it. */
    th_printf(EE_MSG_TIMESTAMP_MODE);
    /* Always call the timestamp on initialize so that the open-drain output
       is set to "1" (so that we catch a falling edge) */
    th_timestamp();
}

/**
 * @brief Performs two functions: First, it returns a uint32_t timestamp value
 * of the number of microseconds currently counted by a monotonically increasing
 * counter. The minimum resolution is one millisecond for the framework. If the
 * timer only provides milliecond resolution, multiply by 1000. Second, it
 * generates output. If running in energy mode, it pulls an OPEN-DRAIN GPIO low
 * for at least 2 microseconds. If running in performance mode, it prints a
 * pre-formatted message.
 *
 * Typically in energy mode, the external energy monitor must synchronize with
 * the DUT, and to avoid as much latency is possible, this is done with GPIO.
 * However, in performance mode, an EMON is not used, so the DUT must report
 * a timestamp that the Host GUI will use to compute performance.
 *
 * Lastly, the returned value may be used by some profiles for self-tuning.
 *
 * Some profiles perform a significant amount of self-tuning before the
 * benchmark begins. In these cases, the timestamp itself can be supressed to
 * avoid flooding the other components in the framework with unnecessary
 * timestamps (hence, the `g_mute_timestamps` global).
 *
 * @return uint32_t - The number of microseconds elapsed since the last call.
 * 
 * PORTME: This function is essential.
 */
uint32_t
th_timestamp(void)
{
    uint32_t elapsedMicroSeconds = 0;
    /* USER CODE 1 BEGIN */
#warning "th_timestamp() not implemented"
    /* USER CODE 1 END */
    if (!g_mute_timestamps)
    {
#if EE_CFG_ENERGY_MODE == 1
        /**
         * 1. pull open-drain pin low
         * 2. wait at least 2us
         * 3. release pin
         */
#else
        /* This message must be printed, the host needs it. */
        th_printf(EE_MSG_TIMESTAMP, elapsedMicroSeconds);
#endif
    }
    return elapsedMicroSeconds;
}

/**
 * PORTME: Set up a serialport at 9600 baud to use for communication to the
 * host system if it hasn't already been done, otherwise it is OK to leave this
 * blank.
 *
 * Repeat: for connections through the IO Manager, baud rate is 9600!
 * For connections directly to the Host UI, baud must be 115200.
 */
void
th_serialport_initialize(void)
{
#if EE_CFG_ENERGY_MODE == 1
/* In energy mode, talk to the DUT through the IO Manager at baud = 9600 */
#else
/* In energy mode, talk to directly to the host at baud = 115200 */
#endif
}

/**
 * PORTME: Modify this function to call the proper printf and send to the
 * serial port.
 *
 * It may only be necessary to comment out this function and define
 * th_printf as printf and just rerout fputc();
 */
void
th_printf(const char *p_fmt, ...)
{
    va_list args;
    va_start(args, p_fmt);
    (void)th_vprintf(p_fmt, args);
    va_end(args);
}

/**
 * PORTME: This function is called with a pointer to the command built from the
 * ee_serial_callback() function during the ISR. It is up to the developer
 * to call ee_serial_command_parser_callback() at the next available non-ISR
 * clock with this command string.
 */
void
th_command_ready(volatile char *p_command)
{
    p_command = p_command;
/**
 * Example of how this might be implemented if there's no need to store
 * the command string locally:
 *
 * ee_serial_command_parser_callback(command);
 *
 * Or, depending on the baremetal/RTOS, it might be necessary to create a
 * static char array in this file, store the command, and then call
 * ee_serial_command_parser_callback() when the system is ready to do
 * work.
 */
#warning "th_command_ready() not implemented"
}

#endif /* EE_CFG_SELFHOSTED */
