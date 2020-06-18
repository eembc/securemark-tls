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

#if EE_CFG_ENERGY_MODE == 1
#else
extern bool g_verify_mode; // see th_timestamp()
#endif

#if EE_CFG_SELFHOSTED != 1

/**
 * PORTME: If there's anything else that needs to be done on init, do it here,
 * othewise OK to leave it alone.
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
    // USER CODE 1 BEGIN
    // USER CODE 1 END
    // Always print this message
    th_printf(EE_MSG_TIMESTAMP_MODE);
    /* Always call the timestamp on initialize so that the open-drain output
       is set to "1" (so that we catch a falling edge) */
    th_timestamp();
}

/**
 * PORTME: Generate a falling edge. Since GPIO pin is OPEN-DRAIN it is OK to
 * float and let the pullup resistor drive.
 *
 * NOTE: The hold time is 62.5ns.
 */
void
th_timestamp(void)
{
    #warning "th_timestamp() not implemented"
    #if EE_CFG_ENERGY_MODE==1
    // 1. pull pin low
    // 2. wait at least 62.5ns
    // 3. set pin high
    #else
    // Don't print timestamps during verification mode!
    if (g_verify_mode != 0)
    {
        return;
    }
    else
    {
        uint32_t elapsedMicroSeconds = 0;
        // Print out the timestamp in this exact format:
        th_printf(EE_MSG_TIMESTAMP, elapsedMicroSeconds);
    }
    #endif
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
    #if EE_CFG_ENERGY_MODE==1
    // For energy mode, we talk to the DUT through the IO Manager at 9600
    // baud = 9600
    #else
    // For performance mode, we talk directly to the DUT at 115200
    // baud == 115200
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
    (void)th_vprintf(p_fmt, args); // ignore return
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

#endif // EE_CFG_SELFHOSTED
