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

#include "ee_profile.h"

/**
 * @brief This indicates if the DUT should print verification feedback to the
 * Host. See `th_api/th_lib.c`.
 */
extern bool g_mute_timestamps;

#if EE_CFG_SELFHOSTED != 1

/* Verify mode means extra output will be sent to the host. */
static bool g_verify_mode = false;

arg_claimed_t
ee_profile_parse(char *p_command)
{
    char *p_next;
    long  hex;

    if (th_strncmp(p_command, "profile", EE_CMD_SIZE) == 0)
    {
        th_printf("m-profile-[%s]\r\n", EE_FW_VERSION);
    }
    else if (th_strncmp(p_command, "verify", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);
        if (p_next)
        {
            g_verify_mode = (th_atoi(p_next) != 0);
            /* Verify mode prints extra content, but turns off timestamps! */
            g_mute_timestamps = g_verify_mode;
        }
        th_printf("m-verify-%s\r\n", g_verify_mode ? "on" : "off");
    }
    else if (th_strncmp(p_command, "srand", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);

        if (p_next == NULL)
        {
            th_printf("e-[Command srand requires a seed byte, in hex]\r\n");
        }
        else
        {
            hex = ee_hexdec(p_next);

            if (hex < 0)
            {
                th_printf("e-[Invalid hex byte given to srand: %s]\r\n",
                          p_next);
            }
            else
            {
                ee_srand((uint8_t)hex);
            }
        }
    }
    else if (th_strncmp(p_command, "help", EE_CMD_SIZE) == 0)
    {
        th_printf("%s\r\n", EE_FW_VERSION);
        th_printf("\r\n");
        th_printf(
            "help                : Print this information\r\n"
            "name                : Print the name of this device\r\n"
            "profile             : Print the benchmark profile & version\r\n"
            "verify-[0|1]        : Get or set verify mode\r\n"
            "srand-XX            : Seed the PSRN with a hex byte, e.g 7F\r\n"
            "bench-SUBCMD        : Issue a 'bench' subcommand & paramters\r\n"
            "  sha256-*          : SHA256\r\n"
            "  aes128_ecb-*      : AES128 ECB encrypt and decrypt\r\n"
            "  aes128_ccm-*      : AES127 CCM encrypt and decrypt\r\n"
            "  ecdh256-*         : ECDH secret generation (p256r1)\r\n"
            "  ecdsa256-*        : ECDSA sign and verify (p256r1)\r\n"
            "  var01-*           : Varation #1 (mixed contexts)\r\n"
            "     Where *=SEED-ITER-LEN\r\n"
            "     Each subcmd takes a PRNG seed, #iterations & #bytes\r\n"
            "buffer-SUBCMD       : Issue a 'buffer' subcommand\r\n"
            "  fill-XX           : File the buffer with XX hex byte\r\n"
            "  add-XX[-XX]*      : Add hex byte(s) XX to current buffer\r\n"
            "                      pointer (it will wrap)\r\n"
            "  rewind            : Rewind the buffer pointer to the start\r\n"
            "  print             : Print ALL buffer bytes (as hex)\r\n");
    }
    else if (ee_bench_parse(p_command, g_mute_timestamps) == EE_ARG_CLAIMED)
    {
    }
    else if (ee_buffer_parse(p_command) == EE_ARG_CLAIMED)
    {
    }
    else
    {
        return EE_ARG_UNCLAIMED;
    }
    return EE_ARG_CLAIMED;
}

void
ee_profile_initialize(void)
{
    th_buffer_initialize();
    th_profile_initialize();
    g_mute_timestamps = false;
    if (th_buffer_size() < EE_MINBUF)
    {
        /* The host will catch this, rather than returning a value. */
        th_printf("e-[Buffer must be at least %u bytes]\r\n", EE_MINBUF);
    }
}

#endif /* EE_CFG_SELFHOSTED */
