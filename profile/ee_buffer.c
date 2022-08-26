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

#include "ee_buffer.h"

static uint32_t g_buffer_pos = 0;

void
ee_buffer_add(uint8_t byte)
{
    (th_buffer_address())[g_buffer_pos] = byte;
    ++g_buffer_pos;
    if (g_buffer_pos >= th_buffer_size())
    {
        g_buffer_pos = 0;
    }
}

void
ee_buffer_rewind(void)
{
    g_buffer_pos = 0;
}

void
ee_buffer_fill(uint8_t byte)
{
    uint32_t i;

    ee_buffer_rewind();
    for (i = 0; i < th_buffer_size(); ++i)
    {
        ee_buffer_add(byte);
    }
}

void
ee_buffer_print(void)
{
    uint8_t *buffer;
    uint32_t buffer_size;
    uint32_t i;

    buffer      = th_buffer_address();
    buffer_size = th_buffer_size();

    th_printf("m-buffer-");
    for (i = 0; i < buffer_size; ++i)
    {
        th_printf("%02x", buffer[i]);
        if ((i + 1) % 16 == 0)
        {
            th_printf("\r\n");
            if ((i + 1) < buffer_size)
            {
                th_printf("m-buffer-");
            }
        }
        else if ((i + 1) < buffer_size)
        {
            th_printf("-");
        }
    }
    if (i % 16 != 0)
    {
        th_printf("\r\n");
    }
}

arg_claimed_t
ee_buffer_parse(char *p_command)
{
    char *p_subcmd;
    char *p_next;
    long  hex;

    if (th_strncmp(p_command, "buffer", EE_CMD_SIZE) != 0)
    {
        return EE_ARG_UNCLAIMED;
    }

    p_subcmd = th_strtok(NULL, EE_CMD_DELIMITER);

    if (p_subcmd == NULL)
    {
        th_printf("e-[Command 'buffer' takes a subcommand]\r\n");
        return EE_ARG_CLAIMED;
    }

    if (th_strncmp(p_subcmd, "fill", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);

        if (p_next)
        {
            hex = ee_hexdec(p_next);

            if (hex < 0)
            {
                th_printf("e-[Buffer fill invalid byte: %s]\r\n", p_next);
            }
            else
            {
                ee_buffer_fill((uint8_t)hex);
            }
        }
        else
        {
            th_printf("e-[Buffer fill missing a byte]\r\n");
        }
    }
    else if (th_strncmp(p_subcmd, "add", EE_CMD_SIZE) == 0)
    {
        p_next = th_strtok(NULL, EE_CMD_DELIMITER);

        if (p_next == NULL)
        {
            th_printf("e-[Buffer add expects at least on byte]\r\n");
        }
        else
        {
            while (p_next != NULL)
            {
                hex = ee_hexdec(p_next);

                if (hex < 0)
                {
                    th_printf("e-[Buffer add invalid byte: %s]\r\n", p_next);
                }
                else
                {
                    ee_buffer_add((uint8_t)hex);
                }

                p_next = th_strtok(NULL, EE_CMD_DELIMITER);
            }
        }
    }
    else if (th_strncmp(p_subcmd, "rewind", EE_CMD_SIZE) == 0)
    {
        ee_buffer_rewind();
    }
    else if (th_strncmp(p_subcmd, "print", EE_CMD_SIZE) == 0)
    {
        ee_buffer_print();
    }
    else
    {
        th_printf("e-[Unknown buffer subcommand: %s]\r\n", p_subcmd);
    }
    return EE_ARG_CLAIMED;
}
