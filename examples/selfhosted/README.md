# Introduction

This example implements a self-hosted version of the benchmark by including
a `main()` entrypoint with an mbedTLS crypto SDK. It does not requrie a UART
or GPIO timestamp, nor does it require the host UI. It can be compiled into 
a stand-alone executable which can be run from an OS or as baremetal on an
embedded platform.

# Details

## Harness

The `th_printf` and `th_timestamp` functions are implemented in `main.c`. By
compiling with the `EE_CFG_SELFHOSTED` flag set, all of the code for the UART
is removed and replaced with these two local functions. To run the benchmark,
a set of wrapper functions in `main.c` prepare the primitives for local
execution. Keys, plaintext, and ciphertext are all generated randomly with
`ee_srand()` which is seeded with zero for each primitive invocation.

## Self-timinig

The benchmark determines the correct number of iterations automatically by
porportionally increasing the count until a minimum number of seconds (or
minimum number of iterations) elapse. See `MIN_RUNTIME_SEC` and `MIN_ITER` in
`main.c`.

## Self-checking

A set of 16-bit CRC values are provided per sub-test, precomputed by EEMBC. As
long as the seeds in the code aren't changed, these should always be the same.
This is to help verify the primitive SDK implementation is was done correctly.

# Compile and run

This example uses `cmake`. The option `SELFHOSTED` enables the `EE_CFG_SELFHOSTED`
flag in the code, and links in the local `profile/th_api` implementation (as
well as `main.c`).

```
% mkdir build
% cd build
% cmake -DSELFHOSTED=1 ..
% make
:
:
% ./sec-tls
Running each primitive for at least 1s or 10 iterations.
Component #00 ips=    1286609.125 crc=0xc7b0 expected_crc=0xc7b0
Component #01 ips=     886544.812 crc=0x5481 expected_crc=0x5481
Component #02 ips=     633161.562 crc=0x998a expected_crc=0x998a
Component #03 ips=     766433.250 crc=0xd82d expected_crc=0xd82d
Component #04 ips=     393285.844 crc=0x005b expected_crc=0x005b
Component #05 ips=        499.762 crc=0xb659 expected_crc=0xb659
Component #06 ips=       1209.260 crc=0x3a47 expected_crc=0x3a47
Component #07 ips=        344.412 crc=0x3a47 expected_crc=0x3a47
Component #08 ips=    7161712.000 crc=0x2151 expected_crc=0x2151
Component #09 ips=    2998751.750 crc=0x3b3c expected_crc=0x3b3c
Component #10 ips=     473102.938 crc=0x1d3f expected_crc=0x1d3f
Component #11 ips=      79961.562 crc=0x0000 expected_crc=0x0000
Component #12 ips=      42851.652 crc=0x9284 expected_crc=0x9284
Component #13 ips=     101118.016 crc=0x989e expected_crc=0x989e
SecureMark-TLS Score is 112677.812 marks
:
```

# Scoring

This code is provided as an example of how the benchmark operates. In order to
generate an official score, the host software must be used to verify operation
of the benchmark (to discourage cheating). Please contact 
[support@eembc.org](mailto:support@eembc.org) for information on how to license the host
software.



