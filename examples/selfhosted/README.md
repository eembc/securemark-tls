# Introduction

This example implements a self-hosted version of the benchmark by including
a `main()` entry point with an mbedTLS crypto SDK. It does not require a UART
or GPIO timestamp, nor does it require the host UI. It can be compiled into 
a stand-alone executable which can be run from an OS, or bare-metal on an
embedded platform.

# Details

## Harness

The `th_printf` and `th_timestamp` functions are implemented in `main.c`. By
compiling with the `EE_CFG_SELFHOSTED` flag set, all of the code for the UART
is removed and replaced with these two local functions. To run the benchmark,
a set of wrapper functions in `main.c` prepare the primitives for local
execution. Keys, plaintext, and ciphertext are all generated randomly with
`ee_srand()` which is seeded with zero for each primitive invocation.

The `th_timestamp` function is implemented with the POSIX `clock_gettime`
function, which reports elapsed time down to nanoseconds (if supported). If
your compiler does not support this function, edit the `th_timestamp` function
to generate a counter that increases at least once per microsecond.

## Self-timing

The benchmark determines the correct number of iterations automatically by
proportionally increasing the count until a minimum number of seconds (or
minimum number of iterations) elapse. See `MIN_RUNTIME_SEC` and `MIN_ITER` in
`main.c`.

## Self-checking

A set of 16-bit CRC values are provided per sub-test, precomputed by EEMBC. As
long as the seeds in the code aren't changed, these should always be the same.
This is to help verify the primitive SDK implementation is was done correctly.

# Compile and run

The `cmake` list file will build one of three options, depending on the following
variables:

`SELFHOSTED` - Builds a reference mbedTLS executable (mbedTLS source included)
`WOLFSSL` - Builds a reference wolfSSL executable (wolfSSL must be installed)
default - Compiles and builds a library with the un-implemented functions

## Default `SELFHOSTED`: mbedTLS (2.4.2)

This example uses `cmake`. The option `SELFHOSTED` enables the `EE_CFG_SELFHOSTED`
flag in the code, and links in the local `profile/th_api` implementation (as
well as `main.c`).

```
% mkdir build
% cd build
% cmake -DSELFHOSTED=1 ..
% make
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

To compile the SecureMark-TLS benchmark on Windows using Visual Studio open 
the Visual Studio project file at `visualc/sec-tls/sec-tls.vcxproj`.

## `WOLFSSL` self-hosted

To build with using wolfSSL for crypto (https://github.com/wolfssl/wolfssl)
install wolfSSL version 4.8.0 or later on the system. On the host a good configure option to use when
building wolfSSL is:

```Bash
% ./autogen.sh
% ./configure CFLAGS="-DWOLFSSL_AES_DIRECT -DHAVE_AES_ECB -DWOLFSSL_ECDSA_DETERMINISTIC_K" \
              --enable-ecc --enable-keygen --enable-aesccm --enable-sp --enable-sp-asm \
              --enable-eccencrypt --enable-curve25519 --enable-ed25519


% ./configure CFLAGS='-DWOLFSSL_AES_DIRECT -DECC_TIMING_RESISTANT -DHAVE_AES_ECB -DWOLFSSL_ECDSA_DETERMINISTIC_K' \
              --enable-ecc --enable-keygen --enable-aesccm --enable-sp --enable-sp-asm \
              --enable-eccencrypt --enable-curve25519 --enable-ed25519 \
              --enable-aesctr --disable-harden
% make
% sudo make install
```

TODO: Why did we leave ECC_TIMING_RESISTANT?

Note: disabling harden to prevent RSA blinding in order to generate deterministic RSA signatures

Then run `cmake` for SecureMark from this `examples/selfhosted` directory, and execute the benchmark:

```Bash
% mkdir build
% cd build
% cmake -DWOLFSSL=1 ..
% make
% ./sec-tls
```

# Scoring

This code is provided as an example of how the benchmark operates. In order to
generate an official score, the host software must be used to verify operation
of the benchmark (to discourage cheating). Please contact 
[support@eembc.org](mailto:support@eembc.org) for information on how to license the host
software.

