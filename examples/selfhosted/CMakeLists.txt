cmake_minimum_required(VERSION 3.10.2)
project(sec-tls
	DESCRIPTION "Firmware for the SecureMark-TLS Self-Hosted Benchmark"
	LANGUAGES C
	VERSION 1.0.2)

option(SELFHOSTED "Set to '1' to build self-hosted binary, '0' by default makes a library" 0)

include(cmake/splint.cmake)

# Cross compiling with cmake (a possible example)
#set(tools /Users/ptorelli/dev/gcc-arm-none-eabi-8-2018-q4-major)
#set(CMAKE_C_COMPILER ${tools}/bin/arm-none-eabi-gcc)
#set(CMAKE_RANLIB ${tools}/bin/arm-none-eabi-ranlib)
#set(CMAKE_AR ${tools}/bin/arm-none-eabi-ar)
#set(CMAKE_LINKER ${tools}/bin/arm-none-eabi-ld)
#set(CMAKE_STRIP ${tools}/bin/arm-none-eabi-strip)
#set(CMAKE_NM ${tools}/bin/arm-none-eabi-nm)
#set(CMAKE_OBJDUMP ${tools}/bin/arm-none-eabi-objdump)

set(CMAKE_C_FLAGS "-pedantic -Wall -O3")

include_directories(../../monitor)
include_directories(../../monitor/th_api)
include_directories(../../profile)

if (SELFHOSTED)
    include_directories(profile/mbedtls_th_api)
    include_directories(profile/mbedtls_th_api/redist)
    set(SOURCE
        ../../monitor/ee_main.c
        ../../monitor/th_api/th_lib.c
        ../../monitor/th_api/th_libc.c
        ../../profile/ee_aes.c
        ../../profile/ee_ecdh.c
        ../../profile/ee_ecdsa.c
        ../../profile/ee_profile.c
        ../../profile/ee_sha.c
        ../../profile/ee_variations.c
        profile/mbedtls_th_api/redist/mbedtls/aes.c
        profile/mbedtls_th_api/redist/mbedtls/aesni.c
        profile/mbedtls_th_api/redist/mbedtls/asn1parse.c
        profile/mbedtls_th_api/redist/mbedtls/asn1write.c
        profile/mbedtls_th_api/redist/mbedtls/bignum.c
        profile/mbedtls_th_api/redist/mbedtls/ccm.c
        profile/mbedtls_th_api/redist/mbedtls/cipher.c
        profile/mbedtls_th_api/redist/mbedtls/cipher_wrap.c
        profile/mbedtls_th_api/redist/mbedtls/ecdh.c
        profile/mbedtls_th_api/redist/mbedtls/ecdsa.c
        profile/mbedtls_th_api/redist/mbedtls/ecp.c
        profile/mbedtls_th_api/redist/mbedtls/ecp_curves.c
        profile/mbedtls_th_api/redist/mbedtls/hmac_drbg.c
        profile/mbedtls_th_api/redist/mbedtls/md.c
        profile/mbedtls_th_api/redist/mbedtls/nist_kw.c
        profile/mbedtls_th_api/redist/mbedtls/platform_util.c
        profile/mbedtls_th_api/redist/mbedtls/sha256.c
        profile/mbedtls_th_api/th_aes.c
        profile/mbedtls_th_api/th_ecdh.c
        profile/mbedtls_th_api/th_ecdsa.c
        profile/mbedtls_th_api/th_sha.c
        profile/mbedtls_th_api/th_util.c
        main.c
    )
    add_definitions(-DEE_CFG_SELFHOSTED=1)
    add_definitions(-DEE_CFG_QUIET=1)
    add_executable(sec-tls ${SOURCE})
elseif(WOLFSSL)
    include_directories(profile/wolfssl_th_api)
    set(SOURCE
        ../../profile/ee_aes.c
        ../../profile/ee_ecdsa.c
        ../../profile/ee_variations.c
        ../../profile/ee_ecdh.c
        ../../profile/ee_profile.c
        ../../profile/ee_sha.c
        profile/wolfssl_th_api/th_aes.c
        profile/wolfssl_th_api/th_util.c
        profile/wolfssl_th_api/th_ecdh.c
        profile/wolfssl_th_api/th_ecdsa.c
        profile/wolfssl_th_api/th_sha.c
        ../../monitor/ee_main.c
        ../../monitor/th_api/th_lib.c
        ../../monitor/th_api/th_libc.c
        main.c
    )
    find_path(WOLFSSL_INCLUDE wolfssl/options.h)
    find_library(WOLFSSL_LIB wolfssl)

    include_directories(${WOLFSSL_INCLUDE})
    link_libraries(${WOLFSSL_LIB})

    message("WOLFSSL_INCLUDE = ${WOLFSSL_INCLUDE}")
    message("WOLFSSL_LIB = ${WOLFSSL_LIB}")

    add_definitions(-DEE_CFG_SELFHOSTED=1)
    add_definitions(-DEE_CFG_QUIET=1)
    add_executable(sec-tls ${SOURCE})
else()
    include_directories(../../monitor/th_api)
    include_directories(../../profile/th_api)
    set(SOURCE
        ../../profile/ee_aes.c
        ../../profile/ee_ecdsa.c
        ../../profile/ee_variations.c
        ../../profile/ee_ecdh.c
        ../../profile/ee_profile.c
        ../../profile/ee_sha.c
        ../../profile/th_api/th_aes.c
        ../../profile/th_api/th_sha.c
        ../../profile/th_api/th_util.c
        ../../profile/th_api/th_ecdh.c
        ../../profile/th_api/th_ecdsa.c
        ../../monitor/ee_main.c
        ../../monitor/th_api/th_lib.c
        ../../monitor/th_api/th_libc.c
    )
    add_library(sec-tls ${SOURCE})
endif()

add_splint(sec-tls ${SOURCE})
