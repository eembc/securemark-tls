cmake_minimum_required(VERSION 3.10.2)
project(sec-tls
        DESCRIPTION "Firmware for the SecureMark-TLS Self-Hosted Benchmark"
        LANGUAGES C
        VERSION 1.0.3)

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
            ../../profile/ee_aes.c
            ../../profile/ee_ecdsa.c
            ../../profile/ee_variations.c
            ../../profile/ee_ecdh.c
            ../../profile/ee_profile.c
            ../../profile/ee_sha.c
            profile/mbedtls_th_api/th_aes.c
            profile/mbedtls_th_api/redist/mbedtls/aes.c
            profile/mbedtls_th_api/redist/mbedtls/ecdh.c
            profile/mbedtls_th_api/redist/mbedtls/cipher_wrap.c
            profile/mbedtls_th_api/redist/mbedtls/hmac_drbg.c
            profile/mbedtls_th_api/redist/mbedtls/asn1parse.c
            profile/mbedtls_th_api/redist/mbedtls/asn1write.c
            profile/mbedtls_th_api/redist/mbedtls/ccm.c
            profile/mbedtls_th_api/redist/mbedtls/bignum.c
            profile/mbedtls_th_api/redist/mbedtls/md_wrap.c
            profile/mbedtls_th_api/redist/mbedtls/ecp.c
            profile/mbedtls_th_api/redist/mbedtls/sha256.c
            profile/mbedtls_th_api/redist/mbedtls/ecp_curves.c
            profile/mbedtls_th_api/redist/mbedtls/md.c
            profile/mbedtls_th_api/redist/mbedtls/cipher.c
            profile/mbedtls_th_api/redist/mbedtls/ecdsa.c
            profile/mbedtls_th_api/th_util.c
            profile/mbedtls_th_api/th_ecdh.c
            profile/mbedtls_th_api/th_ecdsa.c
            profile/mbedtls_th_api/th_sha.c
            ../../monitor/ee_main.c
            ../../monitor/th_api/th_lib.c
            ../../monitor/th_api/th_libc.c
            main.c
            )
    add_definitions(-DEE_CFG_SELFHOSTED=1)
    add_definitions(-DEE_CFG_QUIET=1)
    add_executable(sec-tls ${SOURCE})
elseif(PSA_MBEDTLS)
    include_directories(profile/psa_crypto_th_api)
    include_directories(profile/psa_crypto_th_api/redist/mbedtls)
    include_directories(profile/psa_crypto_th_api/redist/mbedtls/library)
    include_directories(profile/psa_crypto_th_api/redist/mbedtls/include)
    set(src_crypto
            profile/psa_crypto_th_api/redist/mbedtls/library/aes.c
            profile/psa_crypto_th_api/redist/mbedtls/library/asn1parse.c
            profile/psa_crypto_th_api/redist/mbedtls/library/asn1write.c
            profile/psa_crypto_th_api/redist/mbedtls/library/bignum.c
            profile/psa_crypto_th_api/redist/mbedtls/library/ccm.c
            profile/psa_crypto_th_api/redist/mbedtls/library/cipher.c
            profile/psa_crypto_th_api/redist/mbedtls/library/cipher_wrap.c
            profile/psa_crypto_th_api/redist/mbedtls/library/constant_time.c
            profile/psa_crypto_th_api/redist/mbedtls/library/ctr_drbg.c
            profile/psa_crypto_th_api/redist/mbedtls/library/ecdh.c
            profile/psa_crypto_th_api/redist/mbedtls/library/ecdsa.c
            profile/psa_crypto_th_api/redist/mbedtls/library/ecp.c
            profile/psa_crypto_th_api/redist/mbedtls/library/ecp_curves.c
            profile/psa_crypto_th_api/redist/mbedtls/library/entropy.c
            profile/psa_crypto_th_api/redist/mbedtls/library/entropy_poll.c
            profile/psa_crypto_th_api/redist/mbedtls/library/error.c
            profile/psa_crypto_th_api/redist/mbedtls/library/hmac_drbg.c
            profile/psa_crypto_th_api/redist/mbedtls/library/md.c
            profile/psa_crypto_th_api/redist/mbedtls/library/memory_buffer_alloc.c
            profile/psa_crypto_th_api/redist/mbedtls/library/mps_reader.c
            profile/psa_crypto_th_api/redist/mbedtls/library/mps_trace.c
            profile/psa_crypto_th_api/redist/mbedtls/library/nist_kw.c
            profile/psa_crypto_th_api/redist/mbedtls/library/platform.c
            profile/psa_crypto_th_api/redist/mbedtls/library/platform_util.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_aead.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_cipher.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_client.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_driver_wrappers.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_ecp.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_hash.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_mac.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_rsa.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_slot_management.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_crypto_storage.c
            profile/psa_crypto_th_api/redist/mbedtls/library/psa_its_file.c
            profile/psa_crypto_th_api/redist/mbedtls/library/sha256.c
            profile/psa_crypto_th_api/redist/mbedtls/library/threading.c
            profile/psa_crypto_th_api/redist/mbedtls/library/timing.c
            profile/psa_crypto_th_api/redist/mbedtls/library/version.c
            profile/psa_crypto_th_api/redist/mbedtls/library/version_features.c
    )
    set(SOURCE
            ../../profile/ee_aes.c
            ../../profile/ee_ecdsa.c
            ../../profile/ee_variations.c
            ../../profile/ee_ecdh.c
            ../../profile/ee_profile.c
            ../../profile/ee_sha.c
            profile/psa_crypto_th_api/th_aes.c
            profile/psa_crypto_th_api/th_util.c
            profile/psa_crypto_th_api/th_ecdh.c
            profile/psa_crypto_th_api/th_ecdsa.c
            profile/psa_crypto_th_api/th_sha.c
            ../../monitor/ee_main.c
            ../../monitor/th_api/th_lib.c
            ../../monitor/th_api/th_libc.c
            main.c
    )
    add_definitions(-DEE_CFG_SELFHOSTED=1)
    add_definitions(-DEE_CFG_QUIET=1)
    add_executable(sec-tls ${src_crypto})
    target_sources(sec-tls PRIVATE ${SOURCE})
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
