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
	set(CMAKE_C_FLAGS "-pedantic -Wall -O3 -DEE_CFG_SELFHOSTED=1")
	if(MBEDTLS)
		include_directories(profile/th_api)
		include_directories(profile/th_api/redist/mbedtls-3.0.0/include)
		set(SOURCE
			../../profile/ee_aes.c
			../../profile/ee_bench.c
			../../profile/ee_buffer.c
			../../profile/ee_chachapoly.c
			../../profile/ee_ecdh.c
			../../profile/ee_ecdsa.c
			../../profile/ee_profile.c
			../../profile/ee_sha.c
			../../profile/ee_util.c
			../../profile/ee_variations.c

			profile/th_api/th_aes.c
			profile/th_api/th_chachapoly.c
			profile/th_api/th_ecdh.c
			profile/th_api/th_ecdsa.c
			profile/th_api/th_sha.c
			profile/th_api/th_util.c

			../../monitor/ee_main.c
			../../monitor/th_api/th_lib.c
			../../monitor/th_api/th_libc.c

			profile/th_api/redist/mbedtls-3.0.0/library/aes.c
			profile/th_api/redist/mbedtls-3.0.0/library/aesni.c
			profile/th_api/redist/mbedtls-3.0.0/library/aria.c
			profile/th_api/redist/mbedtls-3.0.0/library/asn1parse.c
			profile/th_api/redist/mbedtls-3.0.0/library/asn1write.c
			profile/th_api/redist/mbedtls-3.0.0/library/base64.c
			profile/th_api/redist/mbedtls-3.0.0/library/bignum.c
			profile/th_api/redist/mbedtls-3.0.0/library/camellia.c
			profile/th_api/redist/mbedtls-3.0.0/library/ccm.c
			profile/th_api/redist/mbedtls-3.0.0/library/chacha20.c
			profile/th_api/redist/mbedtls-3.0.0/library/chachapoly.c
			profile/th_api/redist/mbedtls-3.0.0/library/cipher.c
			profile/th_api/redist/mbedtls-3.0.0/library/cipher_wrap.c
			profile/th_api/redist/mbedtls-3.0.0/library/cmac.c
			profile/th_api/redist/mbedtls-3.0.0/library/ctr_drbg.c
			profile/th_api/redist/mbedtls-3.0.0/library/debug.c
			profile/th_api/redist/mbedtls-3.0.0/library/des.c
			profile/th_api/redist/mbedtls-3.0.0/library/dhm.c
			profile/th_api/redist/mbedtls-3.0.0/library/ecdh.c
			profile/th_api/redist/mbedtls-3.0.0/library/ecdsa.c
			profile/th_api/redist/mbedtls-3.0.0/library/ecjpake.c
			profile/th_api/redist/mbedtls-3.0.0/library/ecp.c
			profile/th_api/redist/mbedtls-3.0.0/library/ecp_curves.c
			profile/th_api/redist/mbedtls-3.0.0/library/entropy.c
			profile/th_api/redist/mbedtls-3.0.0/library/entropy_poll.c
			profile/th_api/redist/mbedtls-3.0.0/library/gcm.c
			profile/th_api/redist/mbedtls-3.0.0/library/hkdf.c
			profile/th_api/redist/mbedtls-3.0.0/library/hmac_drbg.c
			profile/th_api/redist/mbedtls-3.0.0/library/md5.c
			profile/th_api/redist/mbedtls-3.0.0/library/md.c
			profile/th_api/redist/mbedtls-3.0.0/library/memory_buffer_alloc.c
			profile/th_api/redist/mbedtls-3.0.0/library/mps_reader.c
			profile/th_api/redist/mbedtls-3.0.0/library/mps_trace.c
			profile/th_api/redist/mbedtls-3.0.0/library/net_sockets.c
			profile/th_api/redist/mbedtls-3.0.0/library/nist_kw.c
			profile/th_api/redist/mbedtls-3.0.0/library/oid.c
			profile/th_api/redist/mbedtls-3.0.0/library/padlock.c
			profile/th_api/redist/mbedtls-3.0.0/library/pem.c
			profile/th_api/redist/mbedtls-3.0.0/library/pk.c
			profile/th_api/redist/mbedtls-3.0.0/library/pkcs12.c
			profile/th_api/redist/mbedtls-3.0.0/library/pkcs5.c
			profile/th_api/redist/mbedtls-3.0.0/library/pkparse.c
			profile/th_api/redist/mbedtls-3.0.0/library/pk_wrap.c
			profile/th_api/redist/mbedtls-3.0.0/library/pkwrite.c
			profile/th_api/redist/mbedtls-3.0.0/library/platform.c
			profile/th_api/redist/mbedtls-3.0.0/library/platform_util.c
			profile/th_api/redist/mbedtls-3.0.0/library/poly1305.c
			profile/th_api/redist/mbedtls-3.0.0/library/ripemd160.c
			profile/th_api/redist/mbedtls-3.0.0/library/rsa_alt_helpers.c
			profile/th_api/redist/mbedtls-3.0.0/library/rsa.c
			profile/th_api/redist/mbedtls-3.0.0/library/sha1.c
			profile/th_api/redist/mbedtls-3.0.0/library/sha256.c
			profile/th_api/redist/mbedtls-3.0.0/library/sha512.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_cache.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_ciphersuites.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_cli.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_cookie.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_msg.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_srv.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_ticket.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_tls13_keys.c
			profile/th_api/redist/mbedtls-3.0.0/library/ssl_tls.c
			profile/th_api/redist/mbedtls-3.0.0/library/threading.c
			profile/th_api/redist/mbedtls-3.0.0/library/timing.c
			profile/th_api/redist/mbedtls-3.0.0/library/version.c
			profile/th_api/redist/mbedtls-3.0.0/library/x509.c
			profile/th_api/redist/mbedtls-3.0.0/library/x509_create.c
			profile/th_api/redist/mbedtls-3.0.0/library/x509_crl.c
			profile/th_api/redist/mbedtls-3.0.0/library/x509_crt.c
			profile/th_api/redist/mbedtls-3.0.0/library/x509_csr.c
			profile/th_api/redist/mbedtls-3.0.0/library/x509write_crt.c
			profile/th_api/redist/mbedtls-3.0.0/library/x509write_csr.c

			main.c
		)
		add_definitions(-DEE_CFG_SELFHOSTED=1)
		add_definitions(-DEE_CFG_QUIET=1)
		add_executable(sec-tls ${SOURCE})
	endif()
else()
    include_directories(../../monitor/th_api)
    include_directories(../../profile/th_api)
    set(SOURCE
        ../../profile/ee_aes.c
        ../../profile/ee_bench.c
        ../../profile/ee_buffer.c
        ../../profile/ee_chachapoly.c
        ../../profile/ee_ecdh.c
        ../../profile/ee_ecdsa.c
        ../../profile/ee_profile.c
        ../../profile/ee_sha.c
        ../../profile/ee_util.c
        ../../profile/ee_variations.c
        ../../profile/th_api/th_aes.c
        ../../profile/th_api/th_chachapoly.c
        ../../profile/th_api/th_ecdh.c
        ../../profile/th_api/th_ecdsa.c
        ../../profile/th_api/th_sha.c
        ../../profile/th_api/th_util.c
        ../../monitor/ee_main.c
        ../../monitor/th_api/th_lib.c
        ../../monitor/th_api/th_libc.c
    )
    add_library(sec-tls ${SOURCE})
endif()

add_splint(sec-tls ${SOURCE})
