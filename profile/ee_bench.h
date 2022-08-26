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

#ifndef __EE_BENCH_H
#define __EE_BENCH_H

#include "ee_main.h"
#include "ee_aes.h"
#include "ee_chachapoly.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_rsa.h"
#include "ee_sha.h"
#include "ee_variations.h"
#include "ee_util.h"

/**
 * @brief The top-level SHA benchmark wrapper.
 *
 * The `th_buffer` will be populated by the function. The resulting contents
 * shall be as follows:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Message (randomly generated)
 * " + n        Digest (size depends on SHA)
 *
 * @param size - The enum indicating the number of bits in the SHA
 * @param n - The length of the random message to create
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_sha(ee_sha_size_t size, uint32_t n, uint32_t i, bool verify);

/**
 * @brief The top-level SHA multi benchmark wrapper.
 *
 * The `th_buffer` will be populated by the function. The resulting contents
 * shall be as follows:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            # of SHAs to do = N
 * 4            1st 32-bit sizes, the size of each SHA
 * 4+4*1        2nd
 * 4+4*(N-1)    Nth SHA input size
 * 4+4*N        1st output digest pointer
 * 4+4*N+P*(N-1)Nth output digest pointer; pointer size in bytes = P
 * 4+4*N+P*N    1st input message pointer
 * 4*4*N+P*N+P*(N-1) Nth input message pointer
 *
 * @param size - The enum indicating the number of bits in the SHA
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_sha_multi(ee_sha_size_t size, uint32_t i, bool verify);

/**
 * @brief The top-level AES benchmark wrapper.
 *
 * The `th_buffer` will be populated by the function. The resulting contents
 * shall be as follows:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            key (randomly generated)
 * " + keylen   iv (if used, randomly generated)
 * " + ivlen    input text message (randomly generated)
 * " + n        output buffer (result of encrypt/decrypt)
 * " + n        tag (if used, populated by function)
 *
 * Why not just have the host pre-fill the buffer and ignore `n`? Randomly
 * generating these values on the DUT reduces the amount of data the host has
 * to send down the UART, speeding up the test.
 *
 * @param mode - The enum indicating the AES mode
 * @param func - The enum indicating the function
 * @param keylen - The length of the key to generate (in bytes)
 * @param n - The length of the text (plain/cipher, depends on function)
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_aes(ee_aes_mode_t mode, ee_aes_func_t func, uint32_t i, bool verify);

/**
 * @brief The top-level AES multi benchmark wrapper.
 *
 * The `th_buffer` will be populated by the function. The resulting contents
 * shall be as follows:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            # of AESs to do = N
 * 4            N 32-bit sizes, the size of each AES operation
 * :
 * 4+4*N        1st output ciphertext pointer
 * 4+4*N+P*(N-1)Nth output ciphertext pointer; pointer size in bytes = P
 * 4+4*N+P*N    1st input plaintext pointer
 * 4*4*N+P*N+P*(N-1) Nth input plantext pointer
 *
 * @param mode - The enum indicating the AES mode
 * @param func - The enum indicating the function
 * @param i - The number of iterations to perform
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_aes_multi(ee_aes_mode_t mode, ee_aes_func_t func, uint32_t i);

/**
 * @brief The top-level ChaCha20-Poly1305 benchmark wrapper.
 *
 * The `th_buffer` will be populated by the function. The resulting contents
 * shall be as follows:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            key (randomly generated)
 * " + keylen   iv (if used, randomly generated)
 * " + ivlen    input text message (randomly generated)
 * " + n        output buffer (result of encrypt/decrypt)
 * " + n        tag (if used, populated by function)
 *
 * See note above in `ee_bench_aes()` about host pre-filling the buffer.
 *
 * @param func - The enum indicating the function
 * @param n - The length of the text (plain/cipher, depends on function)
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_chachapoly(ee_chachapoly_func_t func,
                             int                  n,
                             int                  i,
                             bool                 verify);

/**
 * @brief The top-level ECDH benchmark wrapper.
 *
 * The wrapper expects this format to the `th_buffer`:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Input: length of public key (32-bits)
 * 4            Input: public key
 * " + publen   Output: length of secret (32-bits)
 * " + seclen   Output: secret
 *
 * For SECP/NIST curves 256r1 and 384r1, the public key is uncompressed X, Y
 * coordinates, 256 or 384 bits as SECP1 format { 04 | X | Y }; For X25519, it
 * is 256 bits.
 *
 * @param g - See the `ee_ecdh_group_t` enum
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_ecdh(ee_ecdh_group_t g, uint32_t i, bool verify);

/**
 * @brief The top-level ECDSA/EdDSA sign benchmark wrapper.
 *
 * The wrapper expects this format to the `th_buffer`:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Input: message data (n bytes)
 * " + n        Output: 256-byte buffer for public key
 * " + 256      Output: 256-byte buffer for signature
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * @param g - See the `ee_ecdh_group_t` enum
 * @param n - The length of the message to sign
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_ecdsa_sign(ee_ecdh_group_t g,
                             uint32_t        n,
                             uint32_t        i,
                             bool            verify);

/**
 * @brief The top-level ECDSA/EdDSA sign benchmark wrapper.
 *
 * The wrapper expects this format to the `th_buffer`:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Input: Message buffer
 * "" + n       Input: 32-bit length of public key in bytes
 * "" + 4       Input: Public key buffer
 * "" + publen  Input: 32-bit length of signature in bytes
 * "" + 4       Input: Signature buffer
 * "" + siglen  Output: pass/fail byte (1=pass 0=fail)
 *
 * For SECP/NIST curves 256r1 and 384r1, the public key is uncompressed X, Y
 * coordinates, 256 or 384 bits as SECP1 format { 04 | X | Y }; For X25519, it
 * is 256 bits.
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * @param g - See the `ee_ecdh_group_t` enum
 * @param n - The length of the message to sign
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_ecdsa_verify(ee_ecdh_group_t g,
                               uint32_t        n,
                               uint32_t        i,
                               bool            verify);

/**
 * @brief The top-level RSA benchmark wrapper.
 *
 * The wrapper expects this format to the `th_buffer`:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Input: Message buffer
 * "" + n       Input: 32-bit length of public key in bytes
 * "" + 4       Input: Public key buffer
 * "" + publen  Input: 32-bit length of signature in bytes
 * "" + 4       Input: Signature buffer
 * "" + siglen  Output: pass/fail byte (1=pass 0=fail)
 *
 * The message is the non-encoded encryption of message M according to PCKS1v15.
 * Meaning, the hash will not be encoded, it will simply be padded and
 * encrypted, and the expected signature for verification will follow the
 * same convention.
 *
 * The public key is in ASN.1 DER format {n,e} according to RFC 8017 A.1.1
 *
 * @param id - The RSA enum indicating the modulus
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @return uint32_t - Execution time in microseconds
 */
uint32_t ee_bench_rsa_verify(ee_rsa_id_t  id,
                             unsigned int n,
                             unsigned int i,
                             bool         verify);

arg_claimed_t ee_bench_parse(char *p_command, bool verify);

#endif /* __EE_BENCH_H */
