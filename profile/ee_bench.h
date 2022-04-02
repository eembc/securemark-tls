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
 */
void ee_bench_sha(ee_sha_size_t size,
                  uint_fast32_t n,
                  uint_fast32_t i,
                  bool          verify);

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
 */
void ee_bench_aes(ee_aes_mode_t mode,
                  ee_aes_func_t func,
                  uint_fast32_t keylen,
                  uint_fast32_t n,
                  uint_fast32_t i,
                  bool          verify);

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
 */
void ee_bench_chachapoly(ee_chachapoly_func_t func, int n, int i, bool verify);

/**
 * @brief The top-level ECDH benchmark wrapper.
 *
 * The caller must populate `th_buffer` with the first two items.
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Public peer key (see below for format)
 * " + publen   Private key (see below for format)
 *
 * For SECP/NIST curves 256r1 and 384r1, the public key is uncompressed X, Y
 * coordinates, 256 or 384 bits; same for private key `d`. For X25519, both
 * are 256 bits.
 *
 * @param g - The group enum indicating the curve
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 */
void ee_bench_ecdh(ee_ecdh_group_t g, uint_fast32_t i, bool verify);

/**
 * @brief The top-level ECDSA/EdDSA benchmark wrapper.
 *
 * The caller must populate `th_buffer` with the first two items if sign, or
 * all three if verify.
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Private key (see below for format)
 * " + prilen   Message to sign or verify
 * " + n        Signature (input or output; see below for format)
 *
 * Since this function does deterministic EcDSA and Ed25519, the key length
 * is known from the lookup table in `ecdh.h` (ee_pri_sz[]).
 *
 * The private key is always given, regardless of sign or verify. If the target
 * requires a public key to do verify, then it should be constructed during
 * the context create and init. The format is the same as in `ee_bench_ecdh()`.
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * @param g - The group enum indicating the curve, or Ed25519 (see the enum)
 * @param func - The enum indicating the function
 * @param n - The length of the message to sign
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 */
void ee_bench_ecdsa(ee_ecdh_group_t g,
                    ee_ecdsa_func_t func,
                    uint_fast32_t   n,
                    uint_fast32_t   i,
                    bool            verify);

/**
 * @brief The top-level RSA benchmark wrapper.
 *
 * The caller must populate `th_buffer` with the 5 values for sign, and all
 * 7 for verify.
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Private key length (uint32)
 * " + 4        Presented as ASN.1 private key (RFC 8017 A.1.2)
 * " + prilen   Message length (uint32)
 * " + 4        Message octets
 * " + msglen   Signature length (uint32)
 * " + 4        Signature octets
 *
 * The message is the non-encoded encryption of message M according to PCKS1v15.
 * Meaning, the hash will not be encoded, it will simply be padded and
 * encrypted, and the expected signature for verification will follow the
 * same convention.
 *
 * The private key is always given, regardless of sign or verify. If the target
 * requires a public key to do verify, then it should be constructed during
 * the context create and init, as the specified ASN.1 format contains enough
 * information to reconstruct the public key.
 *
 * Note that this function only verifies that the RSA operation succeeded,
 * in the case of verify, the decrypted bytes are NOT compared to the message.
 *
 * @param id - The RSA enum indicating the modulus
 * @param func - The enum indicating the function
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 */
void ee_bench_rsa(ee_rsa_id_t       id,
                  ee_rsa_function_t func,
                  unsigned int      i,
                  bool              verify);

arg_claimed_t ee_bench_parse(char *p_command, bool verify);

#endif /* __EE_BENCH_H */
