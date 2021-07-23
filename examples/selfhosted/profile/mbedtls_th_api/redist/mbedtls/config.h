#ifndef __CONFIG_H
#define __CONFIG_H

#define MBEDTLS_SHA256_C
#define MBEDTLS_AES_C
#define MBEDTLS_CCM_C
#define MBEDTLS_CIPHER_C

#define MBEDTLS_ECDH_C 
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDSA_C 
#define MBEDTLS_ECP_C 
#define MBEDTLS_ASN1_WRITE_C 
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C


#define MBEDTLS_ECDSA_SECP256r1_SHA256 
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C

/* ECP options */
#define MBEDTLS_ECP_WINDOW_SIZE            7 /**< Maximum window size used */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM      1 /**< Enable fixed-point speed-up */

/* MPI / BIGNUM options */
#define MBEDTLS_MPI_WINDOW_SIZE            6 /**< Maximum windows size used. */
#define MBEDTLS_MPI_MAX_SIZE            1024 /**< Maximum number of bytes for usable MPIs. */

#endif
