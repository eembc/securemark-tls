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

#include "mbedtls/config.h"

#include "mbedtls/pk_internal.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"

#include <string.h>

//#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"

/*
 * An ASN.1 encoded signature is a sequence of two ASN.1 integers. Parse one of
 * those integers and convert it to the fixed-length encoding expected by PSA.
 */
static int extract_ecdsa_sig_int( unsigned char **from, const unsigned char *end,
                                  unsigned char *to, size_t to_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t unpadded_len, padding_len;

    if( ( ret = mbedtls_asn1_get_tag( from, end, &unpadded_len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 )
    {
        return( ret );
    }

    while( unpadded_len > 0 && **from == 0x00 )
    {
        ( *from )++;
        unpadded_len--;
    }

    if( unpadded_len > to_len || unpadded_len == 0 )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    padding_len = to_len - unpadded_len;
    memset( to, 0x00, padding_len );
    memcpy( to + padding_len, *from, unpadded_len );
    ( *from ) += unpadded_len;

    return( 0 );
}

/*
 * Convert a signature from an ASN.1 sequence of two integers
 * to a raw {r,s} buffer. Note: the provided sig buffer must be at least
 * twice as big as int_size.
 */
static int extract_ecdsa_sig( unsigned char **p, const unsigned char *end,
                              unsigned char *sig, size_t int_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t tmp_size;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &tmp_size,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    /* Extract r */
    if( ( ret = extract_ecdsa_sig_int( p, end, sig, int_size ) ) != 0 )
        return( ret );
    /* Extract s */
    if( ( ret = extract_ecdsa_sig_int( p, end, sig + int_size, int_size ) ) != 0 )
        return( ret );

    return( 0 );
}



/*
 * Simultaneously convert and move raw MPI from the beginning of a buffer
 * to an ASN.1 MPI at the end of the buffer.
 * See also mbedtls_asn1_write_mpi().
 *
 * p: pointer to the end of the output buffer
 * start: start of the output buffer, and also of the mpi to write at the end
 * n_len: length of the mpi to read from start
 */
static int asn1_write_mpibuf( unsigned char **p, unsigned char *start,
                              size_t n_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if( (size_t)( *p - start ) < n_len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = n_len;
    *p -= len;
    memmove( *p, start, len );

    /* ASN.1 DER encoding requires minimal length, so skip leading 0s.
     * Neither r nor s should be 0, but as a failsafe measure, still detect
     * that rather than overflowing the buffer in case of a PSA error. */
    while( len > 0 && **p == 0x00 )
    {
        ++(*p);
        --len;
    }

    /* this is only reached if the signature was invalid */
    if( len == 0 )
        return( MBEDTLS_ERR_PK_HW_ACCEL_FAILED );

    /* if the msb is 1, ASN.1 requires that we prepend a 0.
     * Neither r nor s can be 0, so we can assume len > 0 at all times. */
    if( **p & 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                                                MBEDTLS_ASN1_INTEGER ) );

    return( (int) len );
}

/* Transcode signature from PSA format to ASN.1 sequence.
 * See ecdsa_signature_to_asn1 in ecdsa.c, but with byte buffers instead of
 * MPIs, and in-place.
 *
 * [in/out] sig: the signature pre- and post-transcoding
 * [in/out] sig_len: signature length pre- and post-transcoding
 * [int] buf_len: the available size the in/out buffer
 */
static int pk_ecdsa_sig_asn1_from_psa( unsigned char *sig, size_t *sig_len,
                                       size_t buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const size_t rs_len = *sig_len / 2;
    unsigned char *p = sig + buf_len;

    MBEDTLS_ASN1_CHK_ADD( len, asn1_write_mpibuf( &p, sig + rs_len, rs_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, asn1_write_mpibuf( &p, sig, rs_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, sig, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, sig,
                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    memmove( sig, p, len );
    *sig_len = len;

    return( 0 );
}

struct psa_ecdsa_structure
{
    psa_key_attributes_t *attributes;  // own key attributes
    psa_key_handle_t key_handle;       // own key handle
};

typedef struct psa_ecdsa_structure psa_ecdsa_structure;

#include "ee_ecdh.h"
#include "ee_ecdsa.h" 

/**
 * Create the context passed between functions.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_create(
    void **p_context // output: portable context
)
{
    psa_ecdsa_structure *p_ecdsa;

    p_ecdsa = 
       (psa_ecdsa_structure *)th_malloc(sizeof(psa_ecdsa_structure));
    if (p_ecdsa == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create\r\n");
        return EE_STATUS_ERROR;
    }
    memset(p_ecdsa,0,sizeof(psa_ecdsa_structure));

    p_ecdsa->attributes = th_malloc(sizeof(psa_key_attributes_t));
    memset(p_ecdsa->attributes, 0, sizeof(psa_key_attributes_t));

    *p_context = (void *)p_ecdsa; 
    return EE_STATUS_OK;
}

/**
 * Initialize to a group (must be in the EE_ enum) with a predefined
 * private key.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_init(
    void            *p_context, // input: portable context
    ecdh_group_t     group,     // input: see `ecdh_group_t` for options
    uint8_t         *p_private, // input: private key from host
    uint_fast32_t    plen       // input: length of private key in bytes
)
{
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;
    psa_status_t status;

    switch (group)
    { 
        case EE_P256R1:
            psa_set_key_usage_flags( context->attributes,
                                     PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH );
            psa_set_key_algorithm( context->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256) );
            psa_set_key_type( context->attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );
            break; 
        default:
            th_printf("e-[Invalid ECC curve in th_ecdh_init]\r\n");
            return EE_STATUS_ERROR;
    }

    // Import own private key
    status = psa_import_key(context->attributes, p_private, plen, &context->key_handle );
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[psa_import_key: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Create a signature using the specified hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_sign(
    void          *p_context,   // input: portable context
    uint8_t       *p_hash,      // input: sha256 digest
    uint_fast32_t  hlen,        // input: length of digest in bytes
    uint8_t       *p_sig,       // output: signature
    uint_fast32_t *p_slen       // in/out: input=MAX slen, output=resultant
)
{
    uint_fast32_t                 slent;
    psa_status_t status;
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;
    int res;

    status = psa_sign_hash( context->key_handle,            // key handle 
                            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), // signature algorithm
                            p_hash, hlen,                   // hash of the message
                            p_sig, *p_slen,                 // signature (as output)
                            &slent );                       // length of signature output
    
	if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed to sign in th_ecdsa_sign: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    /* Encode the PSA signature output into the RFC4492 format. */
    res = pk_ecdsa_sig_asn1_from_psa( p_sig, (size_t*) &slent, (size_t) *p_slen );

    if (res != 0)
    {
        th_printf("e-[Failed to pk_ecdsa_sig_asn1_from_psa: -0x%04x]\r\n", -res);
        return EE_STATUS_ERROR;
    }

    *p_slen = (unsigned int)slent;

    return EE_STATUS_OK;
}

/**
 * Create a signature using SHA256 hash.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_ecdsa_verify(
    void          *p_context,   // input: portable context
    uint8_t       *p_hash,      // input: sha256 digest
    uint_fast32_t  hlen,        // input: length of digest in bytes
    uint8_t       *p_sig,       // input: signature
    uint_fast32_t  slen         // input: length of signature in bytes
)
{ 
    psa_status_t status;
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;
	// Buffer to store the ASN.1 representation of the signature
    uint8_t buf[30 + 2 * MBEDTLS_ECP_MAX_BYTES];
	/* Length of binary representation of r and s, respectively. 
	 * Size for P256r1 curve. 
	 */
    uint_fast32_t signature_part_size = 0x20;
    int ret;

    if( ( ret = extract_ecdsa_sig( &p_sig, p_sig + slen, // signature start and end
	                               buf,                  // output buffer
                                   signature_part_size   // length of r and s, respectively 
								 ) ) != 0 )
    {
        th_printf("e-[Failed to extract_ecdsa_sig: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    status = psa_verify_hash( context->key_handle,                           // key handle
                              PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),  // signature algorithm
                              p_hash, hlen,                                  // hash of message
                              buf, 2 * signature_part_size );                // signature
   
    if( status != PSA_SUCCESS )
    {
        th_printf("e-[Failed to verify in th_ecdsa_verify: -0x%04x]\r\n", -status);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

/**
 * Destroy the context created earlier.
 */
void
th_ecdsa_destroy(
    void *p_context // portable context
)
{ 
    psa_ecdsa_structure *context = (psa_ecdsa_structure *) p_context;

    th_free(context->attributes);

    psa_destroy_key( context->key_handle );

    th_free(p_context);
}
