/**
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

/* ASN.1 buffer writing functionality */

#include "ali_crypto.h"
#include "asn1write.h"

int asn1_write_len( unsigned char **p, unsigned char *start, size_t len )
{
    if( len < 0x80 )
    {
        if( *p - start < 1 )
            return -ALI_CRYPTO_SHORT_BUFFER;

        *--(*p) = (unsigned char) len;
        return( 1 );
    }

    if( len <= 0xFF )
    {
        if( *p - start < 2 )
            return -ALI_CRYPTO_SHORT_BUFFER;

        *--(*p) = (unsigned char) len;
        *--(*p) = 0x81;
        return( 2 );
    }

    if( len <= 0xFFFF )
    {
        if( *p - start < 3 )
            return -ALI_CRYPTO_SHORT_BUFFER;

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = 0x82;
        return( 3 );
    }

    if( len <= 0xFFFFFF )
    {
        if( *p - start < 4 )
            return -ALI_CRYPTO_SHORT_BUFFER;

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = 0x83;
        return( 4 );
    }

    if( len <= 0xFFFFFFFF )
    {
        if( *p - start < 5 )
            return -ALI_CRYPTO_SHORT_BUFFER;

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = ( len >> 24 ) & 0xFF;
        *--(*p) = 0x84;
        return( 5 );
    }

    return ALI_CRYPTO_LENGTH_ERR;
}

int asn1_write_tag( unsigned char **p, unsigned char *start, unsigned char tag )
{
    if( *p - start < 1 )
        return -ALI_CRYPTO_SHORT_BUFFER;

    *--(*p) = tag;

    return( 1 );
}

int asn1_write_int( unsigned char **p, unsigned char *start, int val )
{
    int ret;
    size_t len = 0;

    // TODO negative values and values larger than 128
    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    if( *p - start < 1 )
        return -ALI_CRYPTO_SHORT_BUFFER;

    len += 1;
    *--(*p) = val;

    if( val > 0 && **p & 0x80 )
    {
        if( *p - start < 1 )
            return -ALI_CRYPTO_SHORT_BUFFER;

        *--(*p) = 0x00;
        len += 1;
    }

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_INTEGER ) );

    return( (int) len );
}

// from asn1_write_mpi
int asn1_write_buffer( unsigned char **p, unsigned char *start, const uint8_t *x, size_t size )
{
    int ret;
    size_t len = 0;

    // Write the MPI
    len = size;

    if( *p < start || (size_t)( *p - start ) < len )
        return -ALI_CRYPTO_SHORT_BUFFER;

    (*p) -= len;
    memcpy(*p, x, len);

    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    //if( X->s ==1 && **p & 0x80 )
    // x buff only contains unsigned buffer(so alway positive)
    if (**p & 0x80)
    {
        if( *p - start < 1 )
            return -ALI_CRYPTO_SHORT_BUFFER;

        *--(*p) = 0x00;
        len += 1;
    }

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_INTEGER ) );

    ret = (int) len;

    return( ret );
}

int asn1_write_raw_buffer( unsigned char **p, unsigned char *start,
                                   const unsigned char *buf, size_t size )
{
    size_t len = 0;

    if( *p < start || (size_t)( *p - start ) < size )
        return -ALI_CRYPTO_SHORT_BUFFER;

    len = size;
    (*p) -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}

int asn1_write_null( unsigned char **p, unsigned char *start )
{
    int ret;
    size_t len = 0;

    // Write NULL
    //
    ASN1_CHK_ADD( len, asn1_write_len( p, start, 0) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_NULL ) );

    return( (int) len );
}

int asn1_write_oid( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len )
{
    int ret;
    size_t len = 0;

    ASN1_CHK_ADD( len, asn1_write_raw_buffer( p, start,
                                  (const unsigned char *) oid, oid_len ) );
    ASN1_CHK_ADD( len , asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len , asn1_write_tag( p, start, ASN1_OID ) );

    return( (int) len );
}

int asn1_write_algorithm_identifier( unsigned char **p, unsigned char *start,
                                     const char *oid, size_t oid_len,
                                     size_t par_len )
{
    int ret;
    size_t len = 0;

    if( par_len == 0 )
        ASN1_CHK_ADD( len, asn1_write_null( p, start ) );
    else
        len += par_len;

    ASN1_CHK_ADD( len, asn1_write_oid( p, start, oid, oid_len ) );

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start,
                                       ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    return( (int) len );
}