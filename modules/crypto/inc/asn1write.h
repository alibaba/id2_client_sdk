/**
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

#ifndef ASN1_WRITE_H
#define ASN1_WRITE_H

//#include "asn1.h"

/**
 * \name DER constants
 * These constants comply with DER encoded the ANS1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::x509_buf.
 * \{
 */
#define ASN1_BOOLEAN                 0x01
#define ASN1_INTEGER                 0x02
#define ASN1_BIT_STRING              0x03
#define ASN1_OCTET_STRING            0x04
#define ASN1_NULL                    0x05
#define ASN1_OID                     0x06
#define ASN1_UTF8_STRING             0x0C
#define ASN1_SEQUENCE                0x10
#define ASN1_SET                     0x11
#define ASN1_PRINTABLE_STRING        0x13
#define ASN1_T61_STRING              0x14
#define ASN1_IA5_STRING              0x16
#define ASN1_UTC_TIME                0x17
#define ASN1_GENERALIZED_TIME        0x18
#define ASN1_UNIVERSAL_STRING        0x1C
#define ASN1_BMP_STRING              0x1E
#define ASN1_PRIMITIVE               0x00
#define ASN1_CONSTRUCTED             0x20
#define ASN1_CONTEXT_SPECIFIC        0x80

#define ASN1_CHK_ADD_CLEAN(g, f) do { if( ( ret = f ) < 0 ) goto cleanup; else   \
                                      g += ret; } while( 0 )

#define ASN1_CHK_ADD(g, f) do { if( ( ret = f ) < 0 ) return( ret ); else   \
                                g += ret; } while( 0 )

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Write a length field in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param len       the length to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_len( unsigned char **p, unsigned char *start, size_t len );

/**
 * \brief           Write a ASN.1 tag in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param tag       the tag to write
 *
 * \return          the length written or a negative error code
 */
int asn1_write_tag( unsigned char **p, unsigned char *start,
                    unsigned char tag );

/**
 * \brief           Write raw buffer data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param buf       data buffer to write
 * \param size      length of the data buffer
 *
 * \return          the length written or a negative error code
 */
int asn1_write_raw_buffer( unsigned char **p, unsigned char *start,
                           const unsigned char *buf, size_t size );

/**
 * \brief           Write a big number (ASN1_INTEGER) in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param x         the key content buffer
 * \param size      the key content buffer size
 *
 * \return          the length written or a negative error code
 */
int asn1_write_buffer( unsigned char **p, unsigned char *start, const uint8_t *x, size_t size );

/**
 * \brief           Write a NULL tag (ASN1_NULL) with zero data in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 *
 * \return          the length written or a negative error code
 */
int asn1_write_null( unsigned char **p, unsigned char *start );

/**
 * \brief           Write an OID tag (ASN1_OID) and data in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param oid       the OID to write
 * \param oid_len   length of the OID
 *
 * \return          the length written or a negative error code
 */
int asn1_write_oid( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len );

/**
 * \brief           Write an AlgorithmIdentifier sequence in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param oid       the OID of the algorithm
 * \param oid_len   length of the OID
 * \param par_len   length of parameters, which must be already written.
 *                  If 0, NULL parameters are added
 *
 * \return          the length written or a negative error code
 */
int asn1_write_algorithm_identifier( unsigned char **p, unsigned char *start,
                                     const char *oid, size_t oid_len,
                                     size_t par_len );

/**
 * \brief           Write a boolean tag (ASN1_BOOLEAN) and value in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param boolean   0 or 1
 *
 * \return          the length written or a negative error code
 */
int asn1_write_bool( unsigned char **p, unsigned char *start, int boolean );

/**
 * \brief           Write an int tag (ASN1_INTEGER) and value in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param val       the integer value
 *
 * \return          the length written or a negative error code
 */
int asn1_write_int( unsigned char **p, unsigned char *start, int val );

#ifdef __cplusplus
}
#endif

#endif /* ASN1_WRITE_H */
