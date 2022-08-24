/**
* Copyright (C) 2017  Alibaba Group Holding Limited.
**/

#ifndef ALI_ALGO_ASN1_H
#define ALI_ALGO_ASN1_H

#include <stddef.h>

#if defined(ALI_ALGO_BIGNUM_C)
#include "bignum.h"
#endif

/**
 * \addtogroup asn1_module
 * \{
 */

/**
 * \name ASN1 Error codes
 * These error codes are OR'ed to X509 error codes for
 * higher error granularity.
 * ASN1 is a standard to specify data structures.
 * \{
 */
#define ALI_ALGO_ERR_ASN1_OUT_OF_DATA                      -0x0060  /**< Out of data when parsing an ASN1 data structure. */
#define ALI_ALGO_ERR_ASN1_UNEXPECTED_TAG                   -0x0062  /**< ASN1 tag was of an unexpected value. */
#define ALI_ALGO_ERR_ASN1_INVALID_LENGTH                   -0x0064  /**< Error when trying to determine the length or invalid length. */
#define ALI_ALGO_ERR_ASN1_LENGTH_MISMATCH                  -0x0066  /**< Actual length differs from expected length. */
#define ALI_ALGO_ERR_ASN1_INVALID_DATA                     -0x0068  /**< Data is invalid. (not used) */
#define ALI_ALGO_ERR_ASN1_ALLOC_FAILED                     -0x006A  /**< Memory allocation failed */
#define ALI_ALGO_ERR_ASN1_BUF_TOO_SMALL                    -0x006C  /**< Buffer too small when writing ASN.1 data structure. */

/* \} name */

/**
 * \name DER constants
 * These constants comply with DER encoded the ANS1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::ali_algo_x509_buf.
 * \{
 */
#define ALI_ALGO_ASN1_BOOLEAN                 0x01
#define ALI_ALGO_ASN1_INTEGER                 0x02
#define ALI_ALGO_ASN1_BIT_STRING              0x03
#define ALI_ALGO_ASN1_OCTET_STRING            0x04
#define ALI_ALGO_ASN1_NULL                    0x05
#define ALI_ALGO_ASN1_OID                     0x06
#define ALI_ALGO_ASN1_UTF8_STRING             0x0C
#define ALI_ALGO_ASN1_SEQUENCE                0x10
#define ALI_ALGO_ASN1_SET                     0x11
#define ALI_ALGO_ASN1_PRINTABLE_STRING        0x13
#define ALI_ALGO_ASN1_T61_STRING              0x14
#define ALI_ALGO_ASN1_IA5_STRING              0x16
#define ALI_ALGO_ASN1_UTC_TIME                0x17
#define ALI_ALGO_ASN1_GENERALIZED_TIME        0x18
#define ALI_ALGO_ASN1_UNIVERSAL_STRING        0x1C
#define ALI_ALGO_ASN1_BMP_STRING              0x1E
#define ALI_ALGO_ASN1_PRIMITIVE               0x00
#define ALI_ALGO_ASN1_CONSTRUCTED             0x20
#define ALI_ALGO_ASN1_CONTEXT_SPECIFIC        0x80
/* \} name */
/* \} addtogroup asn1_module */

/** Returns the size of the binary string, without the trailing \\0 */
#define ALI_ALGO_OID_SIZE(x) (sizeof(x) - 1)

/**
 * Compares an ali_algo_asn1_buf structure to a reference OID.
 *
 * Only works for 'defined' oid_str values (ALI_ALGO_OID_HMAC_SHA1), you cannot use a
 * 'unsigned char *oid' here!
 */
#define ALI_ALGO_OID_CMP(oid_str, oid_buf)                                   \
        ( ( ALI_ALGO_OID_SIZE(oid_str) != (oid_buf)->len ) ||                \
          memcmp( (oid_str), (oid_buf)->p, (oid_buf)->len) != 0 )

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name Functions to parse ASN.1 data structures
 * \{
 */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef struct ali_algo_asn1_buf
{
    int tag;                /**< ASN1 type, e.g. ALI_ALGO_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
}
ali_algo_asn1_buf;

/**
 * Container for ASN1 bit strings.
 */
typedef struct ali_algo_asn1_bitstring
{
    size_t len;                 /**< ASN1 length, in octets. */
    unsigned char unused_bits;  /**< Number of unused bits at the end of the string */
    unsigned char *p;           /**< Raw ASN1 data for the bit string */
}
ali_algo_asn1_bitstring;

/**
 * Container for a sequence of ASN.1 items
 */
typedef struct ali_algo_asn1_sequence
{
    ali_algo_asn1_buf buf;                   /**< Buffer containing the given ASN.1 item. */
    struct ali_algo_asn1_sequence *next;    /**< The next entry in the sequence. */
}
ali_algo_asn1_sequence;

/**
 * Container for a sequence or list of 'named' ASN.1 data items
 */
typedef struct ali_algo_asn1_named_data
{
    ali_algo_asn1_buf oid;                   /**< The object identifier. */
    ali_algo_asn1_buf val;                   /**< The named value. */
    struct ali_algo_asn1_named_data *next;  /**< The next entry in the sequence. */
    unsigned char next_merged;      /**< Merge next item into the current one? */
}
ali_algo_asn1_named_data;

/**
 * \brief       Get the length of an ASN.1 element.
 *              Updates the pointer to immediately behind the length.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param len   The variable that will receive the value
 *
 * \return      0 if successful, ALI_ALGO_ERR_ASN1_OUT_OF_DATA on reaching
 *              end of data, ALI_ALGO_ERR_ASN1_INVALID_LENGTH if length is
 *              unparseable.
 */
int ali_algo_asn1_get_len( unsigned char **p,
                  const unsigned char *end,
                  size_t *len );

/**
 * \brief       Get the tag and length of the tag. Check for the requested tag.
 *              Updates the pointer to immediately behind the tag and length.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param len   The variable that will receive the length
 * \param tag   The expected tag
 *
 * \return      0 if successful, ALI_ALGO_ERR_ASN1_UNEXPECTED_TAG if tag did
 *              not match requested tag, or another specific ASN.1 error code.
 */
int ali_algo_asn1_get_tag( unsigned char **p,
                  const unsigned char *end,
                  size_t *len, int tag );

/**
 * \brief       Retrieve a boolean ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param val   The variable that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
int ali_algo_asn1_get_bool( unsigned char **p,
                   const unsigned char *end,
                   int *val );

/**
 * \brief       Retrieve an integer ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param val   The variable that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
int ali_algo_asn1_get_int( unsigned char **p,
                  const unsigned char *end,
                  int *val );

/**
 * \brief       Retrieve a bitstring ASN.1 tag and its value.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param bs    The variable that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
int ali_algo_asn1_get_bitstring( unsigned char **p, const unsigned char *end,
                        ali_algo_asn1_bitstring *bs);

/**
 * \brief       Retrieve a bitstring ASN.1 tag without unused bits and its
 *              value.
 *              Updates the pointer to the beginning of the bit/octet string.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param len   Length of the actual bit/octect string in bytes
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
int ali_algo_asn1_get_bitstring_null( unsigned char **p, const unsigned char *end,
                             size_t *len );

/**
 * \brief       Parses and splits an ASN.1 "SEQUENCE OF <tag>"
 *              Updated the pointer to immediately behind the full sequence tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param cur   First variable in the chain to fill
 * \param tag   Type of sequence
 *
 * \return      0 if successful or a specific ASN.1 error code.
 */
int ali_algo_asn1_get_sequence_of( unsigned char **p,
                          const unsigned char *end,
                          ali_algo_asn1_sequence *cur,
                          int tag);

#if defined(ALI_ALGO_BIGNUM_C)
/**
 * \brief       Retrieve a MPI value from an integer ASN.1 tag.
 *              Updates the pointer to immediately behind the full tag.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param X     The MPI that will receive the value
 *
 * \return      0 if successful or a specific ASN.1 or MPI error code.
 */
int ali_algo_asn1_get_mpi( unsigned char **p,
                  const unsigned char *end,
                  ali_algo_mpi *X );
#endif /* ALI_ALGO_BIGNUM_C */

/**
 * \brief       Retrieve an AlgorithmIdentifier ASN.1 sequence.
 *              Updates the pointer to immediately behind the full
 *              AlgorithmIdentifier.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param alg   The buffer to receive the OID
 * \param params The buffer to receive the params (if any)
 *
 * \return      0 if successful or a specific ASN.1 or MPI error code.
 */
int ali_algo_asn1_get_alg( unsigned char **p,
                  const unsigned char *end,
                  ali_algo_asn1_buf *alg, ali_algo_asn1_buf *params );

/**
 * \brief       Retrieve an AlgorithmIdentifier ASN.1 sequence with NULL or no
 *              params.
 *              Updates the pointer to immediately behind the full
 *              AlgorithmIdentifier.
 *
 * \param p     The position in the ASN.1 data
 * \param end   End of data
 * \param alg   The buffer to receive the OID
 *
 * \return      0 if successful or a specific ASN.1 or MPI error code.
 */
int ali_algo_asn1_get_alg_null( unsigned char **p,
                       const unsigned char *end,
                       ali_algo_asn1_buf *alg );

/**
 * \brief       Find a specific named_data entry in a sequence or list based on
 *              the OID.
 *
 * \param list  The list to seek through
 * \param oid   The OID to look for
 * \param len   Size of the OID
 *
 * \return      NULL if not found, or a pointer to the existing entry.
 */
ali_algo_asn1_named_data *ali_algo_asn1_find_named_data( ali_algo_asn1_named_data *list,
                                       const char *oid, size_t len );

/**
 * \brief       Free a ali_algo_asn1_named_data entry
 *
 * \param entry The named data entry to free
 */
void ali_algo_asn1_free_named_data( ali_algo_asn1_named_data *entry );

/**
 * \brief       Free all entries in a ali_algo_asn1_named_data list
 *              Head will be set to NULL
 *
 * \param head  Pointer to the head of the list of named data entries to free
 */
void ali_algo_asn1_free_named_data_list( ali_algo_asn1_named_data **head );

#ifdef __cplusplus
}
#endif

#endif /* asn1.h */
