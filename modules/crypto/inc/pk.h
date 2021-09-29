/**
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

#ifndef PK_H
#define PK_H

#include "ali_crypto.h"

#define ERR_PK_ALLOC_FAILED         0x3F80  /**< Memory allocation failed. */
#define ERR_PK_TYPE_MISMATCH        0x3F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define ERR_PK_BAD_INPUT_DATA       0x3E80  /**< Bad input parameters to function. */
#define ERR_PK_FILE_IO_ERROR        0x3E00  /**< Read/write of file failed. */
#define ERR_PK_KEY_INVALID_VERSION  0x3D80  /**< Unsupported key version */
#define ERR_PK_KEY_INVALID_FORMAT   0x3D00  /**< Invalid key tag or value. */
#define ERR_PK_UNKNOWN_PK_ALG       0x3C80  /**< Key algorithm is unsupported (only RSA and EC are supported). */
#define ERR_PK_PASSWORD_REQUIRED    0x3C00  /**< Private key password can't be empty. */
#define ERR_PK_PASSWORD_MISMATCH    0x3B80  /**< Given private key password does not allow for correct decryption. */
#define ERR_PK_INVALID_PUBKEY       0x3B00  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
#define ERR_PK_INVALID_ALG          0x3A80  /**< The algorithm tag or value is invalid. */
#define ERR_PK_UNKNOWN_NAMED_CURVE  0x3A00  /**< Elliptic curve is unsupported (only NIST curves are supported). */
#define ERR_PK_FEATURE_UNAVAILABLE  0x3980  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
#define ERR_PK_SIG_LEN_MISMATCH     0x3900  /**< The signature is valid but its length is less than expected. */

/**
 * \brief          Public key types
 */
typedef enum {
    PK_NONE=0,
    PK_RSA,
    PK_ECKEY,
    PK_ECKEY_DH,
    PK_ECDSA,
    PK_RSA_ALT,
    PK_RSASSA_PSS,
} pk_type_t;

/**
 * \brief           Public key information and operations
 */
typedef struct pk_info_t pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct
{
    const pk_info_t *   pk_info; /**< Public key informations        */
    void *              pk_ctx;  /**< Underlying public key context  */
} pk_context;

/**
 * \brief           Parse a SubjectPublicKeyInfo DER structure
 *
 * \param p         the position in the ASN.1 data
 * \param end       end of the buffer
 * \param key       the key to fill
 *
 * \return          0 if successful, or a specific PK error code
 */
int pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        icrypt_key_data_t *key );


#endif // PK_H
