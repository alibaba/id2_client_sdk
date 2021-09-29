/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 */

#ifndef _ALI_CRYPTO_TYPES_H_
#define _ALI_CRYPTO_TYPES_H_

#include <stdint.h>
#include <stddef.h> /* for size_t */
#include <stdbool.h>
#include "ls_osa.h"

#ifndef false
#define false   (0)
#endif

#ifndef true
#define true    (1)
#endif

#ifndef NULL
#define NULL    ((void *)0)
#endif

#define UNUSED(expr) do { (void)(expr); } while (0)

typedef enum _ali_crypto_result {
    ALI_CRYPTO_ERROR = (int)0xffff0000, /* Generic Error */
    ALI_CRYPTO_NOSUPPORT,               /* Scheme not support */
    ALI_CRYPTO_INVALID_KEY,             /* Invalid Key in asymmetric scheme: RSA/DSA/ECCP/DH etc */
    ALI_CRYPTO_INVALID_TYPE,            /* Invalid aes_type/des_type/authenc_type/hash_type/cbcmac_type/cmac_type */
    ALI_CRYPTO_INVALID_CONTEXT,         /* Invalid context in multi-thread cipher/authenc/mac/hash etc */
    ALI_CRYPTO_INVALID_PADDING,         /* Invalid sym_padding/rsassa_padding/rsaes_padding */
    ALI_CRYPTO_INVALID_AUTHENTICATION,  /* Invalid authentication in AuthEnc(AES-CCM/AES-GCM)/asymmetric verify(RSA/DSA/ECCP DSA) */
    ALI_CRYPTO_INVALID_ARG,             /* Invalid arguments */
    ALI_CRYPTO_INVALID_PACKET,          /* Invalid packet in asymmetric enc/dec(RSA) */
    ALI_CRYPTO_LENGTH_ERR,              /* Invalid Length in arguments */
    ALI_CRYPTO_OUTOFMEM,                /* Memory alloc NULL */
    ALI_CRYPTO_SHORT_BUFFER,            /* Output buffer is too short to store result */
    ALI_CRYPTO_NULL,                    /* NULL pointer in arguments */
    ALI_CRYPTO_ERR_STATE,               /* Bad state in mulit-thread cipher/authenc/mac/hash etc */
    ALI_CRYPTO_SUCCESS = 0,             /* Success */
} ali_crypto_result;

#define AES_BLOCK_SIZE       16   /* don't change this value,since AES only support 16 byte block size */
#define AES_IV_SIZE          16
#define SM4_BLOCK_SIZE       16
#define SM4_IV_SIZE          16
#define DES_BLOCK_SIZE       8
#define DES_IV_SIZE          8

/* hash constants */
#define MAX_HASH_SIZE        64  /* longest known is SHA512 */

/* RSA constants */
#define ALI_CRYPTO_RSA_PUBLIC           0
#define ALI_CRYPTO_RSA_PRIVATE          1

#define ALI_CRYPTO_RSA_PKCS_V15         0
#define ALI_CRYPTO_RSA_PKCS_V21         1

#define ALI_CRYPTO_RSA_SIGN             1
#define ALI_CRYPTO_RSA_CRYPT            2
#define ALI_CRYPTO_RSA_SALT_LEN_ANY    -1

/**
 * API AES defines
 **/
typedef enum _sym_padding_t {
    SYM_NOPAD       = 0,
    SYM_PKCS5_PAD   = 1,
    SYM_ZERO_PAD    = 2,
} sym_padding_t;

typedef enum _aes_type_t {
    AES_ECB         = 0,
    AES_CBC         = 1,
    AES_CTR         = 2,
    AES_CTS         = 3,
    AES_XTS         = 4,
    AES_CFB8        = 5,
    AES_CFB128      = 6,
} aes_type_t;

typedef struct _api_aes_ctx_t {
    aes_type_t type;
    bool       is_enc;
    uint32_t   hal_size;
    void *     hal_ctx;
} api_aes_ctx_t;

/**
 * API SM4 defines
 **/

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

typedef enum _sm4_type_t {
    SM4_ECB     = 0,
    SM4_CBC     = 1,
    SM4_CTR     = 2,
} sm4_type_t;

typedef struct _api_sm4_ctx_t {
    sm4_type_t type;
    bool       is_enc;
    uint32_t   hal_size;
    void *     hal_ctx;
} api_sm4_ctx_t;

typedef enum _des_type_t {
    DES_ECB     = 0,
    DES_CBC     = 1,
    DES3_ECB    = 2,
    DES3_CBC    = 3,
} des_type_t;

/**
 * API HASH defines
 **/
typedef enum _hash_type_t {
    HASH_NONE   = 0,
    SHA1        = 1,
    SHA224      = 2,
    SHA256      = 3,
    SHA384      = 4,
    SHA512      = 5,
    MD5         = 6,
    SM3         = 7,
} hash_type_t;

typedef struct {
    hash_type_t type;
    uint32_t hal_size;
    void * hal_ctx;
} api_hash_ctx_t;

enum {
    MD5_HASH_SIZE       = 16,
    SHA1_HASH_SIZE      = 20,
    SHA224_HASH_SIZE    = 28,
    SHA256_HASH_SIZE    = 32,
    SM3_HASH_SIZE       = 32,
    SHA384_HASH_SIZE    = 48,
    SHA512_HASH_SIZE    = 64,
};

/**
 * API RSA defines
 **/
typedef struct {
    size_t          type;
    uint8_t         opad[64];
    size_t          opad_size;
    api_hash_ctx_t  hash_ctx;
} api_hmac_ctx_t;

#define MAX_BLOCK_SIZE 64

/**
 * API RSA defines
 **/
typedef struct _api_rsa_ctx_t {
    uint32_t keybytes;
    void *   hal_ctx;
} api_rsa_ctx_t;

typedef enum _rsa_key_attr_t {
    RSA_MODULUS          = 0x130,
    RSA_PUBLIC_EXPONENT  = 0x230,
    RSA_PRIVATE_EXPONENT = 0x330,
    RSA_PRIME1           = 0x430,
    RSA_PRIME2           = 0x530,
    RSA_EXPONENT1        = 0x630,
    RSA_EXPONENT2        = 0x730,
    RSA_COEFFICIENT      = 0x830,
} rsa_key_attr_t;

typedef enum _rsa_pad_type_t {
    RSA_NOPAD               = 0,

    /* encrypt */
    RSAES_PKCS1_V1_5        = 10,
    RSAES_PKCS1_OAEP_MGF1   = 11,

    /* sign */
    RSASSA_PKCS1_V1_5       = 20,
    RSASSA_PKCS1_PSS_MGF1   = 21,
} rsa_pad_type_t;

enum {
    CRYPTO_STATUS_CLEAN        = 0,
    CRYPTO_STATUS_INITIALIZED  = 1,
    CRYPTO_STATUS_PROCESSING   = 2,
    CRYPTO_STATUS_FINISHED     = 3,
};

typedef struct _rsa_padding_t {
    rsa_pad_type_t type;
    union {
        struct {
            hash_type_t type;
        } rsaes_oaep;
        struct {
            hash_type_t type;   /* md5/sha1/sha224/sha256/sha384/sha512 */
        } rsassa_v1_5;
        struct {
            hash_type_t type;   /* sha1/sha224/sha256/sha384/sha512 */
            size_t salt_len;
        } rsassa_pss;
    } pad;
} rsa_padding_t;

/**
 * \brief          RSA keypair structure
 */
typedef struct _rsa_key_t {
    size_t   key_bytes;
    uint8_t  *n;
    size_t   n_size;
    uint8_t  *e;
    size_t   e_size;
    uint8_t  *d;
    size_t   d_size;
    uint8_t  *p;
    size_t   p_size;
    uint8_t  *q;
    size_t   q_size;
    uint8_t  *dp;
    size_t   dp_size;
    uint8_t  *dq;
    size_t   dq_size;
    uint8_t  *qp;
    size_t   qp_size;
} rsa_key_t;

typedef enum {
    ECP_DP_NONE = 0,
    ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    ECP_DP_CURVE25519,     /*!< Curve25519 */
    ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
    ECP_DP_SMP256R1,       /*!< 256-bits SM2 curve */
    ECP_DP_SMP256R2,       /*!< 256-bits SM2 test curve */
} ecp_curve_id_t;

/**
 * \brief          SM2 keypair structure
 */
typedef struct _ecc_keypair_t {
    ecp_curve_id_t curve;   /* elliptic curve name*/
    uint8_t *x;      /* x coordinate of pub key */
    size_t  x_size;
    uint8_t *y;      /* y coordinate of pub key */
    size_t  y_size;
    uint8_t *d;      /* secret value */
    size_t  d_size;
} ecc_key_t;

typedef struct _icrypt_key_data_t {
    uint8_t key_type;
    union {
        rsa_key_t rsa_key;
        ecc_key_t ecc_key;
    };
} icrypt_key_data_t;

#endif /* _ALI_CRYPTO_TYPES_H_ */
