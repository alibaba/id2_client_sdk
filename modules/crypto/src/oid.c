/**
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

#include "oid.h"

/*
 * Macro to automatically add the size of #define'd OIDs
 */
#define ADD_LEN(s)      s, OID_SIZE(s)

/*
 * Macro to generate an internal function for oid_XXX_from_asn1() (used by
 * the other functions)
 */
#define FN_OID_TYPED_FROM_ASN1( TYPE_T, NAME, LIST )                        \
static const TYPE_T * oid_ ## NAME ## _from_asn1( const asn1_buf *oid )     \
{                                                                           \
    const TYPE_T *p = LIST;                                                 \
    const oid_descriptor_t *cur = (const oid_descriptor_t *) p;             \
    if( p == NULL || oid == NULL ) return( NULL );                          \
    while( cur->asn1 != NULL ) {                                            \
        if( cur->asn1_len == oid->len &&                                    \
            memcmp( cur->asn1, oid->p, oid->len ) == 0 ) {                  \
            return( p );                                                    \
        }                                                                   \
        p++;                                                                \
        cur = (const oid_descriptor_t *) p;                                 \
    }                                                                       \
    return( NULL );                                                         \
}

/*
 * Macro to generate a function for retrieving a single attribute from an
 * oid_descriptor_t wrapper.
 */
#define FN_OID_GET_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( ERR_OID_NOT_FOUND );            \
    *ATTR1 = data->ATTR1;                                               \
    return( 0 );                                                        \
}

/*
 * Macro to generate a function for retrieving the OID based on a single
 * attribute from a mbedtls_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_OID_BY_ATTR1(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1)   \
int FN_NAME( ATTR1_TYPE ATTR1, const char **oid, size_t *olen )             \
{                                                                           \
    const TYPE_T *cur = LIST;                                               \
    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == ATTR1 ) {                                         \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
        }                                                                   \
        cur++;                                                              \
    }                                                                       \
    return( ERR_OID_NOT_FOUND );                                   \
}

/*
 * For PublicKeyInfo (PKCS1, RFC 5480)
 */
typedef struct {
    oid_descriptor_t    descriptor;
    pk_type_t           pk_alg;
} oid_pk_alg_t;

static const oid_pk_alg_t oid_pk_alg[] =
{
    {
        { ADD_LEN( OID_PKCS1_RSA ),      "rsaEncryption",   "RSA" },
        PK_RSA,
    },
    {
        { ADD_LEN( OID_EC_ALG_UNRESTRICTED ),  "id-ecPublicKey",   "Generic EC key" },
        PK_ECKEY,
    },
    {
        { NULL, 0, NULL, NULL },
        PK_NONE,
    },
};

FN_OID_TYPED_FROM_ASN1(oid_pk_alg_t, pk_alg, oid_pk_alg)
FN_OID_GET_ATTR1(oid_get_pk_alg, oid_pk_alg_t, pk_alg, pk_type_t, pk_alg)

/*
 * For namedCurve (RFC 5480)
 */
typedef struct {
    oid_descriptor_t    descriptor;
    ecp_curve_id_t      grp_id;
} oid_ecp_grp_t;

static const oid_ecp_grp_t oid_ecp_grp[] =
{
#if defined(ECP_DP_SMP256R1_ENABLED)
    {
        { ADD_LEN( OID_EC_GRP_SMP265R1 ),   "smp256r1","smp256r1" },
        ECP_DP_SMP256R1,
    },
#endif // IMPL_ECP_DP_SMP256R1_ENABLED
};

FN_OID_TYPED_FROM_ASN1(oid_ecp_grp_t, grp_id, oid_ecp_grp)
FN_OID_GET_ATTR1(oid_get_ec_grp, oid_ecp_grp_t, grp_id, ecp_curve_id_t, grp_id)
FN_OID_GET_OID_BY_ATTR1(oid_get_oid_by_ec_grp, oid_ecp_grp_t, oid_ecp_grp, ecp_curve_id_t, grp_id)


/*
 * For digestAlgorithm
 */
typedef struct {
    oid_descriptor_t    descriptor;
    hash_type_t         md_alg;
} oid_md_alg_t;

static const oid_md_alg_t oid_md_alg[] =
{
    {
        { ADD_LEN( OID_DIGEST_ALG_MD5 ),       "id-md5",       "MD5" },
        MD5,
    },
    {
        { ADD_LEN( OID_DIGEST_ALG_SHA1 ),      "id-sha1",      "SHA-1" },
        SHA1,
    },
    {
        { ADD_LEN( OID_DIGEST_ALG_SHA224 ),    "id-sha224",    "SHA-224" },
        SHA224,
    },
    {
        { ADD_LEN( OID_DIGEST_ALG_SHA256 ),    "id-sha256",    "SHA-256" },
        SHA256,
    },
    {
        { ADD_LEN( OID_DIGEST_ALG_SHA384 ),    "id-sha384",    "SHA-384" },
        SHA384,
    },
    {
        { ADD_LEN( OID_DIGEST_ALG_SHA512 ),    "id-sha512",    "SHA-512" },
        SHA512,
    },
    {
        { NULL, 0, NULL, NULL },
        HASH_NONE,
    },
};

FN_OID_TYPED_FROM_ASN1(oid_md_alg_t, md_alg, oid_md_alg)
FN_OID_GET_ATTR1(oid_get_md_alg, oid_md_alg_t, md_alg, hash_type_t, md_alg)
FN_OID_GET_OID_BY_ATTR1(oid_get_oid_by_md, oid_md_alg_t, oid_md_alg, hash_type_t, md_alg)