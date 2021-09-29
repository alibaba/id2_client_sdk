/**
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

/* Public Key layer for parsing key files and structures */

#include "asn1.h"
#include "pk.h"
#include "oid.h"
#include "ecp.h"

/*
 * EC public key is an EC point
 *
 * The caller is responsible for clearing the structure upon failure if
 * desired. Take care to pass along the possible ECP_FEATURE_UNAVAILABLE
 * return code of mbedtls_ecp_point_read_binary() and leave p in a usable state.
 */
static int pk_get_ecpubkey( unsigned char **p, const unsigned char *end,
                            ecc_key_t *key )
{
    size_t plen = 0;

    // Only support SM2 Curve now
    if (key->curve == ECP_DP_SMP256R1) {
        // refer to ecp_curves defines
        plen = 32;
    } else {
        ls_osa_print("err: only support sm2 pubkey now!\n");
        return ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if (*p[0] != 0x04) {
        return ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if ( (end - *p) != 2 * plen + 1 ) {
        return ERR_ECP_BAD_INPUT_DATA;
    }

    // init x
    key->x_size = plen;
    key->x = (uint8_t *)ls_osa_malloc(plen);
    memcpy(key->x, *p + 1, plen);
    // init y
    key->y_size = plen;
    key->y = (uint8_t *)ls_osa_malloc(plen);
    memcpy(key->y, *p + 1 + plen, plen);
    // inid d
    key->d = NULL;
    key->d_size = 0;

    /*
     * We know mbedtls_ecp_point_read_binary consumed all bytes or failed
     */
    *p = (unsigned char *) end;

    return 0;
}

/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_get_rsapubkey( unsigned char **p,
                             const unsigned char *end,
                             rsa_key_t *rsa )
{
    int ret;
    size_t len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( ERR_PK_INVALID_PUBKEY +
                ERR_ASN1_LENGTH_MISMATCH );

    // extract n
    ret = asn1_get_tag( p, end, &len, ASN1_INTEGER );
    // Note: if the 1st byte is 0(used to indicate bignum is positive)
    //       do not put it in rsa->n
    while (*p[0] == 0) {
        len -= 1;
        *p += 1;
    }
    // init key_bytes
    rsa->key_bytes = len;
    rsa->n_size = len;
    rsa->n = ls_osa_malloc(len);
    memcpy(rsa->n, *p, rsa->n_size);
    *p += len;

    // extract e
    ret = asn1_get_tag( p, end, &len, ASN1_INTEGER );

    // remove the leading zeros
    while ((*p)[0] == 0) {
        len -= 1;
        *p += 1;
    }
    rsa->e_size = len;
    rsa->e = ls_osa_malloc(len);
    memcpy(rsa->e, *p, rsa->e_size);
    *p += len;

    // init d
    rsa->d = NULL;
    rsa->d_size = 0;

    if( *p != end )
        return( ERR_PK_INVALID_PUBKEY +
                ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg( unsigned char **p,
                          const unsigned char *end,
                          pk_type_t *pk_alg, asn1_buf *params )
{
    int ret;
    asn1_buf alg_oid;

    memset( params, 0, sizeof(asn1_buf) );

    if( ( ret = asn1_get_alg( p, end, &alg_oid, params ) ) != 0 )
        return( ERR_PK_INVALID_ALG + ret );
    if( oid_get_pk_alg( &alg_oid, pk_alg ) != 0 )
        return( ERR_PK_UNKNOWN_PK_ALG );

    /*
     * No parameters with RSA (only for EC)
     */
    if( *pk_alg == PK_RSA &&
            ( ( params->tag != ASN1_NULL && params->tag != 0 ) ||
                params->len != 0 ) )
    {
        return( ERR_PK_INVALID_ALG );
    }

    return( 0 );
}

/*
 * Use EC parameters to initialise an EC group
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 */
static int pk_use_ecparams( const asn1_buf *params, ecc_key_t *key )
{
    ecp_curve_id_t grp_id;

    if( params->tag == ASN1_OID ) {
        if( oid_get_ec_grp( params, &grp_id ) != 0 )
            return( ERR_PK_UNKNOWN_NAMED_CURVE );
    } else {
        return( ERR_PK_KEY_INVALID_FORMAT );
    }

    /*
     * grp may already be initialized; if so, make sure IDs match
     */
    if( key->curve != ECP_DP_NONE && key->curve != grp_id )
        return( ERR_PK_KEY_INVALID_FORMAT );

    // init key curve id(which corresponds to group id)
    key->curve = grp_id;

    return( 0 );
}

static void rsa_pubkey_init(rsa_key_t *key) {
    // init
    key->n = NULL;
    key->n_size = 0;
    key->e = NULL;
    key->e_size = 0;
    key->d = NULL;
    key->d_size = 0;
    key->p = NULL;
    key->p_size = 0;
    key->q = NULL;
    key->q_size = 0;
    key->dp = NULL;
    key->dp_size = 0;
    key->dq = NULL;
    key->dq_size = 0;
    key->qp = NULL;
    key->qp_size = 0;
}

static void ecc_pubkey_init(ecc_key_t *key) {
    // init
    key->curve = ECP_DP_NONE;
    key->x = NULL;
    key->x_size = 0;
    key->y = NULL;
    key->y_size = 0;
    key->d = NULL;
    key->d_size = 0;
}

/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        icrypt_key_data_t *key )
{
    int ret = 0;
    size_t len;
    asn1_buf alg_params;
    pk_type_t pk_alg = PK_NONE;
    rsa_key_t *rsa_key = NULL;
    ecc_key_t *ecc_key = NULL;

    if( ( ret = asn1_get_tag( p, end, &len,
                    ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 ) {
        return( ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = pk_get_pk_alg( p, end, &pk_alg, &alg_params ) ) != 0 )
        return( ret );

    if( ( ret = asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( ERR_PK_INVALID_PUBKEY +
                ERR_ASN1_LENGTH_MISMATCH );

    if( pk_alg == PK_RSA ) {
        // update key type
        key->key_type = RSA_PUBKEY;
        rsa_key = &key->rsa_key;
        rsa_pubkey_init(rsa_key);
        ret = pk_get_rsapubkey( p, end, rsa_key );
    } else if( pk_alg == PK_ECKEY_DH || pk_alg == PK_ECKEY ) {
        // update key type
        key->key_type = ECC_PUBKEY;
        ecc_key = &key->ecc_key;
        // init
        ecc_pubkey_init(ecc_key);
        // parse curve_id
        ret = pk_use_ecparams( &alg_params, ecc_key);
        if( ret == 0 )
            ret = pk_get_ecpubkey( p, end, ecc_key );
    } else {
        ret = ERR_PK_UNKNOWN_PK_ALG;
    }

    if( ret == 0 && *p != end ) {
        ret = ERR_ASN1_LENGTH_MISMATCH;
    }

    return( ret );
}
