/**
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

#include "ali_crypto.h"
#include "asn1write.h"
#include "oid.h"
#include "asn1.h"
#include "ecp.h"

/**< Maximum number of bytes for usable MPIs. */
#define MPI_MAX_SIZE                              1024

/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
 *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
 *                                                + 1 + 1 + 9 (rsa oid)
 *                                                + 1 + 1 (params null)
 *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {                     1 + 3
 *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
 *  }
 */
#define RSA_PUB_DER_MAX_BYTES   38 + 2 * MPI_MAX_SIZE

/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
 *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
 *                                            + 1 + 1 + 7 (ec oid)
 *                                            + 1 + 1 + 9 (namedCurve oid)
 *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
 *                                            + 1 (point format)        [1]
 *                                            + 2 * ECP_MAX (coords)    [1]
 *  }
 */
#define ECP_PUB_DER_MAX_BYTES   30 + 2 * ECP_MAX_BYTES

/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_write_rsa_pubkey( unsigned char **p, unsigned char *start,
                                rsa_key_t *rsa_key )
{
    int ret;
    size_t len = 0;

    ASN1_CHK_ADD( len, asn1_write_buffer( p, start, rsa_key->e, rsa_key->e_size ) );
    ASN1_CHK_ADD( len, asn1_write_buffer( p, start, rsa_key->n, rsa_key->n_size ) );

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    return( (int) len );
}

/*
 * EC public key is an EC point
 */
static int pk_write_ec_pubkey( unsigned char **p, unsigned char *start,
                               ecc_key_t *key )
{
    size_t len = 0;
    unsigned char buf[ECP_MAX_PT_LEN];

    // format is uncompressed
    len = 2 * key->x_size + 1;
    buf[0] = 0x04;
    memcpy(buf + 1, key->x, key->x_size);
    memcpy(buf + 1 + key->x_size, key->y, key->y_size);

    if( *p < start || (size_t)( *p - start ) < len )
        return( ERR_ASN1_BUF_TOO_SMALL );

    *p -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}

int pk_write_pubkey( unsigned char **p, unsigned char *start,
                     icrypt_key_data_t *key )
{
    int ret;
    size_t len = 0;

    if (key->key_type == RSA_PUBKEY) {
        ASN1_CHK_ADD( len, pk_write_rsa_pubkey( p, start, &key->rsa_key ) );
    } else if (key->key_type == ECC_PUBKEY) {
        // TODO: add ECP/SM2 support
        ASN1_CHK_ADD( len, pk_write_ec_pubkey( p, start, &key->ecc_key ) );
    } else {
        CRYPTO_ERR_LOG("key type(%d) not supported\n", key->key_type);
        return ERR_PK_FEATURE_UNAVAILABLE;
    }

    return( (int) len );
}

// write ecc grp oid
static int pk_write_ec_param( unsigned char **p, unsigned char *start, ecc_key_t *key)
{
    int ret;
    size_t len = 0;
    const char *oid;
    size_t oid_len;

    if (( ret = oid_get_oid_by_ec_grp( key->curve, &oid, &oid_len ) ) != 0) {

        CRYPTO_ERR_LOG("get ec grp oid failed(0x%08x)\n", ret);
        return ret;
    }
    ASN1_CHK_ADD( len, asn1_write_oid( p, start, oid, oid_len ) );

    return ( (int) len );
}

// write public key into ASN1(DER) format
ali_crypto_result ali_pk_write_pubkey_der(icrypt_key_data_t *key, uint8_t *buf, size_t *size)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret = 0;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    const char *oid;
    unsigned char * tmp;
    size_t tmp_len;

    if (!size || (!buf && *size)) {
        CRYPTO_ERR_LOG("invalid buf/size\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    if (key == NULL) {
        CRYPTO_ERR_LOG("invalid key\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    if (key->key_type == RSA_PUBKEY) {
        tmp_len = RSA_PUB_DER_MAX_BYTES;
    } else if (key->key_type == ECC_PUBKEY) {
        tmp_len = ECP_PUB_DER_MAX_BYTES;
    } else {
        CRYPTO_ERR_LOG("key type(%d) not supported\n", key->key_type);
        return ALI_CRYPTO_INVALID_ARG;
    }

    tmp = (unsigned char *)ls_osa_malloc(tmp_len);
    if (tmp == NULL) {
        CRYPTO_ERR_LOG("failed to malloc %ld bytes\n", tmp_len);
        return ALI_CRYPTO_OUTOFMEM;
    }

    // and use c = buf + *size
    // default: rsa case
    c = tmp + tmp_len;

    ASN1_CHK_ADD_CLEAN( len, pk_write_pubkey( &c, tmp, key ) );
    if( c - tmp < 1 ) {
        *size = tmp_len;
        result = ALI_CRYPTO_SHORT_BUFFER;
        goto cleanup;
    }

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    ASN1_CHK_ADD_CLEAN( len, asn1_write_len( &c, tmp, len ) );
    ASN1_CHK_ADD_CLEAN( len, asn1_write_tag( &c, tmp, ASN1_BIT_STRING ) );

    // TODO: add other key type support (oid/oid_len assigned accoridng to key type)
    if (key->key_type == RSA_PUBKEY) {
        oid = OID_PKCS1_RSA;
        oid_len = sizeof(OID_PKCS1_RSA) - 1;
    } else if (key->key_type == ECC_PUBKEY) {
        oid = OID_EC_ALG_UNRESTRICTED;
        oid_len = sizeof(OID_EC_ALG_UNRESTRICTED) - 1;
        // For ECC, need to add group oid
        ASN1_CHK_ADD_CLEAN( par_len, pk_write_ec_param( &c, tmp, &key->ecc_key) );
    } else {
        CRYPTO_ERR_LOG("key type(%d) not supported\n", key->key_type);
        return ALI_CRYPTO_INVALID_ARG;
    }

    ASN1_CHK_ADD_CLEAN( len, asn1_write_algorithm_identifier( &c, tmp, oid, oid_len,
                                                              par_len ) );

    ASN1_CHK_ADD_CLEAN( len, asn1_write_len( &c, tmp, len ) );
    ASN1_CHK_ADD_CLEAN( len, asn1_write_tag( &c, tmp, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    if (*size == 0 && !buf) {
        *size = len;
        result = ALI_CRYPTO_SHORT_BUFFER;
        goto cleanup;
    }

    if (*size < len) {
        *size = len;
        result = ALI_CRYPTO_SHORT_BUFFER;
        goto cleanup;
    }

    // update size
    *size = len;

    // copy from tmp to buf
    memcpy(buf, tmp + tmp_len - len, len);

cleanup:
    // free
    if (tmp) {
        ls_osa_free(tmp);
        tmp = NULL;
    }

    if (result != ALI_CRYPTO_SUCCESS) {
        CRYPTO_ERR_LOG("failed(%d)\n", result);
        return result;
    }

    return result;
}
