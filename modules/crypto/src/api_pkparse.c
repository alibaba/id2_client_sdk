/**
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

#include "ali_crypto.h"
#include "pk.h"
#include "oid.h"
#include "asn1.h"

// parse ASN1(DER) format of RSA public key
ali_crypto_result ali_pk_parse_public_key(uint8_t *buf, size_t size, icrypt_key_data_t *key)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret;
    unsigned char *p;

    if (!key) {
        CRYPTO_ERR_LOG("NULL key\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    p = (unsigned char *) buf;

    ret = pk_parse_subpubkey(&p, p + size, key);
    if (ret) {
        CRYPTO_ERR_LOG("failed 0x%08x\n", ret);
        result = ALI_CRYPTO_ERROR;
    }

    return result;
}
