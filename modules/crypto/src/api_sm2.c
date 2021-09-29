/**
 * Copyright (C) 2018  Alibaba Group Holding Limited.
 */

#include "ali_crypto.h"
#include "ls_hal_crypt.h"

ali_crypto_result ali_sm2_public_encrypt(const ecc_key_t *key,
                                         const uint8_t *src, size_t src_size,
                                         uint8_t *dst, size_t *dst_size)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret;
    void *hal_ctx;

    if (key == NULL) {
        CRYPTO_ERR_LOG("invalid key\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL || src_size == 0 || dst_size == NULL ||
        ((dst == NULL) && (*dst_size != 0))) {
        CRYPTO_ERR_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    // allocate hal ctx
    hal_ctx = (void *)ls_osa_malloc(ls_hal_ecc_get_ctx_size());
    if (hal_ctx == NULL) {
        CRYPTO_ERR_LOG("malloc %d failed\n", ls_hal_ecc_get_ctx_size());
        return ALI_CRYPTO_OUTOFMEM;
    }

    // init hal_ctx
    ret = ls_hal_ecc_init(hal_ctx);
    if (ret) {
        CRYPTO_ERR_LOG("hal_ctx init failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_ecc_init_pubkey(hal_ctx, key->curve,
                                 key->x, key->x_size,
                                 key->y, key->y_size);
    if (ret) {
        CRYPTO_ERR_LOG("init pubkey failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_sm2_encrypt(hal_ctx,
                             src, src_size,
                             dst, dst_size);
    if (ret == HAL_CRYPT_SHORT_BUFFER) {
        result = ALI_CRYPTO_SHORT_BUFFER;
        goto cleanup;
    }

    if (ret) {
        CRYPTO_ERR_LOG("public enc failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

cleanup:
    // free hal_ctx
    if (hal_ctx) {
        ls_hal_ecc_cleanup(hal_ctx);
        ls_osa_free(hal_ctx);
    }

    return result;
}

ali_crypto_result ali_sm2_private_decrypt(const ecc_key_t *key,
                                          const uint8_t *src, size_t src_size,
                                          uint8_t *dst, size_t *dst_size)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret;
    void *hal_ctx;

    if (key == NULL) {
        CRYPTO_ERR_LOG("invalid key\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL || src_size == 0 || dst_size == NULL ||
        ((dst == NULL) && (*dst_size != 0))) {
        CRYPTO_ERR_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    // allocate hal ctx
    hal_ctx = (void *)ls_osa_malloc(ls_hal_ecc_get_ctx_size());
    if (hal_ctx == NULL) {
        CRYPTO_ERR_LOG("malloc %d failed\n", ls_hal_ecc_get_ctx_size());
        return ALI_CRYPTO_OUTOFMEM;
    }

    // init hal_ctx
    ret = ls_hal_ecc_init(hal_ctx);
    if (ret) {
        CRYPTO_ERR_LOG("hal_ctx init failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_ecc_init_keypair(hal_ctx, key->curve,
                                  key->x, key->x_size,
                                  key->y, key->y_size,
                                  key->d, key->d_size);
    if (ret) {
        CRYPTO_ERR_LOG("init pubkey failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_sm2_decrypt(hal_ctx,
                             src, src_size,
                             dst, dst_size);
    if (ret == HAL_CRYPT_SHORT_BUFFER) {
        result = ALI_CRYPTO_SHORT_BUFFER;
        goto cleanup;
    }

    if (ret) {
        CRYPTO_ERR_LOG("private dec failed(0x%08x)\n", ret);
        ret = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

cleanup:
    // free hal_ctx
    if (hal_ctx) {
        ls_hal_ecc_cleanup(hal_ctx);
        ls_osa_free(hal_ctx);
    }

    return result;
}

ali_crypto_result ali_sm2_sign(const ecc_key_t *key,
                               const uint8_t *dig, size_t dig_size,
                               uint8_t *sig, size_t *sig_size)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret;
    void *hal_ctx;

    if (dig == NULL || dig_size == 0 || sig_size == NULL ||
        ((sig == NULL) && (*sig_size != 0))) {
        CRYPTO_ERR_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    if (dig_size != SM3_HASH_SIZE) {
        CRYPTO_ERR_LOG("wrong digest size(%ld)\n", dig_size);
        return ALI_CRYPTO_INVALID_ARG;
    }

    if (*sig_size < 2*dig_size) {
        *sig_size = 2*dig_size;
        return ALI_CRYPTO_SHORT_BUFFER;
    }

    // allocate hal ctx
    hal_ctx = (void *)ls_osa_malloc(ls_hal_ecc_get_ctx_size());
    if (hal_ctx == NULL) {
        CRYPTO_ERR_LOG("malloc %d failed\n", ls_hal_ecc_get_ctx_size());
        return ALI_CRYPTO_OUTOFMEM;
    }

    // init hal_ctx
    ret = ls_hal_ecc_init(hal_ctx);
    if (ret) {
        CRYPTO_ERR_LOG("hal_ctx init failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_ecc_init_keypair(hal_ctx, key->curve,
                                  key->x, key->x_size,
                                  key->y, key->y_size,
                                  key->d, key->d_size);
    if (ret) {
        CRYPTO_ERR_LOG("init pubkey failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_sm2_sign(hal_ctx,
                          dig, dig_size,
                          sig, sig_size);
    if (ret == HAL_CRYPT_SHORT_BUFFER) {
        result = ALI_CRYPTO_SHORT_BUFFER;
        goto cleanup;
    }

    if (ret) {
        CRYPTO_ERR_LOG("private dec failed(0x%08x)\n", ret);
        ret = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

cleanup:
    // free hal_ctx
    if (hal_ctx) {
        ls_hal_ecc_cleanup(hal_ctx);
        ls_osa_free(hal_ctx);
    }

    return result;
}

ali_crypto_result ali_sm2_verify(const ecc_key_t *key,
                                 const uint8_t *dig, size_t dig_size,
                                 const uint8_t *sig, size_t sig_size,
                                 bool *p_result)
{
    ali_crypto_result result = 0;
    int ret;
    void *hal_ctx;

    if (p_result == NULL
        || dig == NULL || dig_size == 0
        || sig == NULL || sig_size == 0) {
        CRYPTO_ERR_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }
    *p_result = false;

    // allocate hal ctx
    hal_ctx = (void *)ls_osa_malloc(ls_hal_ecc_get_ctx_size());
    if (hal_ctx == NULL) {
        CRYPTO_ERR_LOG("malloc %d failed\n", ls_hal_ecc_get_ctx_size());
        return ALI_CRYPTO_OUTOFMEM;
    }

    // init hal_ctx
    ret = ls_hal_ecc_init(hal_ctx);
    if (ret) {
        CRYPTO_ERR_LOG("hal_ctx init failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_ecc_init_pubkey(hal_ctx, key->curve,
                                 key->x, key->x_size,
                                 key->y, key->y_size);
    if (ret) {
        CRYPTO_ERR_LOG("init pubkey failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_sm2_verify(hal_ctx,
                            dig, dig_size,
                            sig, sig_size);
cleanup:
    // free hal_ctx
    if (hal_ctx) {
        ls_hal_ecc_cleanup(hal_ctx);
        ls_osa_free(hal_ctx);
    }

    if (HAL_CRYPT_INVALID_AUTH == ret) {
        return ALI_CRYPTO_INVALID_AUTHENTICATION;
    } else if (ret) {
        CRYPTO_ERR_LOG("verify failed(0x%08x)\n", ret);
        return ALI_CRYPTO_ERROR;
    } else {
        *p_result = true;
    }

    return result;
}

ali_crypto_result ali_sm2_msg_sign(const ecc_key_t *key,
                                   hash_type_t hash,
                                   const uint8_t *id,  size_t id_size,
                                   const uint8_t *msg, size_t msg_size,
                                   uint8_t *sig, size_t *sig_size)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret = 0;
    void *hal_ctx = NULL;
    // digest
    uint8_t *e = NULL;
    size_t e_size;

    if (key == NULL) {
        CRYPTO_ERR_LOG("invalid key\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (msg == NULL || msg_size == 0   ||
       ( id == NULL ||  id_size == 0 ) ||
        ((sig == NULL) && (*sig_size != 0))) {
        CRYPTO_ERR_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    // set the max possible hash length by default
    e_size = SHA512_HASH_SIZE;
    e = (uint8_t *)ls_osa_malloc(e_size);
    if (NULL == e) {
        CRYPTO_ERR_LOG("malloc %ld failed\n", e_size);
        goto cleanup;
    }

    // allocate hal ctx
    hal_ctx = (void *)ls_osa_malloc(ls_hal_ecc_get_ctx_size());
    if (hal_ctx == NULL) {
        CRYPTO_ERR_LOG("malloc %d failed\n", ls_hal_ecc_get_ctx_size());
        result = ALI_CRYPTO_OUTOFMEM;
        goto cleanup;
    }

    // init hal_ctx
    ret = ls_hal_ecc_init(hal_ctx);
    if (ret) {
        CRYPTO_ERR_LOG("hal_ctx init failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_ecc_init_keypair(hal_ctx, key->curve,
                                  key->x, key->x_size,
                                  key->y, key->y_size,
                                  key->d, key->d_size);
    if (ret) {
        CRYPTO_ERR_LOG("init pubkey failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    // ls_hal
    ret = ls_hal_sm2_msg_digest(hal_ctx,
                                hash,
                                id, id_size,
                                msg, msg_size,
                                e, &e_size);
    if (ret) {
        CRYPTO_ERR_LOG("msg digest failed(0x%08x)\n", ret);
        goto cleanup;
    }

    // sm2 sign
    ret = ls_hal_sm2_sign(hal_ctx,
                          e, e_size,
                          sig, sig_size);
    if (ret == HAL_CRYPT_SHORT_BUFFER) {
        result = ALI_CRYPTO_SHORT_BUFFER;
        goto cleanup;
    }

    if (ret) {
        CRYPTO_ERR_LOG("hal sm2 sign failed(0x%08x)\n", ret);
        goto cleanup;
    }

cleanup:
    if (hal_ctx) {
        ls_hal_ecc_cleanup(hal_ctx);
        ls_osa_free(hal_ctx);
    }

    if (e) {
        ls_osa_free(e);
    }

    return result;
}

ali_crypto_result ali_sm2_msg_verify(const ecc_key_t *key,
                                     hash_type_t hash,
                                     const uint8_t *id,  size_t id_size,
                                     const uint8_t *msg, size_t msg_size,
                                     const uint8_t *sig, size_t sig_size,
                                     bool *p_result)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret = 0;
    void *hal_ctx = NULL;
    // digest
    uint8_t *e = NULL;
    size_t e_size;

    if (key == NULL) {
        CRYPTO_ERR_LOG("invalid key\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (p_result == NULL ||
        msg == NULL || msg_size == 0  ||
        id == NULL  || id_size == 0   ||
        sig == NULL || sig_size == 0) {
        CRYPTO_ERR_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }
    *p_result = false;

    // set the max possible hash length by default
    e_size = SHA512_HASH_SIZE;
    e = (uint8_t *)ls_osa_malloc(e_size);
    if (NULL == e) {
        CRYPTO_ERR_LOG("malloc %ld failed\n", e_size);
        result = ALI_CRYPTO_OUTOFMEM;
        goto cleanup;
    }

    // allocate hal ctx
    hal_ctx = (void *)ls_osa_malloc(ls_hal_ecc_get_ctx_size());
    if (hal_ctx == NULL) {
        CRYPTO_ERR_LOG("malloc %d failed\n", ls_hal_ecc_get_ctx_size());
        result = ALI_CRYPTO_OUTOFMEM;
        goto cleanup;
    }

    // init hal_ctx
    ret = ls_hal_ecc_init(hal_ctx);
    if (ret) {
        CRYPTO_ERR_LOG("hal_ctx init failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_ecc_init_pubkey(hal_ctx, key->curve,
                                 key->x, key->x_size,
                                 key->y, key->y_size);
    if (ret) {
        CRYPTO_ERR_LOG("init pubkey failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    // ls_hal
    ret = ls_hal_sm2_msg_digest(hal_ctx,
                                hash,
                                id, id_size,
                                msg, msg_size,
                                e, &e_size);
    if (ret) {
        CRYPTO_ERR_LOG("msg digest failed(0x%08x)\n", ret);
        goto cleanup;
    }

    // sm2 verify
    ret = ls_hal_sm2_verify(hal_ctx,
                            e, e_size,
                            sig, sig_size);
cleanup:
    // free hal_ctx
    if (hal_ctx) {
        ls_hal_ecc_cleanup(hal_ctx);
        ls_osa_free(hal_ctx);
    }

    if (e) {
        ls_osa_free(e);
    }

    if (HAL_CRYPT_INVALID_AUTH == ret) {
        return ALI_CRYPTO_INVALID_AUTHENTICATION;
    } else if (ret) {
        CRYPTO_ERR_LOG("verify failed(0x%08x)\n", ret);
        return ALI_CRYPTO_ERROR;
    } else {
        *p_result = true;
    }

    return result;
}
