/**
 * Copyright (C) 2018  Alibaba Group Holding Limited.
 */

#include "ali_crypto.h"
#include "ls_hal_crypt.h"

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    int ret = 0;
    long long time_ms = ls_osa_get_time_ms();

    ret = ls_hal_set_seed((uint8_t *)&time_ms, sizeof(long long));
    if (ret != HAL_CRYPT_SUCCESS) {
        CRYPTO_ERR_LOG("set seed failed(0x%08x)\n", ret);
        return ret;
    }

    ret = ls_hal_get_random(output, len);
    if (ret != HAL_CRYPT_SUCCESS) {
        CRYPTO_ERR_LOG("gen rand failed(%08x)\n", ret);
        return ret;
    }
    return ret;
}

ali_crypto_result ali_ecc_init_key(ecc_key_t *key,
                                   ecc_key_type_t type,
                                   ecp_curve_id_t curve,
                                   uint8_t *x, size_t x_size,
                                   uint8_t *y, size_t y_size,
                                   uint8_t *d, size_t d_size)
{
    // x, y must be valid
    if (type == ECC_PUBKEY) {
        if (x == NULL || x_size == 0 || y == NULL || y_size == 0) {
            CRYPTO_ERR_LOG("invalid x/y\n");
            return ALI_CRYPTO_INVALID_ARG;
        }
    }

    // check curve id
    if (curve <= 0 || curve > ECP_DP_SMP256R2) {
        CRYPTO_ERR_LOG("invalid curve id(%d)\n", curve);
        return ALI_CRYPTO_INVALID_ARG;
    }

    // init ecc key
    key->curve = curve;
    key->x = NULL;
    key->y = NULL;
    key->d = NULL;

    if (type == ECC_PUBKEY || type == ECC_KEYPAIR) {
        _MALLOC_COPY(key->x, x, x_size);
        key->x_size = x_size;
        _MALLOC_COPY(key->y, y, y_size);
        key->y_size = y_size;

        if (type == ECC_KEYPAIR) {
            if (d == NULL || d_size == 0) {
                CRYPTO_ERR_LOG("invalid d\n");
                return ALI_CRYPTO_INVALID_ARG;
            }

            _MALLOC_COPY(key->d, d, d_size);
            key->d_size = d_size;
        }

        return ALI_CRYPTO_SUCCESS;
    } else {
        CRYPTO_ERR_LOG("invalid type value(%d)\n", type);
        return ALI_CRYPTO_INVALID_ARG;
    }

cleanup:
    _FREE_BUF(key->x);
    _FREE_BUF(key->y);
    _FREE_BUF(key->d);
    return ALI_CRYPTO_OUTOFMEM;
}

void ali_ecc_clean(ecc_key_t *key)
{
    if (key) {
        // free x/y/d
        _FREE_BUF(key->x);
        _FREE_BUF(key->y);
        _FREE_BUF(key->d);
    }
    return;
}

ali_crypto_result ali_ecc_gen_keypair(ecp_curve_id_t curve,
                                      ecc_key_t *key)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret = 0;
    void * hal_ctx;
    hal_ecc_keypair_t kp;

    if (curve <= 0 || curve > ECP_DP_SMP256R2) {
        CRYPTO_ERR_LOG("invalid curve type(%d)\n", curve);
        return ALI_CRYPTO_INVALID_ARG;
    }

    if (key == NULL) {
        CRYPTO_ERR_LOG("invalid key\n");
        return ALI_CRYPTO_INVALID_ARG;
    }
    key->curve = curve;

    // allocate hal ctx
    hal_ctx = (void *)ls_osa_malloc(ls_hal_ecc_get_ctx_size());
    if (hal_ctx == NULL) {
        CRYPTO_ERR_LOG("malloc %d failed\n", ls_hal_rsa_get_ctx_size());
        return ALI_CRYPTO_OUTOFMEM;
    }

    // init hal_ctx
    ret = ls_hal_ecc_init(hal_ctx);
    if (ret) {
        CRYPTO_DBG_LOG("hal_ctx init failed(0x%08x)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = ls_hal_ecc_gen_keypair(hal_ctx, curve, myrand, NULL, &kp);
    if (ret) {
        CRYPTO_ERR_LOG("gen keypair failed(%d)\n", ret);
        result = ALI_CRYPTO_ERROR;
        goto cleanup;
    }

    key->x = kp.x;
    key->x_size = kp.x_size;
    key->y = kp.y;
    key->y_size = kp.y_size;
    key->d = kp.d;
    key->d_size = kp.d_size;

cleanup:
    // free hal_ctx
    if (hal_ctx) {
        ls_hal_ecc_cleanup(hal_ctx);
        ls_osa_free(hal_ctx);
    }

    return result;
}
