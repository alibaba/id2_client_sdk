/**
 * Copyright (C) 2017  Alibaba Group Holding Limited.
 */

#include "ali_crypto.h"
#include "ls_hal_crypt.h"

ali_crypto_result ali_rand_gen(uint8_t *buf, size_t len)
{
    int ret = HAL_CRYPT_SUCCESS;

    if (buf == NULL || len == 0) {
        CRYPTO_ERR_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ret = ls_hal_get_random(buf, len);
    if (ret != HAL_CRYPT_SUCCESS) {
        CRYPTO_ERR_LOG("hal get random failed(0x%08x)\n", ret);
        return ALI_CRYPTO_ERROR;
    }

    return ALI_CRYPTO_SUCCESS;
}

ali_crypto_result ali_seed(uint8_t *seed, size_t seed_len)
{
    int ret = HAL_CRYPT_SUCCESS;

    if (seed == NULL || seed_len == 0) {
        CRYPTO_DBG_LOG("invalid input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ret = ls_hal_set_seed(seed, seed_len);
    if (ret != HAL_CRYPT_SUCCESS) {
        CRYPTO_ERR_LOG("failed(0x%08x)\n", ret);
        return ALI_CRYPTO_ERROR;
    }
    	
    return ALI_CRYPTO_SUCCESS;
}
