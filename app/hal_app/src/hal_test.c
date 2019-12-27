/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 */

#include "hal_test.h"

int hal_dump_data(const char *name, uint8_t *data, uint32_t size)
{
#if defined(CONFIG_HAL_DEBUG)
    size_t i;

    if (data == NULL || size == 0) {
        HAL_TEST_ERR("invalid input args\n");
        return -1;
    }

    HAL_TEST_INF("%s size: %d\n", name, (int)size);

    for (i = 0; i < size - size % 8; i += 8) {
        HAL_TEST_INF("%s data: %02x%02x %02x%02x %02x%02x %02x%02x\n", name,
                  data[i + 0], data[i + 1], data[i + 2], data[i + 3],
                  data[i + 4], data[i + 5], data[i + 6], data[i + 7]);
    }
    while (i < size) {
        HAL_TEST_INF("%s data: %02x\n", name, data[i]);
        i++;
    }

    return 0;
#else
    (void)name;
    (void)data;
    (void)size;

    return 0;
#endif
}

#if defined(CONFIG_HAL_CRYPTO)

int hal_crypto_test(void)
{
    int ret = 0;

    HAL_TEST_INF("HAL Hash Test:\n");
    ret = hal_hash_test();
    if (ret < 0) {
        return ret;
    }

    HAL_TEST_INF("HAL Rand Test:\n");
    ret = hal_rand_test();
    if (ret < 0) {
        return ret;
    }

    HAL_TEST_INF("HAL AES Test:\n");
    ret = hal_aes_test();
    if (ret < 0) {
        return ret;
    }

    HAL_TEST_INF("HAL RSA Test:\n");
    ret = hal_rsa_test();
    if (ret < 0) {
        return ret;
    }

    return ret;
}

#endif
