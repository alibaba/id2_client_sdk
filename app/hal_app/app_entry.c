/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "hal_test.h"

int main(int argc, char *argv[])
{
    int ret;

#if defined(CONFIG_HAL_CRYPTO)
    ret = hal_crypto_test();
    if (ret < 0) {
        HAL_TEST_ERR("hal_crypto test fail!!\n");
        return -1;
    }
#endif

    ret = hal_sst_test();
    if (ret < 0) {
        HAL_TEST_ERR("hal_sst test fail!!\n");
        return -1;
    }

    ret = hal_km_test();
    if (ret < 0) {
        HAL_TEST_ERR("hal_km test fail!!\n");
        return -1;
    }

    return 0;
}

