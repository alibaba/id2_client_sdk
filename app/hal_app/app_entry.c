/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "hal_test.h"

int main(int argc, char *argv[])
{
    int ret;

    ret = hal_crypto_test();
    if (ret < 0) {
        HAL_TEST_ERR("hal_crypto test fail!!\n");
        return -1;
    }

    return 0;
}

