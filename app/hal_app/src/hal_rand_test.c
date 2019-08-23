/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 */

#include "ls_hal.h"
#include "hal_test.h"

#if defined(CONFIG_HAL_CRYPTO)

int hal_rand_test(void)
{
    ls_hal_crypt_result ret;
    uint8_t buf[16] = {0};

    ret = ls_hal_get_random(buf, 16);
    hal_dump_data("random buf", buf, 16);

    ret = ls_hal_get_random(buf, 16);
    hal_dump_data("random buf", buf, 16);

    if (ret == HAL_CRYPT_SUCCESS) {
        HAL_TEST_INF("==========================> HAL Rand Test Pass.\n\n");
        return 0;
    } else {
        HAL_TEST_INF("==========================> HAL Rand Test Fail.\n\n");
        return -1;
    }
}

#endif  /* CONFIG_HAL_CRYPTO */

