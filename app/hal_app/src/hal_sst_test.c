/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "ls_hal.h"
#include "hal_test.h"

#define g_key_1 "sst_hal_test_key_1"
#define g_val_1 "sst_hal_test_val_1"
#define g_val1_len 18

#define MAX_TEST_VALUE_LEN 512

typedef struct _set_test_params_t {
    char *key;
    char *value;
    uint32_t value_len;
    uint32_t exp_ret;
} set_test_params_t;

typedef struct _get_test_params_t {
    char *key;
    uint8_t value_null;
    uint32_t value_len;
    uint32_t exp_ret;
    uint32_t exp_len;
    char *value;
} get_test_params_t;

typedef struct _del_test_params_t {
    char *key;
    uint32_t exp_ret;
} del_test_params_t;

static set_test_params_t set_params[] = {
    {NULL, NULL, 0, SST_HAL_ERROR_BAD_PARAMETERS},
    {NULL, g_val_1, g_val1_len, SST_HAL_ERROR_BAD_PARAMETERS},
    {g_key_1, NULL, 0, SST_HAL_ERROR_BAD_PARAMETERS},
    {g_key_1, g_val_1, g_val1_len, SST_HAL_SUCCESS},
};

static get_test_params_t get_params[] = {
    {NULL, 0, 0, SST_HAL_ERROR_BAD_PARAMETERS, 0, NULL},
    {g_key_1, 1, 1, SST_HAL_ERROR_BAD_PARAMETERS, 0, NULL}, //secret = NULL
    {g_key_1, 1, 0, SST_HAL_ERROR_SHORT_BUFFER, g_val1_len, NULL}, //secret = NULL
    {g_key_1, 0, 1, SST_HAL_ERROR_SHORT_BUFFER, g_val1_len, NULL}, //secret != NULL
    {g_key_1, 0, g_val1_len, SST_HAL_SUCCESS, g_val1_len, g_val_1},
    {g_key_1, 0, MAX_TEST_VALUE_LEN, SST_HAL_SUCCESS, g_val1_len, g_val_1},
    {g_val_1, 0, g_val1_len, SST_HAL_ERROR_ITEM_NOT_FOUND, 0, NULL},
};

static del_test_params_t del_params[] = {
    {NULL, SST_HAL_ERROR_BAD_PARAMETERS},
    {g_val_1, SST_HAL_ERROR_ITEM_NOT_FOUND},
    {g_key_1, SST_HAL_SUCCESS},
};

static int hal_sst_test_set()
{
    char *key;
    uint8_t *secret;
    uint32_t secret_len = 0;
    uint32_t ret;
    int size_store_case = (int)(sizeof(set_params) / sizeof(set_params[0]));
    set_test_params_t store_param;
    int i = 0;

    HAL_TEST_INF("test_sec_sst_store.\n set case size %d\n", size_store_case);

    for (i = 0; i < size_store_case; i++) {
        store_param = set_params[i];
        HAL_TEST_INF("\ncase %d: ", i);

        key = store_param.key;
        secret = (uint8_t *)(store_param.value);
        secret_len = store_param.value_len;
        ret = ls_hal_kv_set(key, secret, secret_len);
        if (ret != store_param.exp_ret) {
            HAL_TEST_ERR("test kv set[%d] failed ret 0x%x : exp_ret 0x%x\n",
                    i, ret, store_param.exp_ret);
            return -1;
        }
        HAL_TEST_INF("test_sec_sst_store[%d] success\n", i);
    }
    HAL_TEST_INF("test_sec_sst_store total %d case success\n\n", size_store_case);
    return 0;
}

static int hal_sst_test_get()
{
    char *key = NULL;
    uint8_t *secret = NULL;
    uint32_t secret_len = 0;
    int i = 0;
    int size_get_case = (int)(sizeof(get_params) / sizeof(get_params[0]));
    get_test_params_t get_param;
    int ret = 0;

    HAL_TEST_INF("test_sec_sst_store.\n get case size %d\n", size_get_case);

    for (i = 0; i < size_get_case; i++) {
        HAL_TEST_INF("\ncase %d: ", i);
        get_param = get_params[i];

        key = get_param.key;
        if (get_param.value_null) {
            secret = NULL;
        } else {
            secret = ls_osa_malloc(get_param.value_len + 1);
            memset(secret, 0, get_param.value_len + 1);
        }
        secret_len = get_param.value_len;
        ret = ls_hal_kv_get(key, secret, &secret_len);
        if (ret != get_param.exp_ret) {
            HAL_TEST_ERR("test kv get[%d] failed ret 0x%x : exp_ret 0x%x\n",
                    i, ret, get_param.exp_ret);
            goto clean;
        }

        if (get_param.exp_ret == SST_HAL_SUCCESS) {
            if (secret_len != get_param.exp_len) {
                HAL_TEST_ERR("test_sec_sst_get[%d] failed wrong len %d\n", i, secret_len);
                goto clean;
            }

            if (memcmp(secret, get_param.value, secret_len)) {
                HAL_TEST_ERR("test_sec_sst_get[%d] failed wrong secret %s\n", i, secret);
                goto clean;
            } else {
                HAL_TEST_INF("secret is %s\n", secret);
            }
        } else if (get_param.exp_ret == SST_HAL_ERROR_SHORT_BUFFER) {
            if (secret_len != get_param.exp_len) {
                HAL_TEST_ERR("test_sec_sst_get[%d] failed wrong len %d\n", i, secret_len);
                goto clean;
            }
        }

        if (secret) {
            ls_osa_free(secret);
            secret = NULL;
        }

        HAL_TEST_INF("test_sec_sst_get[%d] success\n", i);
    }
    HAL_TEST_INF("test_sec_sst_get success. \n\n");
    return 0;

clean:
    if (secret) {
        ls_osa_free(secret);
        secret = NULL;
    }
    return -1;
}

int hal_sst_test_del()
{
    char *key = NULL;
    int i = 0;
    int size_del_case = (int)(sizeof(del_params) / sizeof(del_params[0]));
    del_test_params_t del_param;
    int ret = 0;

    for (i = 0; i < size_del_case; i++) {
        del_param = del_params[i];
        key = del_param.key;
        ret = ls_hal_kv_del(key);
        if (ret != del_param.exp_ret) {
            HAL_TEST_ERR("test kv del[%d] failed ret 0x%x : exp_ret 0x%x\n",
                    i, ret, del_param.exp_ret);
            return -1;
        }
        if (!del_param.exp_ret) { //delete success
            uint8_t data[MAX_TEST_VALUE_LEN];
            uint32_t data_len = MAX_TEST_VALUE_LEN;
            ret = ls_hal_kv_get(key, data, &data_len);
            if (!ret) {
                HAL_TEST_ERR("test_delete_item[%d] failed\n", i);
                return -1;
            }
        }
        HAL_TEST_INF("test_sec_sst_del[%d] success\n", i);
    }
    HAL_TEST_INF("test_sec_sst_del total %d case success\n\n", size_del_case);

    return 0;
}

int hal_sst_test()
{
    uint32_t ret = 0;

    ret = ls_hal_kv_init();
    if (ret == SST_HAL_ERROR_NOT_SUPPORTED) {
        HAL_TEST_INF("========================> SST HAL API: has not been implemented!\n");
        HAL_TEST_INF("========================> HAL SST Test End.\n\n");
        return 0;
    } else if (ret != SST_HAL_SUCCESS) {
        HAL_TEST_ERR("sst init failed\n");
        goto _out;
    }

    ret = hal_sst_test_set();
    if (ret != SST_HAL_SUCCESS) {
        HAL_TEST_ERR("hal sst test: kv set fail\n");
        ret = -1;
        goto _out;
    } else {
        HAL_TEST_INF("hal sst test: kv set Pass.\n");
    }

    ret = hal_sst_test_get();
    if (ret != SST_HAL_SUCCESS) {
        HAL_TEST_ERR("hal sst test: kv get fail\n");
        ret = -1;
        goto _out;
    } else {
        HAL_TEST_INF("hal sst test: kv get pass.\n");
    }

    ret = hal_sst_test_del();
    if (ret != SST_HAL_SUCCESS) {
        HAL_TEST_ERR("hal sst test: kv del fail\n");
        ret = -1;
        goto _out;
    } else {
        HAL_TEST_INF("hal sst test: kv del pass.\n");
    }

    ret = 0;

_out:
    ls_hal_kv_deinit();

    if (ret == SST_HAL_SUCCESS) {
        HAL_TEST_INF("========================> HAL SST Test Pass.\n\n");
        return 0;
    } else {
        HAL_TEST_INF("========================> HAL SST Test Fail.\n\n");
        return -1;
    }
}

