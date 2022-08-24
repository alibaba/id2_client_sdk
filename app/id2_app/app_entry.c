/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "id2_test.h"

#define SERVER_NAME     "itls.cn-shanghai.aliyuncs.com"
#define SERVER_PORT     1883

#define PRODUCT_KEY     "a1WO4Z9qHRw"
#define PRODUCT_SECRET  "i113XXXXXXXXXXXXXXXXXXXXXXXXXXXX"

/* Hex String, getting from id2 console */
#define ID2_AUTH_CODE          ""
#define ID2_CIPHER_DATA        ""

static kpm_suite_t kpm_suite = {
    /* user-defined index */
    LS_KPM_KEY_IDX_INVALID,

    /* kpm defined key info */
    LS_KPM_KEY_INFO_AES_128,

    /* import key data, getting from id2 console  */
    ""
};

int main(int argc, char *argv[])
{
    int ret;
    uint32_t timeout_ms = 2000;
    uint32_t auth_code_len = 0;
    uint32_t cipher_len = 0;
    char *auth_code = ID2_AUTH_CODE;
    char *cipher_data = ID2_CIPHER_DATA;

    /* 1. id2 client init */
    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    /* 2. check if id2 has been provisioned or not, if not, request id2 from itls server */
    ret = id2_client_wrap_do_provisioning(SERVER_NAME,
                     SERVER_PORT, PRODUCT_KEY, PRODUCT_SECRET, timeout_ms);
    if (ret == IROT_ERROR_NOT_SUPPORTED) {
        /* do nothing */
    } else if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client do provisioning fail, %d\n", ret);
        goto _out;
    } else {
        /* reach here, meaning that id2 has been provisioned */

        /* id2 client function testing */
        ret = id2_client_unit_test();
        if (ret < 0) {
            ID2_DBG_LOG("id2 client unit test fail!!\n");
            goto _out;
        }
    }

    /* 3. generate authcode */
    ret = id2_client_generate_authcode(&kpm_suite);
    if (ret < 0) {
        ID2_DBG_LOG("id2 client generate authcode fail!!\n");
        goto _out;
    }

    /* 4. verify id2 server if auth_code correct */
    auth_code_len = strlen(auth_code);
    if (auth_code_len > ID2_ID_MIN_LEN * 2) {
        ret = id2_client_verify_authcode(auth_code, auth_code_len);
        if (ret < 0) {
            ID2_DBG_LOG("id2 client verify server authcode fail!!\n");
            goto _out;
        }
    }

    /* 5. decrypt data if cipher_data correct */
    cipher_len = strlen(cipher_data);
    if (cipher_len > ID2_ID_MIN_LEN * 2) {
        ret = id2_client_decrypt_data(cipher_data, cipher_len);
        if (ret < 0) {
            ID2_DBG_LOG("id2 client decrypt data fail!!\n");
            goto _out;
        }
    }

    /* 6. id2 kpm testing if needed */
    ret = id2_client_kpm_test(kpm_suite.key_idx, kpm_suite.key_info, kpm_suite.import_data);
    if (ret < 0) {
        ID2_DBG_LOG("id2 client kpm test fail!!\n");
        return -1;
    }

_out:
    /* 7. id2 client cleanup */
    id2_client_cleanup();

    return ret;
}

