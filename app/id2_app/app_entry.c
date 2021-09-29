/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "id2_test.h"

/* Hex String, getting from id2 console */
#define ID2_AUTH_CODE       ""
#define ID2_CIPHER_DATA     ""

#if defined(CONFIG_ID2_DEBUG)
#define ID2_ID     "0102030405060708090A0B0C"
#define ID2_KEY    "0102030405060708090A0B0C0D0E0F101112131415161718"
#endif

int main(int argc, char *argv[])
{
    int ret;
    bool is_prov;
    uint32_t auth_code_len = 0;
    uint32_t cipher_len = 0;
    char *auth_code = ID2_AUTH_CODE;
    char *cipher_data = ID2_CIPHER_DATA;

    ret = id2_client_unit_test();
    if (ret < 0) {
        ID2_DBG_LOG("id2 client unit test fail!!\n");
        return -1;
    }

    /* 1. id2 client init */
    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    /* 2. check if id2 exist in device */
    ret = id2_client_get_prov_stat(&is_prov);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client get prov stat fail, %d\r\n", ret);
        goto _out;
    }

    if (is_prov == false) {
        ID2_DBG_LOG("no id2 in device, need to prov first!!\n");
        ret = -1;
        goto _out;
    }

    /* 3. generate authcode */
    ret = id2_client_generate_authcode();
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

_out:
    /* 6. id2 client cleanup */
    id2_client_cleanup();

    return ret;
}

