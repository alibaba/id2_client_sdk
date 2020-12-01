/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "id2_test.h"

/* Hex String, getting from id2 console */
#define ID2_CIPHER_DATA     "34632fec4a366aa384579b50c207a33612e4e8d9b543"

int main(int argc, char *argv[])
{
    int ret;
    bool is_prov;
    uint32_t cipher_len = 0;
    char *cipher_data = ID2_CIPHER_DATA;
#if defined(CONFIG_ID2_DEBUG)
    char *id2_id = "0102030405060708090A0B0C";
    char *id2_key = "0102030405060708090A0B0C0D0E0F101112131415161718";
#endif

    if (argc >= 2) {
        if (!strcmp(argv[1], "-set_data")) {
            cipher_data = argv[2];
        }
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
        return -1;
    }

    if (is_prov == false) {
#if defined(CONFIG_ID2_DEBUG)
        ret = id2_client_set_id2_and_key(id2_id, 0x02, id2_key);
        if (ret != IROT_SUCCESS) {
            ID2_DBG_LOG("set id2 and key fail, %d\n", ret);
            return -1;
        }
#else
        ID2_DBG_LOG("no id2 in device, need to prov first!!\n");
        return -1;
#endif
    }

    /* 3. generate authcode */
    ret = id2_client_generate_authcode();
    if (ret < 0) {
        ID2_DBG_LOG("id2 client generate authcode fail!!\n");
        return -1;
    }

    /* 4. decrypt data if cipher_data correct */
    cipher_len = strlen(cipher_data);
    if (cipher_len > ID2_ID_LEN * 2) {
        ret = id2_client_decrypt_data(cipher_data, cipher_len);
        if (ret < 0) {
            ID2_DBG_LOG("id2 client decrypt data fail!!\n");
            return -1;
        }
    }

    /* 5. id2 client cleanup */
    id2_client_cleanup();

    return 0;
}

