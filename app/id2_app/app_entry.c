/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "id2_test.h"

/* Hex String, getting from id2 console */
#define ID2_CIPHER_DATA     "34632fec4a366aa384579b50c207a33612e4e8d9b543"

int main(int argc, char *argv[])
{
    int ret;
    uint32_t cipher_len = 0;
    char *cipher_data = ID2_CIPHER_DATA;

    if (argc >= 2) {
        if (!strcmp(argv[1], "-set_data")) {
            cipher_data = argv[2];
        }
    }

    ret = id2_client_unit_test();
    if (ret < 0) {
        ID2_DBG_LOG("id2 client unit test fail!!\n");
        return -1;
    }

    cipher_len = strlen(cipher_data);

    ret = id2_client_generate_authcode();
    if (ret < 0) {
        ID2_DBG_LOG("id2 client generate authcode fail!!\n");
        return -1;
    }

    cipher_len = strlen(cipher_data);
    if (cipher_len > ID2_ID_LEN * 2) {
        ret = id2_client_decrypt_data(cipher_data, cipher_len);
        if (ret < 0) {
            ID2_DBG_LOG("id2 client decrypt data fail!!\n");
            return -1;
        }
    }

    return 0;
}

