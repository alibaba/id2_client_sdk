/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "ls_osa.h"
#include "id2_client.h"

#define ID2_DBG_LOG(_f, ...)    ls_osa_print("%s %d: " _f,\
                                   __FUNCTION__, __LINE__, ##__VA_ARGS__)

static int id2_client_test_get_id(void)
{
    irot_result_t ret;
    uint32_t version = 0;
    uint32_t id2_len = 0;
    uint8_t id2[ID2_ID_MAX_LEN + 1] = {0};

    ID2_DBG_LOG("====> ID2 Client Test Get ID Start.\n");

    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    ret = id2_client_get_version(&version);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client get version fail\n");
        goto _out;
    }

    ret = id2_client_get_id(id2, &id2_len);
    if (ret != IROT_ERROR_SHORT_BUFFER) {
        ID2_DBG_LOG("get client id2 fail, %d\n", ret);
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    id2_len = ID2_ID_MAX_LEN;
    ret = id2_client_get_id(id2, &id2_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("get client id2 fail, %d\n", ret);
        goto _out;
    }

    ID2_DBG_LOG("ID2: %s\n", id2);

_out:
    id2_client_cleanup();

    ID2_DBG_LOG("====> ID2 Client Test Get ID End.\n");

    return ret == IROT_SUCCESS ? 0 : -1;
}

static int id2_client_test_get_challenge_auth_code(void)
{
    irot_result_t ret;
    uint32_t auth_code_len = 0;
    uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN] = {0};
    char *server_random = "55B83408399FA660F05C82E4F25333DC";
    char *extra = "abcd1234";

    ID2_DBG_LOG("====> ID2 Client Test Get Challenge Auth Code Start.\n");

    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    ret = id2_client_get_challenge_auth_code(
              server_random, NULL, 0, auth_code, &auth_code_len);
    if (ret != IROT_ERROR_SHORT_BUFFER) {
        ID2_DBG_LOG("get challenge auth code fail, %d\n", ret);
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    auth_code_len = ID2_MAX_AUTH_CODE_LEN;
    ret = id2_client_get_challenge_auth_code(
              server_random, NULL, 0, auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("get challenge auth code fail, %d\n", ret);
        goto _out;
    }

    ID2_DBG_LOG("authcode[no extra]:\n [%d] %s\n", auth_code_len, auth_code);

    auth_code_len = ID2_MAX_AUTH_CODE_LEN;
    ret = id2_client_get_challenge_auth_code(server_random,
                     (uint8_t *)extra, strlen(extra), auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("get challenge auth code fail, %d\n", ret);
        goto _out;
    }

    ID2_DBG_LOG("authcode[extra = %s]:\n [%d] %s\n", extra, auth_code_len, auth_code);

_out:
    id2_client_cleanup();

    ID2_DBG_LOG("====> ID2 Client Test Get Challenge Auth Code End.\n");

    return ret == IROT_SUCCESS ? 0 : -1;
}

static int id2_client_test_get_timestamp_auth_code(void)
{
    irot_result_t ret;
    uint32_t auth_code_len = 0;
    uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN] = {0};
    char *timestamp = "1512022279204";
    char *extra = "abcd1234";

    ID2_DBG_LOG("====> ID2 Client Test Get Timestamp Auth Code Start.\n");

    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    ret = id2_client_get_timestamp_auth_code(
              timestamp, NULL, 0, auth_code, &auth_code_len);
    if (ret != IROT_ERROR_SHORT_BUFFER) {
        ID2_DBG_LOG("get challenge auth code fail, %d\n", ret);
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    auth_code_len = ID2_MAX_AUTH_CODE_LEN;
    ret = id2_client_get_timestamp_auth_code(
              timestamp, NULL, 0, auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("get challenge auth code fail, %d\n", ret);
        goto _out;
    }

    ID2_DBG_LOG("authcode[no extra]:\n [%d] %s\n", auth_code_len, auth_code);

    auth_code_len = ID2_MAX_AUTH_CODE_LEN;
    ret = id2_client_get_timestamp_auth_code(timestamp,
                     (uint8_t *)extra, strlen(extra), auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("get challenge auth code fail, %d\n", ret);
        goto _out;
    }

    ID2_DBG_LOG("authcode[extra = %s]:\n [%d] %s\n", extra, auth_code_len, auth_code);

_out:
    id2_client_cleanup();

    ID2_DBG_LOG("====> ID2 Client Test Get Timestamp Auth Code End.\n");

    return ret == IROT_SUCCESS ? 0 : -1;
}

static int id2_client_test_get_secret(void)
{
    irot_result_t ret;
    uint32_t secret_len = 0;
    uint8_t secret[ID2_DERIV_SECRET_LEN + 1] = {0};
    const char* seed = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    ID2_DBG_LOG("====> ID2 Client Test Get Secret Start.\n");

    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    ret = id2_client_get_secret(seed, secret, &secret_len);
    if (ret != IROT_ERROR_SHORT_BUFFER) {
        ID2_DBG_LOG("get client secret fail, %d\n", ret);
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    secret_len = ID2_DERIV_SECRET_LEN;
    ret = id2_client_get_secret(seed, secret, &secret_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client get secret fail, %d\n", ret);
        goto _out;
    }

    ID2_DBG_LOG("device secret: [%d] %s\n", secret_len, secret);

_out:
    id2_client_cleanup();

    ID2_DBG_LOG("====> ID2 Client Test Get Secret End.\n");

    return ret == IROT_SUCCESS ? 0 : -1;
}

static int id2_client_test_derive_key(void)
{
    irot_result_t ret;
    uint32_t i, key_len;
    uint8_t key[ID2_DERIV_KEY_LEN] = {0};
    const char* seed = "appKey";

    ID2_DBG_LOG("====> ID2 Client Test Derive Key Start.\n");

    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    key_len = 16;
    ret = id2_client_derive_key(seed, key, key_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client derive key fail, %d\n", ret);
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    for (i = 0; i < key_len - key_len % 4; i += 4) {
        ID2_DBG_LOG("key: 0x%02x 0x%02x 0x%02x 0x%02x\n",
                     key[i+0], key[i+1], key[i+2], key[i+3]);
    }
    while(i < key_len) {
        ID2_DBG_LOG("key: 0x%02x\n", key[i++]);
    }

_out:
    id2_client_cleanup();

    ID2_DBG_LOG("====> ID2 Client Test Derive Key End.\n");

    return ret == IROT_SUCCESS ? 0 : -1;
}

int id2_client_unit_test(void)
{
    int ret;


    ret = id2_client_test_get_id();
    if (ret < 0) {
        ID2_DBG_LOG("=================>ID2 Client Test Get ID Fail.\n\n");
        return -1;
    } else {
        ID2_DBG_LOG("=================>ID2 Client Test Get ID Pass.\n\n");
    }

    ret = id2_client_test_get_challenge_auth_code();
    if (ret < 0) {
        ID2_DBG_LOG("=================>ID2 Client Test Get Challenge Auth Code Fail.\n\n");
        return -1;
    } else {
        ID2_DBG_LOG("=================>ID2 Client Test Get Challenge Auth Code Pass.\n\n");
    }

    ret = id2_client_test_get_timestamp_auth_code();
    if (ret < 0) {
        ID2_DBG_LOG("=================>ID2 Client Test Get Timestamp Auth Code Fail.\n\n");
        return -1;
    } else {
        ID2_DBG_LOG("=================>ID2 Client Test Get Timestamp Auth Code Pass.\n\n");
    }

    ret = id2_client_test_get_secret();
    if (ret < 0) {
        ID2_DBG_LOG("=================>ID2 Client Test Get Secret Fail.\n\n");
        return -1;
    } else {
        ID2_DBG_LOG("=================>ID2 Client Test Get Secret Pass.\n\n");
    }

    ret = id2_client_test_derive_key();
    if (ret < 0) {
        ID2_DBG_LOG("=================>ID2 Client Test Derive Key Fail.\n\n");
        return -1;
    } else {
        ID2_DBG_LOG("=================>ID2 Client Test Derive Key Pass.\n\n");
    }

    return 0;
}
