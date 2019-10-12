/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "id2_test.h"

/* parameters for id2 authcode */
#define ID2_CHALLENGE       "55B83408399FA660F05C82E4F25333DC"
#define ID2_TIMESTAMP       "1512022279204"
#define ID2_EXTRA           "abcd1234"

#define ID2_REPORT_VERSION      "1.0.0"

#define ID2_JSON_MESSAGE  \
"{\n\
    \"reportVersion\":  \"%s\",\n\
    \"sdkVersion\":  \"%s\",\n\
    \"date\":  \"%s\",\n\
    \"testContent\":  [{\n\
                      \"api\":  \"id2_client_get_id\",\n\
                      \"args\": {\n\
                      },\n\
                      \"result\":  \"%s\"\n\
             }, {\n\
                     \"api\":  \"id2_client_get_challenge_auth_code\",\n\
                     \"args\": {\n\
                              \"challenge\":  \"%s\",\n\
                              \"extra\":      \"%s\"\n\
                     },\n\
                     \"result\": \"%s\"\n\
             }, {\n\
                     \"api\":  \"id2_client_get_timestamp_auth_code\",\n\
                     \"args\": {\n\
                              \"timestamp\":  \"%s\",\n\
                              \"extra\":      \"%s\"\n\
                     },\n\
                     \"result\": \"%s\"\n\
             }]\n\
}"

static uint8_t id2_id[ID2_ID_LEN + 1] = {0};
static uint8_t auth_code_challenge[ID2_AUTH_CODE_BUF_LEN] = {0};
static uint8_t auth_code_timestamp[ID2_AUTH_CODE_BUF_LEN] = {0};

static int _char_to_hex(char c)
{
    int hex = -1;

    if (c >= '0' && c <= '9') {
        hex = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        hex = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        hex = c - 'A' + 10;
    }

    return hex;
}

static int _string_to_hex(char *str, uint32_t str_len, uint8_t *hex, uint32_t hex_len)
{
    size_t i;
    uint8_t h, l;

    if (str_len % 2 != 0) {
        ID2_DBG_LOG("invalid string length, %d\n", str_len);
        return -1;
    }

    if (hex_len * 2 < str_len) {
        return -1;
    }

    for (i = 0; i < str_len; i += 2) {
        h = _char_to_hex(str[i]);
        l = _char_to_hex(str[i + 1]);
        if (h < 0 || l < 0) {
            return -1;
        }

        hex[i >> 1] = (h << 4) | (l & 0x0F);
    }

    return 0;
}

int id2_client_generate_authcode(void)
{
    int ret = 0;
    char *message = NULL;
    char vers_str[32] = {0};
    char date_str[32] = {0};
    uint32_t version = 0;
    uint32_t message_len = 0;
    uint32_t ver_max, ver_mid, ver_min;
    uint32_t id2_len = ID2_ID_LEN;
    uint32_t auth_code_len = ID2_AUTH_CODE_BUF_LEN;

    ID2_DBG_LOG("====> ID2 Client Generate AuthCode Start.\n");

    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        return -1;
    }

    ret = id2_client_get_version(&version);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client get version fail, %d\n", ret);
        return -1;
    }

    ver_max = (version >> 16) & 0xFF;
    ver_mid = (version >>  8) & 0xFF;
    ver_min = (version >>  0) & 0xFF;
    ls_osa_snprintf(vers_str, 32, "%d.%d.%d", ver_max, ver_mid, ver_min);
    ls_osa_snprintf(date_str, 32, "%s %s", __DATE__, __TIME__);

    message_len = strlen(ID2_JSON_MESSAGE) + 16 + 32 + 32;

    ret = id2_client_get_id(id2_id, &id2_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 get id fail, %d\n", ret);
        ret = -1;
        goto _out;
    }
    message_len += id2_len;

    ret = id2_client_get_challenge_auth_code(ID2_CHALLENGE,
              (uint8_t *)ID2_EXTRA, strlen(ID2_EXTRA), auth_code_challenge, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 get challenge auth code fail, %d\n", ret);
        ret = -1;
        goto _out;
    }
    message_len += auth_code_len;

    auth_code_len = ID2_AUTH_CODE_BUF_LEN;
    ret = id2_client_get_timestamp_auth_code(ID2_TIMESTAMP,
              (uint8_t *)ID2_EXTRA, strlen(ID2_EXTRA), auth_code_timestamp, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 get timestamp auth code fail, %d\n", ret);
        ret = -1;
        goto _out;
    }
    message_len += auth_code_len;

    message = ls_osa_malloc(message_len);
    if (message == NULL) {
        ID2_DBG_LOG("out of mem, %d\n", message_len);
        ret = -1;
        goto _out;
    }

    ret = ls_osa_snprintf(message, message_len, ID2_JSON_MESSAGE,
                          ID2_REPORT_VERSION, vers_str, date_str,
                          id2_id,
                          ID2_CHALLENGE, ID2_EXTRA, auth_code_challenge,
                          ID2_TIMESTAMP, ID2_EXTRA, auth_code_timestamp);
    if (ret < 0) {
        ID2_DBG_LOG("id2 json message generation fail\n");
        goto _out;
    }

    ID2_DBG_LOG("\n\n============ ID2 Validation Json Message ============:\n%s\n\n", message);

_out:
    if (message != NULL) {
        ls_osa_free(message);
    }

    id2_client_cleanup();

    if (ret < 0) {
        ID2_DBG_LOG("=====>ID2 Client Generate AuthCode Fail.\n\n");
        return -1;
    } else {
        ID2_DBG_LOG("=====>ID2 Client Generate AuthCode End.\n\n");
    }

    return ret;
}

int id2_client_decrypt_data(char *cipher_data, uint32_t cipher_len)
{
    int ret = 0;
    uint32_t hex_len = 0;
    uint32_t out_len = 0;
    uint32_t id2_len = 0;
    uint8_t *hex_data = NULL;
    uint8_t out_data[ID2_ID_LEN + 1] = {0};
    uint8_t id2_data[ID2_ID_LEN + 1] = {0};

    ID2_DBG_LOG("====> ID2 Client Test Decrypt Start.\n");

    if (cipher_data == NULL || cipher_len < ID2_ID_LEN) {
        ID2_DBG_LOG("invalid input args\n");
        return -1;
    }

    hex_len = cipher_len >> 1;
    hex_data = ls_osa_malloc(hex_len);
    if (NULL == hex_data) {
        ID2_DBG_LOG("out of mem, %d\n", cipher_len);
        return -1;
    }

    ret = _string_to_hex(cipher_data, cipher_len, hex_data, hex_len);
    if (ret < 0) {
        ID2_DBG_LOG("string to hex fail\n");
        goto _out;
    }

    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 client init fail, %d\n", ret);
        ret = -1;
        goto _out;
    }

    id2_len = ID2_ID_LEN;
    ret = id2_client_get_id(id2_data, &id2_len);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2 get id fail, %d\n", ret);
        ret = -1;
        goto _out;
    }

    out_len = ID2_ID_LEN;
    ret = id2_client_decrypt(hex_data, hex_len, out_data, &out_len);
    if (ret != IROT_SUCCESS || out_len != ID2_ID_LEN) {
        ID2_DBG_LOG("id2 client decrypt fail, %d %d\n", ret, out_len);
        ret = -1;
        goto _out;
    }

    if (memcmp(id2_data, out_data, ID2_ID_LEN)) {
        ID2_DBG_LOG("plaintext data is error\n");
        ret = -1;
        goto _out;
    }

    ret = 0;

_out:
    if (hex_data != NULL) {
        ls_osa_free(hex_data);
    }

    if (ret < 0) {
        ID2_DBG_LOG("=================>ID2 Client Test Decrypt Fail.\n\n");
        return -1;
    } else {
        ID2_DBG_LOG("=================>ID2 Client Test Decrypt Pass.\n\n");
    }

    return ret;
}
