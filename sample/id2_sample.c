/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#include "ls_osa.h"
#include "id2_client.h"

/* id2 product identifier and secret, getting from id2 console */
#define PRODUCT_KEY     "XXXXXXXXXX"
#define PRODUCT_SECRET  "i11XXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

enum {
    ID2_CMD_KEY_PROVISION        = 1,    /* id2 one-time provisioning command */
    ID2_CMD_GET_CHALLENGE        = 2,    /* id2 get server challenge command */
    ID2_CMD_DEV_AUTH             = 3,    /* id2 device identify authetication command */
    ID2_CMD_DEV_AUTH_AND_DECRYPT = 4     /* id2 device identify authentication and decryption command */
};

typedef struct _id2_info_t {
    uint8_t id2_cmd;                               /* app pre-defined id2 request command to service provider(SP) */
    char *product_key;                             /* id2 product identifier */
    char id2_id[ID2_ID_MAX_LEN + 1];               /* id2 unique id, which is string format */
    char challenge[ID2_MAX_SERVER_RANDOM_LEN + 1]; /* id2 server random string, using to generate device identify authcode */
    char auth_code[ID2_MAX_AUTH_CODE_LEN + 1];     /* id2 device authcode string, using for id2 provisioning or device identify */
    char otp_data[ID2_MAX_OTP_DATA_LEN + 1];       /* id2 provisioning data, getting from id2 server, base64 encoded */
    char cipher_data[ID2_MAX_CRYPT_LEN + 1];       /* id2 cipher data, base64 encoded */
} id2_info_t;

static int _id2_demo_send_request_and_wait_for_response(id2_info_t *info)
{
    if (info == NULL) {
        ls_osa_print("info is null\n");
        return -1;
    }

    switch(info->id2_cmd) {
    case ID2_CMD_KEY_PROVISION: {
         
        /* send id2 request{command, product_key, otp_auth_code} to SP server */

        /* receive id2 response{command, result, otp_data}, saving otp_data into info.otp_data if result is success */

        break;
    }

    case ID2_CMD_GET_CHALLENGE: {

        /* send id2 request{command, product_key, id2_id} to SP server */

        /* receive id2 response{command, result, challenge}, saving challenge into info.challenge if result is success */

        break;
    }

    case ID2_CMD_DEV_AUTH: {
        /* send id2 request{command, product_key, id2_id, dev_auth_code} to SP server */

        /* receive id2 response{command_id, result}, return 0 if result is success */

        break;
    }

    case ID2_CMD_DEV_AUTH_AND_DECRYPT: {
        /* send id2 request{command, product_key, id2_id, dev_auth_code} to SP server */

        /* receive id2 response{command_id, result, cipher_data}, saving cipher_data into info.cipher_data if result is success */

        break;
    }

    default:
        ls_osa_print("not support this command, %d\n", info->id2_cmd);
        return -1;
    }

    return 0;
}

static int _id2_demo_base64_encode(uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len)
{
    uint32_t o_len = o_len = 4 * ((in_len + 2) / 3);

    if (in == NULL || in_len == 0 || out == NULL || out_len == NULL) {
        return -1;
    }

    if (*out_len < o_len) {
        ls_osa_print("short buffer, %d %d\n", *out_len, o_len);
        return -1;
    }

    *out_len = o_len;

    /* TODO base64 encode algorithm */

    return 0;
}

static int _id2_demo_base64_decode(uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len)
{
    uint32_t o_len = in_len / 4 * 3;;

    if (in == NULL || in_len == 0 || out == NULL || out_len == NULL) {
        return -1;
    }

    if (*out_len < o_len) {
        ls_osa_print("short buffer, %d %d\n", *out_len, o_len);
        return -1;
    }

    *out_len = o_len;

    /* TODO base64 decode algorithm */

    return 0;
}

/*
 * execute device id2 one-time provisioning through id2 server directly
 */
int id2_sample_do_provisioning(char *product_key, char *product_secret, uint32_t timeout_ms)
{
    int ret;
    const char *host = "itls.cn-shanghai.aliyuncs.com";
    uint32_t port = 1883;

    /* 1. id2 client init */
    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client init fail, %d\n", ret);
        return -1;
    }

    /* 2. check if id2 has been provisioned or not, if not, request id2 from itls server */
    ret = id2_client_wrap_do_provisioning(host,
                     port, product_key, product_secret, timeout_ms);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client do provisioning fail, %d\n", ret);
        goto _out;
    }

_out:
    /* 3. id2 client cleanup */
    id2_client_cleanup();

    if (ret == IROT_SUCCESS) {
        return 0;
    } else {
        return -1;
    }
}

/*
 * execute device id2 one-time provisioning through server provider server, and then SP call id2 server api
 */
int id2_sample_process_provisioning(char *product_key, char *product_secret)
{
    int ret = IROT_SUCCESS;
    bool is_prov = false;
    uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN];
    uint32_t auth_code_len;
    uint8_t *otp_data = NULL;
    uint32_t tmp_len;
    id2_info_t info;

    /* 1. id2 client init */
    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client init fail, %d\n", ret);
        return -1;
    }

    /* 2. get id2 client prov status */
    ret = id2_client_get_prov_stat(&is_prov);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client get prov stat fail, %d\n", ret);
        goto _out;
    }
    if (is_prov == true) {
        ls_osa_print("id2 has been provisioned\n");
        ret = IROT_SUCCESS;
        goto _out;
    }

    /* 3. get id2 one-time provisioning authentication code */
    auth_code_len = ID2_MAX_AUTH_CODE_LEN;
    ret = id2_client_get_otp_auth_code(
                     (uint8_t *)product_secret, (int)strlen(product_secret),
                     auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2_client_get_otp_auth_code fail, %d\n", ret);
        goto _out;
    }

    /* 4. send id2 provisioning request to service provider server, and wait for response */
    memset(&info, 0, sizeof(id2_info_t));
    info.id2_cmd = ID2_CMD_KEY_PROVISION;
    info.product_key = product_key;

    /* convertid2 otp authcode to base64 encoded */
    tmp_len = ID2_MAX_AUTH_CODE_LEN;
    ret = _id2_demo_base64_encode(auth_code, auth_code_len, (uint8_t *)info.otp_data, &tmp_len);
    if (ret != 0) {
        ls_osa_print("base64 encode fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }
    ret = _id2_demo_send_request_and_wait_for_response(&info);
    if (ret != 0) {
        ls_osa_print("send request and wait for response fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }


    /* 5. load the id2 otp data into km reserved partition */

    /* convert id2 otp data to hexadecimal */
    tmp_len = strlen(info.otp_data);
    otp_data = ls_osa_malloc(tmp_len);
    if (otp_data == NULL) {
        ls_osa_print("out of mem, %d\n", tmp_len);
        ret = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    }
    ret = _id2_demo_base64_decode((uint8_t *)info.otp_data,
                    (int)strlen(info.otp_data), otp_data, &tmp_len);
    if (ret != 0) {
        ls_osa_print("base64 decode fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }
    ret = id2_client_load_otp_data(otp_data, tmp_len);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 load otp data fail, %d\n", ret);
        goto _out;
    }

_out:
    /* 6. id2 client cleanup */
    id2_client_cleanup();

    if (otp_data != NULL) {
        ls_osa_free(otp_data);
    }

    if (ret == IROT_SUCCESS) {
        return 0;
    } else {
        return -1;
    }
}

/*
 * execute id2 device identify authentication through server provider server
 */
int id2_sample_device_identify_authentication(char *product_key)
{
    int ret = IROT_SUCCESS;
    uint8_t id2_id[ID2_ID_MAX_LEN];
    uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN];
    uint32_t id2_id_len = ID2_ID_MAX_LEN;
    uint32_t auth_code_len = ID2_MAX_AUTH_CODE_LEN;
    id2_info_t info;

    /* 1. id2 client init */
    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client init fail, %d\n", ret);
        return -1;
    }

    /* 2. get id2 id */
    ret = id2_client_get_id(id2_id, &id2_id_len);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client get id fail, %d\n", ret);
        goto _out;
    }

    /* 3. send id2 get challenge request to service provider server, and wait for response */
    memset(&info, 0, sizeof(id2_info_t));
    info.id2_cmd = ID2_CMD_GET_CHALLENGE;
    info.product_key = product_key;
    memcpy(info.id2_id, id2_id, id2_id_len);
    ret = _id2_demo_send_request_and_wait_for_response(&info);
    if (ret != 0) {
        ls_osa_print("send request and wait for response fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    /* 4. get id2 device identify authentication code */
    ret = id2_client_get_challenge_auth_code(info.challenge,
                                   NULL, 0, auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client get challenge auth code fail, %d\n", ret);
        goto _out;
    }

    /* 5. send id2 identity authentication request to service provider server, and wait for response */
    memset(&info, 0, sizeof(id2_info_t));
    info.id2_cmd = ID2_CMD_DEV_AUTH;
    info.product_key = product_key;
    memcpy(info.id2_id, id2_id, id2_id_len);
    memcpy(info.auth_code, auth_code, auth_code_len);
    ret = _id2_demo_send_request_and_wait_for_response(&info);
    if (ret != 0) {
        ls_osa_print("send request and wait for response fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

_out:
    /* 6. id2 client cleanup */
    id2_client_cleanup();

    if (ret == IROT_SUCCESS) {
        return 0;
    } else {
        return -1;
    }
}

/*
 * execute id2 device identify authentication and issue id2 encrypted cipher data through service provider server
 */
int id2_sample_device_identify_authentication_and_decryption(char *product_key)
{
    int ret = IROT_SUCCESS;
    uint8_t id2_id[ID2_ID_MAX_LEN];
    uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN];
    uint32_t id2_id_len = ID2_ID_MAX_LEN;
    uint32_t auth_code_len = ID2_MAX_AUTH_CODE_LEN;
    uint8_t *tmp_data = NULL;
    uint32_t tmp_len;
    id2_info_t info;

    /* 1. id2 client init */
    ret = id2_client_init();
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client init fail, %d\n", ret);
        return -1;
    }

    /* 2. get id2 id */
    ret = id2_client_get_id(id2_id, &id2_id_len);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client get id fail, %d\n", ret);
        goto _out;
    }

    /* 3. send id2 get challenge request to service provider server, and wait for response */
    memset(&info, 0, sizeof(id2_info_t));
    info.id2_cmd = ID2_CMD_GET_CHALLENGE;
    info.product_key = product_key;
    memcpy(info.id2_id, id2_id, id2_id_len);
    ret = _id2_demo_send_request_and_wait_for_response(&info);
    if (ret != 0) {
        ls_osa_print("send request and wait for response fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    /* 4. get id2 device identify authentication code */
    ret = id2_client_get_challenge_auth_code(
                         info.challenge, NULL, 0,
                         auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client get challenge auth code fail, %d\n", ret);
        goto _out;
    }

    /* 5. send id2 identity authentication and decryption request to service provider server, and wait for response */
    memset(&info, 0, sizeof(id2_info_t));
    info.id2_cmd = ID2_CMD_DEV_AUTH;
    info.product_key = product_key;
    memcpy(info.id2_id, id2_id, id2_id_len);
    memcpy(info.auth_code, auth_code, auth_code_len);
    ret = _id2_demo_send_request_and_wait_for_response(&info);
    if (ret != 0) {
        ls_osa_print("send request and wait for response fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }

    /* 6. decrypt id2 cipher data */

    /* convert id2 cipher data to hexadecimal */
    tmp_len = (int)strlen(info.cipher_data);
    tmp_data = ls_osa_malloc(tmp_len);
    if (tmp_data == NULL) {
        ls_osa_print("out of mem, %d\n", tmp_len);
        ret = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    }
    ret = _id2_demo_base64_decode((uint8_t *)info.cipher_data, tmp_len, tmp_data, &tmp_len);
    if (ret != 0) {
        ls_osa_print("base64 decode fail\n");
        ret = IROT_ERROR_GENERIC;
        goto _out;
    }
    ret = id2_client_decrypt(tmp_data, tmp_len, tmp_data, &tmp_len);
    if (ret != IROT_SUCCESS) {
        ls_osa_print("id2 client decrypt fail\n");
        goto _out;
    }

_out:
    /* 7. id2 client cleanup */
    id2_client_cleanup();

    if (ret == IROT_SUCCESS) {
        return 0;
    } else {
        return -1;
    }
}

int main(void)
{
    int ret = 0;
    uint32_t timeout_ms = 2000;

    ret = id2_sample_do_provisioning(PRODUCT_KEY, PRODUCT_SECRET, timeout_ms);
    if (ret < 0) {
        ls_osa_print("id2 do provisioning fail\n");
        return -1;
    }

    ret = id2_sample_process_provisioning(PRODUCT_KEY, PRODUCT_SECRET);
    if (ret < 0) {
        ls_osa_print("id2 process provisioning fail\n");
        return -1;
    }

    ret = id2_sample_device_identify_authentication(PRODUCT_KEY);
    if (ret < 0) {
        ls_osa_print("id2 device identify authentication fail\n");
        return -1;
    }

    ret = id2_sample_device_identify_authentication_and_decryption(PRODUCT_KEY);
    if (ret < 0) {
        ls_osa_print("id2 device identify authentication and decryption fail");
        return -1;
    }

    return 0;
}


