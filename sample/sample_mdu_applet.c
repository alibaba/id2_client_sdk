/*
 * Copyright (C) 2018-2020 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "ls_osa.h"
#include "id2_client.h"

#define IOT_ID2_ID_INIT                  0
#define IOT_ID2_ID_CLEANUP               1
#define IOT_ID2_ID_GET_VERSION           2
#define IOT_ID2_ID_GET_ID                3
#define IOT_ID2_ID_GET_CHALLENGE_CODE    4
#define IOT_ID2_ID_GET_TIMESTAMP_CODE    5
#define IOT_ID2_ID_DECRYPT               6
#define IOT_ID2_ID_VERIFY_SERVER         7
#define IOT_ID2_ID_GET_SECRET            8
#define IOT_ID2_ID_DERIVE_KEY            9
#define IOT_ID2_ID_GET_PROV_STAT         10
#define IOT_ID2_ID_GET_OTP_CODE          11
#define IOT_ID2_ID_LOAD_OTP_DATA         12

#define ID2_SOCKET_PATH            "/var/tmp/id2_mdu_sample"
#define ID2_SOCKET_LISTEN_NUM      4

#define ID2_LOG(_f, ...)           ls_osa_print("%s %d: " _f, \
                                          __FUNCTION__, __LINE__, ##__VA_ARGS__)

/* big endian */
#define UINT32_TO_BIN(data, buf)   do {  \
                                       buf[0] = (data & 0xFF000000) >> 24;  \
                                       buf[1] = (data & 0x00FF0000) >> 16;  \
                                       buf[2] = (data & 0x0000FF00) >> 8;   \
                                       buf[3] = (data & 0x000000FF);        \
                                   } while(0);

#define BIN_TO_UINT32(buf)         (((uint8_t *)buf)[0] << 24) |  \
                                   (((uint8_t *)buf)[1] << 16) |  \
                                   (((uint8_t *)buf)[2] << 8) |   \
                                   (((uint8_t *)buf)[3] << 0)

#define ID2_MSG_HEAD_MAGIC        0x1234

typedef struct {
    uint32_t magic;
    uint32_t size;
    uint32_t cmd_id;
    int32_t stat;
} ls_msg_head_t;

static uint8_t * _wait_for_request_message(int sockfd)
{
    int ret = 0;
    uint8_t *msg_buf;
    uint32_t msg_size;
    ls_msg_head_t head;

    ret = (int)read(sockfd, &head, sizeof(ls_msg_head_t));
    if (ret == 0) {
        ID2_LOG("peer has closed socket!!\n");
        return NULL;
    } else if (ret != sizeof(ls_msg_head_t)) {
        ID2_LOG("receive message head fail\n");
        return NULL;
    }

    if (head.magic != ID2_MSG_HEAD_MAGIC) {
        ID2_LOG("invalid message magic, %d\n", head.magic);
        return NULL;
    }

    msg_size = sizeof(ls_msg_head_t) + head.size;
    msg_buf = ls_osa_malloc(msg_size);
    if (msg_buf == NULL) {
        ID2_LOG("out of mem, %d\n", msg_size);
        return NULL;
    }

    memcpy(msg_buf, &head, sizeof(ls_msg_head_t));

    if (head.size > 0) {
        ret = (int)read(sockfd, msg_buf + sizeof(ls_msg_head_t), head.size);
        if (ret < 0) {
            if (errno == ECONNRESET) {
                ID2_LOG("socket is reset by peer\n");
                goto _out;
            } else {
                ID2_LOG("socket read fail - errno: %d\n", errno);
                goto _out;
           }
        } else if (ret != head.size) {
            ID2_LOG("read message body fail\n");
            ret = -1;
            goto _out;
        }
    }

    ret = 0;

_out:
    if (ret < 0) {
        if (msg_buf != NULL) {
            ls_osa_free(msg_buf);
            msg_buf = NULL;
        }
    }

    return msg_buf;
}

static int _send_response_message(int sockfd, uint8_t *buf, uint32_t size)
{
    int ret = 0;

    ret = (int32_t)write(sockfd, buf, size);
    if (ret < 0) {
        if (errno == ECONNRESET) {
            ID2_LOG("socket is reset by peer\n");
        } else {
            ID2_LOG("socket send fail - errno: %d\n", errno);
            ret = -errno;
        }
    }

    return ret;
}

int mdu_applet_process_request_message(int handle, ls_msg_head_t *req_msg)
{
    int result = 0;
    uint32_t offset = 0;
    uint32_t msg_size = 0;
    ls_msg_head_t err_msg;
    ls_msg_head_t *rsp_msg = NULL;

    if (req_msg == NULL) {
        ID2_LOG("invalid input arg\n");
        return IROT_ERROR_GENERIC;
    }

    ID2_LOG("request message - command id: %d\n", req_msg->cmd_id);

    switch(req_msg->cmd_id) {
        case IOT_ID2_ID_INIT: {

            result = id2_client_init();
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_init fail, %d\n", result);
                goto _out;
            }

            msg_size = 0;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;
            }

            break;
        }

        case IOT_ID2_ID_CLEANUP: {

            result = id2_client_cleanup();
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_cleanup fail, %d\n", result);
                goto _out;
            }

            msg_size = 0;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;
            }

            break;
        }

        case IOT_ID2_ID_GET_VERSION: {
            uint32_t version;

            result = id2_client_get_version(&version);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_get_version fail, %d\n", result);
                goto _out;
            }

            msg_size = 4;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(version, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
            }

            break;
        }

        case IOT_ID2_ID_GET_ID: {
            uint32_t id_len = ID2_ID_MAX_LEN;
            uint8_t id_buf[ID2_ID_MAX_LEN + 1] = {0};

            result = id2_client_get_id(id_buf, &id_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_get_id fail, %d\n", result);
                goto _out;
            }

            msg_size = 4 + id_len;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(id_len, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
                memcpy((uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, id_buf, id_len);
            }

            break;
        }

        case IOT_ID2_ID_GET_CHALLENGE_CODE: {
            uint32_t random_len;
            uint32_t extra_len;
            uint32_t auth_code_len;
            uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN];
            uint8_t server_random[ID2_MAX_SERVER_RANDOM_LEN + 1] = {0};
            uint8_t *extra = NULL;

            offset = sizeof(ls_msg_head_t);
            random_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            if (random_len > ID2_MAX_SERVER_RANDOM_LEN) {
                ID2_LOG("server random len exceed limit, %d\n", random_len);
                result = IROT_ERROR_EXCESS_DATA;
                goto _out;
            } else {
                memcpy(server_random, (uint8_t *)req_msg + offset, random_len);
                offset += random_len;
            }

            extra_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            if (extra_len > ID2_MAX_EXTRA_LEN) {
                ID2_LOG("extra len exceed limit, %d\n", extra_len);
                result = IROT_ERROR_EXCESS_DATA;
                goto _out;
            } else {
                if (extra_len != 0) {
                    extra = (uint8_t *)req_msg + offset;
                }
            }

            auth_code_len = ID2_MAX_AUTH_CODE_LEN;
            result = id2_client_get_challenge_auth_code(
                                 (char *)server_random,
                                 extra, extra_len, auth_code, &auth_code_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_get_challenge_auth_code fail, %d\n", result);
                goto _out;
            }

            msg_size = 4 + auth_code_len;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(auth_code_len, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
                memcpy((uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, auth_code, auth_code_len);
            }

            break;
        }

        case IOT_ID2_ID_GET_TIMESTAMP_CODE: {
            uint32_t ts_len;
            uint32_t extra_len;
            uint32_t auth_code_len;
            uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN];
            uint8_t timestamp[ID2_MAX_SERVER_RANDOM_LEN + 1] = {0};
            uint8_t *extra = NULL;

            offset = sizeof(ls_msg_head_t);
            ts_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            if (ts_len > ID2_MAX_SERVER_RANDOM_LEN) {
                ID2_LOG("timestamp len exceed limit, %d\n", ts_len);
                result = IROT_ERROR_EXCESS_DATA;
                goto _out;
            } else {
                memcpy(timestamp, (uint8_t *)req_msg + offset, ts_len);
                offset += ts_len;
            }

            extra_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            if (extra_len > ID2_MAX_EXTRA_LEN) {
                ID2_LOG("extra len exceed limit, %d\n", extra_len);
                result = IROT_ERROR_EXCESS_DATA;
                goto _out;
            } else {
                if (extra_len != 0) {
                    extra = (uint8_t *)req_msg + offset;
                }
            }

            auth_code_len = ID2_MAX_AUTH_CODE_LEN;
            result = id2_client_get_challenge_auth_code(
                             (char *)timestamp,
                             extra, extra_len, auth_code, &auth_code_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_get_challenge_auth_code fail, %d\n", result);
                goto _out;
            }

            msg_size = 4 + auth_code_len;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(auth_code_len, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
                memcpy((uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, auth_code, auth_code_len);
            }

            break;
        }

        case IOT_ID2_ID_DECRYPT: {
            uint32_t in_len;
            uint32_t out_len;
            uint8_t *in_data = NULL;
            uint8_t *out_data = NULL;

            offset = sizeof(ls_msg_head_t);
            in_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            in_data = (uint8_t *)req_msg + offset;

            out_len = in_len;
            out_data = ls_osa_malloc(out_len);
            if (out_data == NULL) {
                ID2_LOG("out of mem, %d\n", out_len);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            }

            result = id2_client_decrypt(in_data, in_len, out_data, &out_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_decrypt fail, %d\n", result);
                ls_osa_free(out_data);
                goto _out;
            }

            msg_size = 4 + out_len;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                ls_osa_free(out_data);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(out_len, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
                memcpy((uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, out_data, out_len);
            }

            ls_osa_free(out_data);

            break;
        }

        case IOT_ID2_ID_VERIFY_SERVER: {
            uint32_t offset;
            uint32_t auth_code_len;
            uint32_t device_random_len;
            uint32_t server_extra_len;
            uint8_t *auth_code = NULL;
            uint8_t *device_random = NULL;
            uint8_t *server_extra = NULL;

            offset = sizeof(ls_msg_head_t);
            auth_code_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            auth_code = (uint8_t *)req_msg + offset;
            offset += auth_code_len;

            device_random_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            device_random = (uint8_t *)req_msg + offset;
            offset += device_random_len;

            server_extra_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            if (server_extra_len != 0) {
                server_extra = ((uint8_t *)req_msg + offset);
            }

            result = id2_client_verify_server(auth_code, auth_code_len,
                         device_random, device_random_len, server_extra, server_extra_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_verify_server fail, %d\n", result);
                goto _out;
            }

            msg_size = 0;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;
            }

            break;
        }

        case IOT_ID2_ID_GET_SECRET: {
            uint32_t seed_len;
            uint32_t secret_len;
            uint8_t seed[ID2_MAX_SEED_LEN + 1] = {0};
            uint8_t secret[ID2_DERIV_SECRET_LEN];

            offset = sizeof(ls_msg_head_t);
            seed_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            if (seed_len > ID2_MAX_SEED_LEN) {
                ID2_LOG("seed length exceed limit, %d\n", seed_len);
                result = IROT_ERROR_EXCESS_DATA;
                goto _out;
            } else {
                memcpy(seed, (uint8_t *)req_msg + offset, seed_len);
            }

            secret_len = ID2_DERIV_SECRET_LEN;
            result = id2_client_get_secret((char *)seed, secret, &secret_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_get_secret fail, %d\n", result);
                goto _out;
            }

            msg_size = 4 + secret_len;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(secret_len, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
                memcpy((uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, secret, secret_len);
            }

            break;
        }

        case IOT_ID2_ID_DERIVE_KEY: {
            uint32_t seed_len;
            uint32_t key_len;
            uint8_t seed[ID2_MAX_SEED_LEN + 1] = {0};
            uint8_t key[ID2_DERIV_KEY_LEN];

            offset = sizeof(ls_msg_head_t);
            seed_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            memcpy(seed, (uint8_t *)req_msg + offset, seed_len);
            offset += seed_len;
            key_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);

            result = id2_client_derive_key((char *)seed, key, key_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_derive_key fail, %d\n", result);
                goto _out;
            }

            msg_size = 4 + key_len;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(key_len, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
                memcpy((uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, key, key_len);
            }

            break;
        }

        case IOT_ID2_ID_GET_PROV_STAT: {
            bool is_prov;

            result = id2_client_get_prov_stat(&is_prov);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_get_prov_stat fail, %d\n", result);
                goto _out;
            }

            msg_size = 4;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(is_prov, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
            }

            break;
        }

        case IOT_ID2_ID_GET_OTP_CODE: {
            uint32_t token_len;
            uint32_t auth_code_len;
            uint8_t *token;
            uint8_t auth_code[ID2_MAX_AUTH_CODE_LEN];

            offset = sizeof(ls_msg_head_t);
            token_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            token = (uint8_t *)req_msg + offset;

            auth_code_len = ID2_MAX_AUTH_CODE_LEN;
            result = id2_client_get_otp_auth_code(token, token_len, auth_code, &auth_code_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_get_otp_auth_code fail, %d\n", result);
                goto _out;
            }

            msg_size = 4 + auth_code_len;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;

                UINT32_TO_BIN(auth_code_len, ((uint8_t *)rsp_msg + sizeof(ls_msg_head_t)));
                memcpy((uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, auth_code, auth_code_len);
            }

            break;
        }

        case IOT_ID2_ID_LOAD_OTP_DATA: {
            uint32_t otp_data_len;
            uint8_t *otp_data;

            offset = sizeof(ls_msg_head_t);
            otp_data_len = BIN_TO_UINT32((uint8_t *)req_msg + offset);
            offset += 4;
            otp_data = (uint8_t *)req_msg + offset;

            result = id2_client_load_otp_data(otp_data, otp_data_len);
            if (result != IROT_SUCCESS) {
                ID2_LOG("id2_client_load_otp_data fail, %d\n", result);
                goto _out;
            }

            msg_size = 0;
            rsp_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
            if (rsp_msg == NULL) {
                ID2_LOG("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
                result = IROT_ERROR_OUT_OF_MEMORY;
                goto _out;
            } else {
                rsp_msg->magic = ID2_MSG_HEAD_MAGIC;
                rsp_msg->size = msg_size;
                rsp_msg->cmd_id = req_msg->cmd_id;
                rsp_msg->stat = IROT_SUCCESS;
            }

            break;
        }

        default:
            ID2_LOG("not support this command id, %d\n", req_msg->cmd_id);
            result = IROT_ERROR_NOT_SUPPORTED;
            goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (rsp_msg != NULL) {
        result = _send_response_message(handle,
                       (uint8_t *)rsp_msg, sizeof(ls_msg_head_t) + rsp_msg->size);
        if (result < 0) {
            ID2_LOG("send response message fail\n");
            ls_osa_free(rsp_msg);
            return IROT_ERROR_GENERIC;
        }

        ls_osa_free(rsp_msg);
    } else {
        err_msg.magic = ID2_MSG_HEAD_MAGIC;
        err_msg.size = 0;
        err_msg.cmd_id = req_msg->cmd_id;
        err_msg.stat = result;

        result = _send_response_message(handle,
                       (uint8_t *)&err_msg, sizeof(ls_msg_head_t));
        if (result < 0) {
            ID2_LOG("send response message fail\n");
            return IROT_ERROR_GENERIC;
        }
    }

    return IROT_SUCCESS;
}

int main()
{
    int ret = 0;
    int server_fd = -1;
    int client_fd = -1;
    struct sockaddr_un saddr;
    ls_msg_head_t *req_msg = NULL;

    ID2_LOG("ID2 Server proc enter.\n");

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        ID2_LOG("socket create fail\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    sprintf(saddr.sun_path, "%s", ID2_SOCKET_PATH);
    unlink(saddr.sun_path);

    ret = bind(server_fd, (struct sockaddr *)&saddr, sizeof(saddr));
    if (ret < 0) {
        ID2_LOG("socket bind fail - errno: %d\n", errno);
        goto _out;
    }

    ret = listen(server_fd, ID2_SOCKET_LISTEN_NUM);
    if (ret < 0) {
        ID2_LOG("socket listen fail - errno: %d\n", errno);
        goto _out;
    }

_sock_reset:
    if (client_fd > 0) {
        shutdown(client_fd, 2);
        close(client_fd);
    }

    ID2_LOG("waiting for client connection ...\n");

    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        ID2_LOG("accept socket fail - errno: %d\n", errno);
        goto _out;
    }

    do {
        if (req_msg != NULL) {
            ls_osa_free(req_msg);
        }

        req_msg = (ls_msg_head_t *)_wait_for_request_message(client_fd);
        if (req_msg == NULL) {
            ID2_LOG("wait for request message fail\n");
            goto _sock_reset;
        }

        ret = mdu_applet_process_request_message(client_fd, req_msg);
        if (ret != IROT_SUCCESS) {
            ID2_LOG("mdu applet proccess request message fail\n");
            goto _out;
        }
    } while(1);

_out:
    ID2_LOG("ID2 Server proc exit.\n");

    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }

    if (server_fd > 0) {
        shutdown(server_fd, 2);
        close(server_fd);
    }
    if (client_fd > 0) {
        shutdown(client_fd, 2);
        close(client_fd);
    }

    return ret;
}

