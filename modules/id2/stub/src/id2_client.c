/*
 * Copyright (C) 2018-2020 Alibaba Group Holding Limited
 */

#include "id2_priv.h"
#include "id2_client.h"

#define __DEMO__

#if defined(__DEMO__)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>

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

static uint8_t s_id2_id[ID2_ID_MAX_LEN + 1] = {0};
static uint8_t s_id2_id_len = 0;

static int sockfd = -1;

static int _id2_socket_connect(void)
{
    int ret;
    int fd = -1;
    int retry = 0;
    struct sockaddr_un saddr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        id2_log_error("socket create fail\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    sprintf(saddr.sun_path, "%s", ID2_SOCKET_PATH);

    do {
        ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
        if (ret < 0 &&
            errno != ENOENT &&
            errno != ENOTCONN && errno != ECONNREFUSED) {
            id2_log_error("socket connect fail - errno: %d\n", errno);
            goto _out;
        }

        usleep(1000);
    } while(ret < 0 && retry++ < 10);

    if (retry == 10) {
        id2_log_error("socket connect timeout\n");
        goto _out;
    }

_out:
    if (ret < 0) {
        shutdown(fd, 2);
        close(fd);
        fd = -1;
    }

    return fd;
}

static irot_result_t _send_request_message(uint8_t *buf, uint32_t size)
{
    int ret = 0;

    if (sockfd < 0) {
        id2_log_error("channel is not connected, %d\n", sockfd);
        return IROT_ERROR_GENERIC;
    } 

    ret = (int32_t)write(sockfd, buf, size);
    if (ret < 0) {
        if (errno == ECONNRESET) {
            id2_log_error("socket is reset by peer\n");
        } else {
            id2_log_error("socket send fail - errno: %d\n", errno);
        }

        return IROT_ERROR_GENERIC;
    }

    return IROT_SUCCESS;
}

static uint8_t * _wait_for_response_message(void)
{
    int ret = 0;
    uint8_t *msg_buf;
    uint32_t msg_size;
    ls_msg_head_t head;

    ret = (int)read(sockfd, &head, sizeof(ls_msg_head_t));
    if (ret == 0) {
        id2_log_error("peer has closed socket!!\n");
        return NULL;
    } else if (ret != sizeof(ls_msg_head_t)) {
        id2_log_error("receive message head fail\n");
        return NULL;
    }

    if (head.magic != ID2_MSG_HEAD_MAGIC) {
        id2_log_error("invalid message magic, %d\n", head.magic);
        return NULL;
    }

    msg_size = sizeof(ls_msg_head_t) + head.size;
    msg_buf = ls_osa_malloc(msg_size);
    if (msg_buf == NULL) {
        id2_log_error("out of mem, %d\n", msg_size);
        return NULL;
    }

    memcpy(msg_buf, &head, sizeof(ls_msg_head_t));

    if (head.size > 0) {
        ret = (int)read(sockfd, msg_buf + sizeof(ls_msg_head_t), head.size);
        if (ret < 0) {
            if (errno == ECONNRESET) {
                id2_log_error("socket is reset by peer\n");
                goto _out;
            } else {
                id2_log_error("socket read fail - errno: %d\n", errno);
                goto _out;
           }
        } else if (ret != head.size) {
            id2_log_error("read message body fail\n");
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

static void _dump_id2_conf_info(void)
{
    ls_osa_print("---------------------------------------------------------------\n");

    ls_osa_print("ID2 Client Stub For Module Build Time: %s %s\n", __DATE__, __TIME__);

#if defined(CONFIG_ID2_DEBUG)
    ls_osa_print("CONFIG_ID2_DEBUG is defined!\n");
#else
    ls_osa_print("CONFIG_ID2_DEBUG is not defined!\n");
#endif

    ls_osa_print("---------------------------------------------------------------\n");
}

irot_result_t id2_client_init(void)
{
    irot_result_t result;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_init enter.]\n");

    _dump_id2_conf_info();

    msg_size = 0;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        return IROT_ERROR_OUT_OF_MEMORY;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_INIT;
    }

    sockfd = _id2_socket_connect();
    if (sockfd < 0) {
        id2_log_error("id2 socket connect fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 init command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    if (result != IROT_SUCCESS) {
        if (sockfd > 0) {
            close(sockfd);
            sockfd = -1;
        }
    }

    return result;
}

irot_result_t id2_client_cleanup(void)
{
    irot_result_t result;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_cleanup enter.]\n");

    msg_size = 0;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_CLEANUP;
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 cleanup command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    if (sockfd > 0) {
        close(sockfd);
        sockfd = -1;
    }

    return result;
}

irot_result_t id2_client_get_version(uint32_t* version)
{
    irot_result_t result;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_get_version enter.]\n");

    if (version == NULL) {
        id2_log_error("invalid input arg.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    msg_size = 0;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_GET_VERSION;
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 get version return error, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size != 4) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    *version = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_get_id(uint8_t* id, uint32_t* len)
{
    irot_result_t result;
    uint32_t out_len;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_get_id enter.]\n");

    if (id == NULL || len == NULL) {
        id2_log_error("id or len is NULL.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    msg_size = 0;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_GENERIC;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_GET_ID;
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 get id command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size <= 4) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    out_len = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));
    if (*len < out_len) {
        id2_log_error("short buffer, %d %d\n", *len, out_len);
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    *len = out_len;
    memcpy(id, (uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, out_len);

    if (s_id2_id_len == 0) {
        s_id2_id_len = out_len;
        memcpy(s_id2_id, id, s_id2_id_len);
    }

    id2_log_info("ID2: %s\n", s_id2_id);

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_get_challenge_auth_code(const char* server_random,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t out_len;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_get_challenge_auth_code enter.]\n");

    if (auth_code == NULL || auth_code_len == NULL ||
        server_random == NULL) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (strlen(server_random) == 0 ||
        strlen(server_random) > ID2_MAX_SERVER_RANDOM_LEN) {
        id2_log_error("invalid server random length, %d.\n", strlen(server_random));
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (extra_len > ID2_MAX_EXTRA_LEN || (
        extra == NULL && extra_len != 0)) {
        id2_log_error("invalid extra data length, %d.\n", extra_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    msg_size = 4 + strlen(server_random) + 4 + extra_len;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_GET_CHALLENGE_CODE;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(strlen(server_random), ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, server_random, strlen(server_random));
    offset += strlen(server_random);

    UINT32_TO_BIN(extra_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    if (extra_len != 0) {
        memcpy((uint8_t *)req_msg + offset, extra, extra_len);
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 get challenge auth code command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size <= 4) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    out_len = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));
    if (*auth_code_len < out_len) {
        id2_log_error("short buffer, %d %d\n", *auth_code_len, out_len);
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    *auth_code_len = out_len;
    memcpy(auth_code, (uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, out_len);

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_get_timestamp_auth_code(const char* timestamp,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t out_len;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_get_timestamp_auth_code enter.]\n");

    if (auth_code == NULL || auth_code_len == NULL ||
        timestamp == NULL) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (strlen(timestamp) == 0 ||
        strlen(timestamp) > ID2_MAX_SERVER_RANDOM_LEN) {
        id2_log_error("invalid timestamp length, %d.\n", strlen(timestamp));
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (extra_len > ID2_MAX_EXTRA_LEN || (
        extra == NULL && extra_len != 0)) {
        id2_log_error("invalid extra data length, %d.\n", extra_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    msg_size = 4 + strlen(timestamp) + 4 + extra_len;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_GET_TIMESTAMP_CODE;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(strlen(timestamp), ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, timestamp, strlen(timestamp));
    offset += strlen(timestamp);

    UINT32_TO_BIN(extra_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    if (extra_len != 0) {
        memcpy((uint8_t *)req_msg + offset, extra, extra_len);
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 get challenge auth code command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size <= 4) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    out_len = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));
    if (*auth_code_len < out_len) {
        id2_log_error("short buffer, %d %d\n", *auth_code_len, out_len);
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    *auth_code_len = out_len;
    memcpy(auth_code, (uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, out_len);

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_decrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t msg_size;
    uint32_t rsp_out_len;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_decrypt enter.]\n");

    if (in == NULL || in_len == 0 || out == NULL || out_len == NULL) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (in_len > ID2_MAX_CRYPT_LEN) {
        id2_log_error("invalid input data length, %d.\n", in_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    msg_size = 4 + in_len;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_DECRYPT;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(in_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, in, in_len);

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 decrypt command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size <= 4) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    rsp_out_len = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));
    if (*out_len < rsp_out_len) {
        id2_log_error("short buffer, %d %d\n", *out_len, rsp_out_len);
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    *out_len = rsp_out_len;
    memcpy(out, (uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, *out_len);

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_verify_server(
                         const uint8_t* auth_code, uint32_t auth_code_len,
                         const uint8_t* device_random, uint32_t device_random_len,
                         const uint8_t* server_extra, uint32_t server_extra_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_verify_server enter.]\n");

    if (auth_code == NULL || auth_code_len == 0 ||
        device_random == NULL || device_random_len == 0) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (device_random_len > ID2_MAX_DEVICE_RANDOM_LEN) {
        id2_log_error("device random length exceed limit, %d\n", device_random_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    if (server_extra_len > ID2_MAX_EXTRA_LEN || (
        server_extra == NULL && server_extra_len != 0)) {
        id2_log_error("invalid server extra length, %d.\n", server_extra_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    msg_size = 4 + auth_code_len + 4 + device_random_len + 4 + server_extra_len;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_VERIFY_SERVER;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(auth_code_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, auth_code, auth_code_len);
    offset += auth_code_len;

    UINT32_TO_BIN(device_random_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, device_random, device_random_len);
    offset += device_random_len;

    UINT32_TO_BIN(server_extra_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    if (server_extra_len != 0) {
        memcpy((uint8_t *)req_msg + offset, server_extra, server_extra_len);
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 verify server command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_get_secret(const char* seed, uint8_t* secret, uint32_t* secret_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t seed_len;
    uint32_t out_len;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_get_secret enter.]\n");

    if (seed == NULL || secret == NULL || secret_len == NULL) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    seed_len = strlen(seed);
    if (seed_len > ID2_MAX_SEED_LEN) {
        id2_log_error("seed length exceed limit, %d\n", seed_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    msg_size = 4 + seed_len;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_GET_SECRET;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(seed_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, seed, seed_len);

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 get secret command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size <= 4) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    out_len = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));
    if (*secret_len < out_len) {
        id2_log_error("short buffer, %d %d\n", *secret_len, out_len);
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    *secret_len = out_len;
    memcpy(secret, (uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, out_len);

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_derive_key(const char* seed, uint8_t* key, uint32_t key_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t seed_len;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_derive_key enter.]\n");

    if (seed == NULL || key == NULL || key_len == 0) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    seed_len = strlen(seed);
    if (seed_len > ID2_MAX_SEED_LEN) {
        id2_log_error("seed length exceed limit, %d\n", seed_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    if (key_len > ID2_DERIV_KEY_LEN) {
        id2_log_error("invalid key length, %d\n", key_len);
        return IROT_ERROR_BAD_PARAMETERS;
    }

    msg_size = 4 + seed_len + 4;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_DERIVE_KEY;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(seed_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, seed, seed_len);
    offset += seed_len;
    UINT32_TO_BIN(key_len, ((uint8_t *)req_msg + offset));

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 derive key command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size != 4 + key_len) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    memcpy(key, (uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, key_len);

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_get_prov_stat(bool* is_prov)
{
    irot_result_t result;
    uint32_t stat;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_get_prov_stat enter.]\n");

    if (is_prov == NULL) {
        id2_log_error("invalid input arg\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    msg_size = 0;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = 0;
        req_msg->cmd_id = IOT_ID2_ID_GET_PROV_STAT;
    }

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 get prov stat command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size != 4) {
        id2_log_error("invalid rsp msg size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    stat = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));
    if (stat == 0) {
        *is_prov = false;
    } else {
        *is_prov = true;
    }

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_get_otp_auth_code(const uint8_t* token, uint32_t token_len,
                                           uint8_t* auth_code, uint32_t* auth_code_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t out_len;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_get_otp_auth_code enter.]\n");

    if (token == NULL || token_len == 0 ||
        auth_code == NULL || auth_code_len == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (token_len < 32 || token_len > 64) {
        id2_log_error("invalid token length, %d\n", token_len);
        return IROT_ERROR_BAD_PARAMETERS;
    }

    msg_size = 4 + token_len;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_GET_OTP_CODE;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(token_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, token, token_len);

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 get otp auth code command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    if (rsp_msg->size <= 4) {
        id2_log_error("invalid message body size, %d\n", rsp_msg->size);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    out_len = BIN_TO_UINT32((uint8_t *)rsp_msg + sizeof(ls_msg_head_t));
    if (*auth_code_len < out_len) {
        id2_log_error("short buffer, %d %d\n", *auth_code_len, out_len);
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    *auth_code_len = out_len;
    memcpy(auth_code, (uint8_t *)rsp_msg + sizeof(ls_msg_head_t) + 4, out_len);

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

irot_result_t id2_client_load_otp_data(const uint8_t* otp_data, uint32_t otp_data_len)
{
    irot_result_t result;
    uint32_t offset;
    uint32_t msg_size;
    ls_msg_head_t *req_msg = NULL;
    ls_msg_head_t *rsp_msg = NULL;

    id2_log_debug("[id2_client_load_otp_data enter.]\n");

    if (otp_data == NULL || otp_data_len == 0) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (otp_data_len > ID2_MAX_OTP_DATA_LEN) {
        id2_log_error("otp data length exceed limit, %d\n", otp_data_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    msg_size = 4 + otp_data_len;
    req_msg = ls_osa_malloc(sizeof(ls_msg_head_t) + msg_size);
    if (req_msg == NULL) {
        id2_log_error("out of mem, %d\n", (int)sizeof(ls_msg_head_t) + msg_size);
        result = IROT_ERROR_OUT_OF_MEMORY;
        goto _out;
    } else {
        req_msg->magic = ID2_MSG_HEAD_MAGIC;
        req_msg->size = msg_size;
        req_msg->cmd_id = IOT_ID2_ID_LOAD_OTP_DATA;
    }

    offset = sizeof(ls_msg_head_t);
    UINT32_TO_BIN(otp_data_len, ((uint8_t *)req_msg + offset));
    offset += 4;
    memcpy((uint8_t *)req_msg + offset, otp_data, otp_data_len);

    result = _send_request_message((uint8_t *)req_msg, sizeof(ls_msg_head_t) + msg_size);
    if (result != IROT_SUCCESS) {
        id2_log_error("send request message fail\n");
        goto _out;
    }

    rsp_msg = (ls_msg_head_t *)_wait_for_response_message();
    if (rsp_msg == NULL) {
        id2_log_error("wait for response message fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (rsp_msg->stat != IROT_SUCCESS) {
        id2_log_error("id2 load otp data command fail, %d\n", rsp_msg->stat);
        result = rsp_msg->stat;
        goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (req_msg != NULL) {
        ls_osa_free(req_msg);
    }
    if (rsp_msg != NULL) {
        ls_osa_free(rsp_msg);
    }

    return result;
}

#else  /* __DEMO__ */

irot_result_t id2_client_init(void)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_cleanup(void)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_get_version(uint32_t* version)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_get_id(uint8_t* id, uint32_t* len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_get_challenge_auth_code(const char* server_random,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len)

{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_get_timestamp_auth_code(const char* timestamp,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_decrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_get_secret(const char* seed, uint8_t* secret, uint32_t* secret_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_derive_key(const char* seed, uint8_t* key, uint32_t key_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t id2_client_get_prov_stat(bool* is_prov)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_get_otp_auth_code(const uint8_t* token, uint32_t token_len,
                                           uint8_t* auth_code, uint32_t* auth_code_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_load_otp_data(const uint8_t* otp_data, uint32_t otp_data_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

#endif /* __DEMO__ */

irot_result_t id2_client_get_device_challenge(uint8_t* random, uint32_t* random_len)
{
    id2_log_info("not supported!\n");

    (void)random;
    (void)random_len;

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_wrap_do_provisioning(const char *host, uint32_t port,
                  const char *product_key, const char *product_secret, uint32_t timeout_ms)
{
    id2_log_info("not supported!");

    (void)host;
    (void)port;
    (void)product_key;
    (void)product_secret;
    (void)timeout_ms;

    return IROT_ERROR_NOT_SUPPORTED;
}

