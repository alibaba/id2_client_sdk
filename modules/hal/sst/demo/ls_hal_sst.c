/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "ls_hal_sst.h"
#include "ls_osa.h"

#if defined(__DEMO__)

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

/* should set the real secure path */
static char *g_sst_path = "./sst_path/";

uint32_t ls_hal_kv_init(void)
{
    if (access(g_sst_path, F_OK) != 0) {
        if (mkdir(g_sst_path, S_IRWXU)) {
            ls_osa_print("mkdir %s fail - errno: %d\n", g_sst_path, errno);
            return SST_HAL_ERROR_GENERIC;
        }
    }

    return SST_HAL_SUCCESS;
}

void ls_hal_kv_deinit(void)
{
    return;
}

uint32_t ls_hal_kv_set(const char *key, const void *value, uint32_t len)
{
    int fd = -1;
    int ret = -1;
    uint32_t flags = 0;
    uint32_t stat = SST_HAL_SUCCESS;
    uint32_t path_len = 0;
    uint32_t name_len = 0;
    char *item_name = NULL;

    if (key == NULL || value == NULL || len == 0) {
        ls_osa_print("invalid input args\n");
        return SST_HAL_ERROR_BAD_PARAMETERS;
    }

    path_len = strlen(g_sst_path);
    name_len = path_len + strlen((char *)key) + 1;
    item_name = ls_osa_malloc(name_len);
    if (item_name == NULL) {
        ls_osa_print("out of mem, %d\n", name_len);
        return SST_HAL_ERROR_OUT_OF_MEMORY;
    } else {
        memset(item_name, 0, name_len);

        memcpy(item_name, g_sst_path, path_len);
        memcpy(item_name + path_len, key, strlen((char *)key));
    }

    flags = O_RDWR | O_CREAT;
    fd = open(item_name, flags, S_IRUSR | S_IWUSR | S_IROTH | S_IRGRP);
    if (-1 == fd) {
        ls_osa_print("open %s fail - errno: %d\n", item_name, errno);
        stat = SST_HAL_ERROR_GENERIC;
        goto _out;
    }

    if (-1 == ftruncate(fd, 0)) {
        ls_osa_print("truncate %s fail - errno: %d\n", key, errno);
        stat = SST_HAL_ERROR_GENERIC;
        goto _out;
    }

    lseek(fd, 0, SEEK_SET);

    ret = write(fd, value, len);
    if (ret < 0) {
        ls_osa_print("write %s fail - errno: %d\n", key, errno);
        stat = SST_HAL_ERROR_GENERIC;
        goto _out;
    }

    if (ret != len) {
        ls_osa_print("write obj len is not right, %d %d\n", ret, len);
        stat = SST_HAL_ERROR_GENERIC;
        goto _out;
    }

    stat = SST_HAL_SUCCESS;

_out:
    if (fd > 0) {
        close(fd);
    }

    if (item_name != NULL) {
        ls_osa_free(item_name);
    }

    return stat;
}

uint32_t ls_hal_kv_get(const char *key, void *buf, uint32_t *buf_len)
{
    int fd = -1;
    int ret = -1;
    uint32_t obj_len = 0;
    uint32_t stat = SST_HAL_SUCCESS;
    uint32_t path_len = 0;
    uint32_t name_len = 0;
    char *item_name = NULL;

    if (key == NULL || buf_len == NULL) {
        ls_osa_print("invalid input args\n");
        return SST_HAL_ERROR_BAD_PARAMETERS;
    }

    path_len = strlen(g_sst_path);
    name_len = path_len + strlen((char *)key) + 1;
    item_name = ls_osa_malloc(name_len);
    if (item_name == NULL) {
        ls_osa_print("out of mem, %d\n", name_len);
        return SST_HAL_ERROR_OUT_OF_MEMORY;
    } else {
        memset(item_name, 0, name_len);

        memcpy(item_name, g_sst_path, path_len);
        memcpy(item_name + path_len, key, strlen((char *)key));
    }

    fd = open(item_name, O_RDONLY, S_IRUSR | S_IROTH | S_IRGRP);
    if (-1 == fd) {
        ls_osa_print("open %s fail - errno: %d\n", item_name, errno);
        stat = SST_HAL_ERROR_ITEM_NOT_FOUND;
        goto _out;
    }

    obj_len = lseek(fd, 0, SEEK_END);
    if (obj_len == 0) {
        ls_osa_print("invalid object length, %d\n", obj_len);
        stat = SST_HAL_ERROR_GENERIC;
        goto _out;
    }

    if (buf == NULL) {
        /* buf_len == 0, set actual length and return SST_HAL_ERROR_SHORT_BUFFER */
        if (*buf_len == 0) {
            *buf_len = obj_len;
            stat = SST_HAL_ERROR_SHORT_BUFFER;
            goto _out;
        } else {
           ls_osa_print("buf_len should be set to zero!\n");
           stat = SST_HAL_ERROR_BAD_PARAMETERS;
           goto _out;
        }
    } else {
        /* should update buf_size if short buffer */
        if (*buf_len < obj_len) {
            ls_osa_print("short buffer, %d %d\n", *buf_len, obj_len);
            *buf_len = obj_len;
            stat = SST_HAL_ERROR_SHORT_BUFFER;
            goto _out;
        }

        lseek(fd, 0, SEEK_SET);

        ret = read(fd, buf, obj_len);
        if (ret < 0) {
            ls_osa_print("read %s fail - errno: %d\n", key, errno);
            stat = SST_HAL_ERROR_GENERIC;
            goto _out;
        }

        if (ret != obj_len){
            ls_osa_print("read obj len is not right, %d %d\n", ret, obj_len);
            stat = SST_HAL_ERROR_GENERIC;
            goto _out;
        }

        *buf_len = obj_len;

        stat = SST_HAL_SUCCESS;
    }

_out:
    if (fd > 0) {
        close(fd);
    }

    if (item_name != NULL) {
        ls_osa_free(item_name);
    }

    return stat;
}

uint32_t ls_hal_kv_del(const char *key)
{
    uint32_t stat = SST_HAL_SUCCESS;
    uint32_t path_len = 0;
    uint32_t name_len = 0;
    char *item_name = NULL;

    if (key == NULL) {
        ls_osa_print("invalid input args\n");
        return SST_HAL_ERROR_BAD_PARAMETERS;
    }

    path_len = strlen(g_sst_path);
    name_len = path_len + strlen((char *)key) + 1;
    item_name = ls_osa_malloc(name_len);
    if (item_name == NULL) {
        ls_osa_print("out of mem, %d\n", name_len);
        return SST_HAL_ERROR_OUT_OF_MEMORY;
    } else {
        memset(item_name, 0, name_len);

        memcpy(item_name, g_sst_path, path_len);
        memcpy(item_name + path_len, key, strlen((char *)key));
    }

    if (access(item_name, F_OK) == -1) {
        ls_osa_print("%s is not exist\n", item_name);
        stat = SST_HAL_ERROR_ITEM_NOT_FOUND;
        goto _out;
    }

    if (unlink(item_name) == -1) {
        ls_osa_print("unlink %s fail\n", item_name);
        stat = SST_HAL_ERROR_GENERIC;
        goto _out;
    }

_out:
    if (item_name != NULL) {
        ls_osa_free(item_name);
    }

    return stat;
}

#else  /* __DEMO__ */

uint32_t ls_hal_kv_init(void)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return SST_HAL_ERROR_NOT_SUPPORTED;
}

void ls_hal_kv_deinit(void)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return;
}

uint32_t ls_hal_kv_set(const char *key, const void *value, uint32_t len)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return SST_HAL_ERROR_NOT_SUPPORTED;
}

uint32_t ls_hal_kv_get(const char *key, void *buffer, uint32_t *buffer_len)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return SST_HAL_ERROR_NOT_SUPPORTED;
}

uint32_t ls_hal_kv_del(const char *key)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return SST_HAL_ERROR_NOT_SUPPORTED;
}

#endif /* __DEMO__ */


