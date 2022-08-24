/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "ls_hal_km.h"
#include "ls_osa.h"

#if defined(__DEMO__)

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define FLASH_BLOCK_LEN   2048

/* should use device unique id */
#define LS_DEMO_UID      "demo-uid"

/* should set the real reserved partition */
#define LS_DEMO_KM_PART  ".dev_key"

static int _init_rsvd_part()
{
    size_t file_len = 0;
    uint8_t *flash_block = NULL;
    int fd = 0;
    int ret = 0;

    /* create FLASH_BLOCK_LEN file */
    fd = open(LS_DEMO_KM_PART, O_CREAT|O_RDWR, S_IRWXU | S_IRGRP | S_IROTH);
    if (fd == -1) {
        ls_osa_print("open file failed errno %d\n", errno);
        return -1;
    }

    flash_block = (uint8_t *)ls_osa_malloc(FLASH_BLOCK_LEN);
    if (!flash_block) {
        ls_osa_print("malloc failed\n");
        ret = -1;
        goto _out;
    }

    memset(flash_block, 0xff, FLASH_BLOCK_LEN);

    /* fix file length first FLASH_BLOCK_LEN for km */
    file_len = write(fd, flash_block, FLASH_BLOCK_LEN);
    if (file_len != FLASH_BLOCK_LEN) {
        ls_osa_print("seek failed errno %d\n", errno);
        ret = -1;
        goto _out;
    }

    /* fix file length last FLASH_BLICK_LEN for prov */
    file_len = write(fd, flash_block, FLASH_BLOCK_LEN);
    if (file_len != FLASH_BLOCK_LEN) {
        ls_osa_print("seek failed errno %d\n", errno);
        ret = -1;
        goto _out;
    }

_out:
    close(fd);

    if (flash_block) {
        ls_osa_free(flash_block);
        flash_block = NULL;
    }

    return ret;
}

int ls_hal_get_dev_id(uint8_t *dev_id, uint32_t *id_len)
{
    uint32_t demo_uid_len;

    if (id_len == NULL) {
        ls_osa_print("invalid input arg\n");
        return -1;
    }

    demo_uid_len = (uint32_t)strlen(LS_DEMO_UID);

    /* check the input buffer length */
    if (*id_len < demo_uid_len) {
        ls_osa_print("short buffer, %d %d\n", *id_len, demo_uid_len);
        *id_len = demo_uid_len;
        return -1;
    }

    /* copy uid into output buffer and update its length */
    if (dev_id != NULL) {
        memcpy(dev_id, LS_DEMO_UID, demo_uid_len);
    }

    *id_len = demo_uid_len;

    return 0;
}

int ls_hal_open_rsvd_part(int flag)
{
    int fd = -1;
    uint32_t mode;
    uint32_t flags;
    int ret = 0;

    /* check if file has already exist */
    if (access(LS_DEMO_KM_PART, F_OK)) {
        ret = _init_rsvd_part();
        if (ret) {
            ls_osa_print("init rsvd part failed\n");
            return -1;
        }
    }

    if (flag == LS_HAL_READ) {
        mode = O_RDONLY;
        flags = O_RDONLY;
    } else if (flag == LS_HAL_WRITE) {
        mode = O_WRONLY;
        flags = O_WRONLY | O_CREAT;
    } else if (flag == (LS_HAL_READ | LS_HAL_WRITE)) {
        mode = S_IRUSR | S_IWUSR;
        flags = O_RDWR | O_CREAT;
    } else {
        ls_osa_print("not support this flag, 0x%x\n", flag);
        return -1;
    }

    fd = open(LS_DEMO_KM_PART, flags, mode);
    if (fd < 0) {
        ls_osa_print("open %s fail - errno %d\n", LS_DEMO_KM_PART, errno);
        return -1;
    }

    return fd;
}

int ls_hal_write_rsvd_part(int fd, uint32_t offset, void *data, uint32_t data_len)
{
    uint32_t real_len = 0;

    if (fd < 0 || data == NULL ||data_len == 0) {
        ls_osa_print("invalid input args\n");
        return -1;
    }

    if (offset != lseek(fd, offset, SEEK_SET)) {
        ls_osa_print("lseek fail - errno %d\n", errno);
        return -1;
    }

    real_len = write(fd, data, data_len);
    if (real_len != data_len) {
        ls_osa_print("write data fail - %d %d\n", real_len, data_len);
        return -1;
    }

    return 0;
}

int ls_hal_read_rsvd_part(int fd, uint32_t offset, void *buffer, uint32_t read_len)
{
    uint32_t real_len = 0;

    if (fd < 0 || buffer == NULL) {
        ls_osa_print("invalid input args\n");
        return -1;
    }

    if (offset != lseek(fd, offset, SEEK_SET)) {
        ls_osa_print("lseek fail - errno %d\n", errno);
        return -1;
    }

    real_len = read(fd, buffer, read_len);
    if (real_len != read_len) {
        ls_osa_print("read data fail, %d %d\n", real_len, read_len);
        return -1;
    }

    return 0;
}

int ls_hal_close_rsvd_part(int fd)
{
    return close(fd);
}

#else  /* __DEMO__ */

int ls_hal_get_dev_id(uint8_t *dev_id, uint32_t *id_len)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

int ls_hal_open_rsvd_part(int flag)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

int ls_hal_write_rsvd_part(int fd, uint32_t offset, void *data, uint32_t data_len)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

int ls_hal_read_rsvd_part(int fd, uint32_t offset, void *buffer, uint32_t read_len)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

int ls_hal_close_rsvd_part(int fd)
{
    ls_osa_print("%s to be implemented!!\n", __FUNCTION__);

    return -1;
}

#endif /* __DEMO__ */
