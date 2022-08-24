/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "ls_hal.h"
#include "hal_test.h"

/* can change base on the size of the rsvd part */
#define RSVD_PART_SIZE    2048

/* device id should be no longer than 100 bytes */
#define MAX_DEV_ID_LEN    100

typedef struct _rsvd_wr_param_t {
    uint32_t offset;
    uint32_t buf_len;
} rsvd_wr_param_t;

rsvd_wr_param_t test_wr_param[] = {
    {0, RSVD_PART_SIZE}, {RSVD_PART_SIZE/2, RSVD_PART_SIZE/2}, {100, 100}
};

uint32_t test_wr_param_num = 3;

static void gen_rand(uint8_t *buf, uint32_t len)
{
    ls_hal_get_random(buf, len);

    return;
}

/* test bad parameters */
int hal_km_get_devid_param_test()
{
    int ret = 0;
    uint32_t id_len = 0;
    uint8_t *dev_id = NULL;

    /* short buffer - buffer == NULL & size == 0 */
    ret = ls_hal_get_dev_id(NULL, &id_len);
    if (ret == 0 || id_len == 0 || id_len > MAX_DEV_ID_LEN) {
        HAL_TEST_ERR("test failed\n");
        return -1;
    }

    /* bad params - buffer == NULL && size == 1 */
    id_len = 1;
    ret = ls_hal_get_dev_id(NULL, &id_len);
    if (ret == 0) {
        HAL_TEST_ERR("test failed\n");
        return -1;
    }

    /* short buffer - buffer != NULL && size == 1 */
    id_len = 1;
    dev_id = ls_osa_malloc(id_len);
    if (dev_id == NULL) {
        HAL_TEST_ERR("out of mem, %d\n", id_len);
        ret = -1;
        goto clean;
    }
    ret = ls_hal_get_dev_id(dev_id, &id_len);
    if (ret == 0 || id_len == 1 || id_len > MAX_DEV_ID_LEN) {
        HAL_TEST_ERR("test failed\n");
        ret = -1;
        goto clean;
    }

    ret = 0;

clean:
    if (dev_id != NULL) {
        ls_osa_free(dev_id);
    }

    return ret;
}

int hal_km_get_devid_stress_test()
{
    int ret = 0;
    uint32_t id_len = 0;
    uint32_t id_len_back = 0;
    uint8_t *dev_id_back = NULL;
    uint8_t *dev_id = NULL;
    uint32_t i = 0;
    uint32_t test_num = 100;

    /* short buffer - buffer == NULL && size == 0, used to get devid real length */
    ret = ls_hal_get_dev_id(NULL, &id_len_back);
    if (ret == 0 || id_len_back == 0 || id_len_back > MAX_DEV_ID_LEN) {
        HAL_TEST_ERR("test failed\n");
        return -1;
    }

    dev_id_back = ls_osa_malloc(id_len_back);
    dev_id = ls_osa_malloc(MAX_DEV_ID_LEN);
    if (dev_id_back == NULL || dev_id == NULL) {
        HAL_TEST_ERR("out of mem, %d\n", id_len_back);
        ret = -1;
        goto clean;
    }

    id_len = id_len_back;
    ret = ls_hal_get_dev_id(dev_id_back, &id_len);
    if (ret != 0) {
        HAL_TEST_ERR("ls hal get dev id failed\n");
        ret = -1;
        goto clean;
    }

    id_len = MAX_DEV_ID_LEN;
    for (i = 0; i < test_num; i++) {
        ret = ls_hal_get_dev_id(dev_id, &id_len);
        if (ret || id_len != id_len_back ||
            memcmp(dev_id, dev_id_back, id_len)) {
            HAL_TEST_ERR("wrong dev id or id length\n");
            ret = -1;
            goto clean;
        }
        id_len = MAX_DEV_ID_LEN;
    }

clean:
    if (dev_id) {
        ls_osa_free(dev_id);
    }
    if (dev_id_back) {
        ls_osa_free(dev_id_back);
    }

    return ret;
}

/* test read and write rsvd part with bad parameters */
int hal_km_rsvd_part_param_test()
{
    int ret = 0;
    uint32_t buf_len = 1;
    uint32_t fd = 0;

    fd = ls_hal_open_rsvd_part(LS_HAL_READ | LS_HAL_WRITE);
    if (fd == -1) {
        HAL_TEST_ERR("open failed\n");
        return ret;
    }

    /* write - buffer == null */
    ret = ls_hal_write_rsvd_part(fd, 0, NULL, buf_len);
    if (ret == 0) {
        HAL_TEST_ERR("test write failed\n");
        ls_hal_close_rsvd_part(fd);
        return -1;
    }

    /* read - buffer == null */
    ret = ls_hal_read_rsvd_part(fd, 0, NULL, buf_len);
    if (ret == 0) {
        HAL_TEST_ERR("test read failed\n");
        ls_hal_close_rsvd_part(fd);
        return -1;
    }

    ret = ls_hal_close_rsvd_part(fd);
    if (ret != 0) {
        HAL_TEST_ERR("close failed\n");
        return ret;
    }

    return 0;
}

/* check the left and right neighbour word of the written part */
static int _hal_km_rsvd_part_basic_test(uint32_t offset, uint32_t buf_len)
{
    int ret = 0;
    uint8_t *write_buf = NULL;
    uint8_t *read_buf = NULL;
    uint32_t fd = 0;
    uint8_t pre_word[4];
    uint8_t suf_word[4];
    uint32_t pre_len = (offset > 4) ? 4 : offset;
    uint32_t suf_len = 0;
    uint32_t read_len = 0;

    if (offset + buf_len < RSVD_PART_SIZE - 4) {
        suf_len = 4;
    } else if (offset + buf_len < RSVD_PART_SIZE) {
        suf_len = RSVD_PART_SIZE - offset - buf_len;
    }

    read_len = buf_len + pre_len + suf_len;

    write_buf = ls_osa_malloc(buf_len);
    if (write_buf == NULL) {
        HAL_TEST_ERR("ls_osa_malloc failed\n");
        return -1;
    }

    read_buf = ls_osa_malloc(read_len);
    if (read_buf == NULL) {
        HAL_TEST_ERR("ls_osa_malloc failed\n");
        ret = -1;
        goto clean1;
    }

    gen_rand(write_buf, buf_len);

    fd = ls_hal_open_rsvd_part(LS_HAL_READ | LS_HAL_WRITE);
    if (fd == -1) {
        HAL_TEST_ERR("open failed\n");
        ret = -1;
        goto clean2;
    }

    /* read the left neighbour word of the written part */
    if (pre_len != 0) {
        ret = ls_hal_read_rsvd_part(fd, offset - pre_len, pre_word, pre_len);
        if (ret) {
            HAL_TEST_ERR("read failed\n");
            ls_hal_close_rsvd_part(fd);
            ret = -1;
            goto clean2;
        }
    }

    /* read the right neighbour word of the written part */
    if (suf_len != 0) {
        ret = ls_hal_read_rsvd_part(fd, offset + buf_len, suf_word, suf_len);
        if (ret) {
            HAL_TEST_ERR("read failed\n");
            ls_hal_close_rsvd_part(fd);
            ret = -1;
            goto clean2;
        }
    }

    hal_dump_data("pre word is:", pre_word, pre_len);
    hal_dump_data("write data is:", write_buf, buf_len);
    hal_dump_data("suf word is:", suf_word, suf_len);

    ret = ls_hal_write_rsvd_part(fd, offset, write_buf, buf_len);
    if (ret) {
        HAL_TEST_ERR("test write failed\n");
        ls_hal_close_rsvd_part(fd);
        ret = -1;
        goto clean2;
    }

    ret = ls_hal_read_rsvd_part(fd, offset - pre_len, read_buf, read_len);
    if (ret) {
        HAL_TEST_ERR("test read failed\n");
        ls_hal_close_rsvd_part(fd);
        ret = -1;
        goto clean2;
    }

    hal_dump_data("read buf is:", read_buf, read_len);

    if (memcmp(read_buf, pre_word, pre_len) ||
        memcmp(read_buf + pre_len, write_buf, buf_len) ||
        memcmp(read_buf + pre_len + buf_len, suf_word, suf_len)) {
        HAL_TEST_ERR("read data is not same to write data\n");
        ret = -1;
        ls_hal_close_rsvd_part(fd);
        goto clean2;
    }

    ret = ls_hal_close_rsvd_part(fd);
    if (ret != 0) {
        HAL_TEST_ERR("close failed\n");
        ret = -1;
        goto clean2;
    }

clean2:
    if (read_buf) {
        ls_osa_free(read_buf);
        read_buf = NULL;
    }

clean1:
    if (write_buf) {
        ls_osa_free(write_buf);
        write_buf = NULL;
    }

    return ret;
}

/* test for read and write rsvd part */
int hal_km_rsvd_part_basic_test()
{
    int ret = 0;
    int i = 0;

    for (i = 0; i < test_wr_param_num; i++) {
        ret = _hal_km_rsvd_part_basic_test(test_wr_param[i].offset, test_wr_param[i].buf_len);
        if (ret) {
            HAL_TEST_ERR("%d test failed\n", i);
            return ret;
        }
    }

    return 0;
}

int hal_km_rsvd_part_stress_test()
{
    uint32_t test_num = 1000;
    double total_time, av_time;
    long long start_time = 0;
    long long end_time = 0;

    int ret = 0;
    uint8_t *write_buf = NULL;
    uint8_t *read_buf = NULL;
    uint32_t fd = 0;
    uint32_t offset = 0;
    uint32_t buf_len = 1024;
    uint32_t i = 0;

    write_buf = ls_osa_malloc(buf_len);
    if (write_buf == NULL) {
        HAL_TEST_ERR("ls_osa_malloc failed\n");
        return -1;
    }

    read_buf = ls_osa_malloc(buf_len);
    if (read_buf == NULL) {
        HAL_TEST_ERR("ls_osa_malloc failed\n");
        goto clean;
    }

    gen_rand(write_buf, buf_len);

    fd = ls_hal_open_rsvd_part(LS_HAL_READ | LS_HAL_WRITE);
    if (fd == -1) {
        HAL_TEST_ERR("open failed\n");
        ret = -1;
        goto clean1;
    }

    start_time = ls_osa_get_time_ms();
    for (i = 0; i < test_num; i++) {
        ret = ls_hal_write_rsvd_part(fd, offset, write_buf, buf_len);
        if (ret) {
            HAL_TEST_ERR("test write failed\n");
            ls_hal_close_rsvd_part(fd);
            ret = -1;
            goto clean1;
        }
    }
    end_time = ls_osa_get_time_ms();
    total_time = end_time - start_time;
    av_time = total_time / test_num;
    HAL_TEST_INF("write 1K data total time: %fms, av_time: %fms\n", total_time, av_time);

    start_time = ls_osa_get_time_ms();
    for (i = 0; i < test_num; i++) {
        ret = ls_hal_read_rsvd_part(fd, offset, read_buf, buf_len);
        if (ret || memcmp(read_buf, write_buf, buf_len)) {
            HAL_TEST_ERR("test read failed\n");
            ls_hal_close_rsvd_part(fd);
            ret = -1;
            goto clean1;
        }
    }
    end_time = ls_osa_get_time_ms();
    total_time = end_time - start_time;
    av_time = total_time / test_num;
    HAL_TEST_INF("read 1K data total time: %fms, av_time: %fms\n", total_time, av_time);

    ls_hal_close_rsvd_part(fd);

clean1:
    if (read_buf) {
        ls_osa_free(read_buf);
        read_buf = NULL;
    }

clean:
    if (write_buf) {
        ls_osa_free(write_buf);
        write_buf = NULL;
    }

    return ret;
}

int hal_km_test()
{
    int ret = 0;

    ret = hal_km_get_devid_param_test();
    if (ret) {
        HAL_TEST_ERR("get dev id short buffer test failed\n");
        ret = -1;
        goto _out;
    }

    ret = hal_km_get_devid_stress_test();
    if (ret) {
        HAL_TEST_ERR("get dev id stress test failed\n");
        ret = -1;
        goto _out;
    }

    ret = hal_km_rsvd_part_param_test();
    if (ret) {
        HAL_TEST_ERR("rsvd part null test failed\n");
        ret = -1;
        goto _out;
    }

    ret = hal_km_rsvd_part_basic_test();
    if (ret) {
        HAL_TEST_ERR("rsvd part wr test failed\n");
        ret = -1;
        goto _out;
    }

    ret = hal_km_rsvd_part_stress_test();
    if (ret) {
        HAL_TEST_ERR("rsvd part read and write stress test failed\n");
        ret = -1;
        goto _out;
    }

    ret = 0;

_out:
    if (ret == 0) {
        HAL_TEST_INF("============================> HAL KM Test Pass.\n\n");
    } else {
        HAL_TEST_INF("============================> HAL KM Test Fail.\n\n");
    }

    return ret;
}

