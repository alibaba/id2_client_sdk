/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "id2_priv.h"
#include "module/mdu_driver.h"

irot_result_t mdu_open_session(void** handle)
{
    return IROT_SUCCESS;
}

irot_result_t mdu_transmit_command(void* handle, const uint8_t* req_buf, const uint32_t req_len, uint8_t* rsp_buf, uint32_t* rsp_len)
{
    id2_log_info("mdu transmit not implemented !!!\n");

    memset(rsp_buf, 0x00, *rsp_len);
    *rsp_len = 0x10;

    return IROT_SUCCESS;
}

irot_result_t mdu_close_session(void* handle)
{
    return IROT_SUCCESS;
}

