/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */


#include <string.h>
#include "se_driver.h"

irot_result_t se_open_session(void** handle)
{
    return IROT_SUCCESS;
}

irot_result_t se_transmit(void* handle, const uint8_t* cmd_apdu, const uint32_t cmd_len, uint8_t* rsp_buf, uint32_t* rsp_len)
{
    memset(rsp_buf, 0x00, *rsp_len);
    return IROT_SUCCESS;
}

irot_result_t se_close_session(void* handle)
{
    return IROT_SUCCESS;
}

