/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#ifndef __MDU_DRIVER_H__
#define __MDU_DRIVER_H__

#include "id2_client.h"

#ifdef __cplusplus
extern "C"
#endif

/**
 * @brief open session and connect to module.
 *
 * @param handle
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_open_session(void **handle);

/**
 * @brief transmit AT command to module.
 *
 * @param handle
 * @param req_buf  request command buffer.
 * @param req_len  request command length.
 * @param rsp_buf  response command buffer.
 * @param rsp_len  input with response buffer length, output with real response length.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_transmit_command(void *handle, const uint8_t *req_buf, uint32_t req_len, uint8_t *rsp_buf, uint32_t *rsp_len);

/**
 * @brief close session and disconnect to module.
 *
 * @param handle
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_close_session(void *handle);

#ifdef __cplusplus
}
#endif

#endif  /* __HAL_DRIVER_H__ */

