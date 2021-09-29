/*
 * Copyright (C) 2019 - 2021 Alibaba Group Holding Limited
 */

#ifndef __CHIP_LOG_H__
#define __CHIP_LOG_H__

#include "ls_osa.h"
#include "chip_config.h"

#define chip_log_error(_f, _a ...)     ls_osa_print("E %s %d: " _f , \
                                              __FUNCTION__, __LINE__, ##_a)

#define chip_log_info(_f, _a ...)      ls_osa_print("I %s %d: "  _f , \
                                              __FUNCTION__, __LINE__,  ##_a)

#if defined(CONFIG_CHIP_DEBUG)

#define chip_log_debug(_f, _a ...)     ls_osa_print("D %s %d: " _f , \
                                              __FUNCTION__, __LINE__,  ##_a)
#else

#define chip_log_debug(_f, _a ...)

#endif

void chip_dump_buf(const char* name, uint8_t* data, uint32_t len);

#endif  /* __CHIP_LOG_H__ */
