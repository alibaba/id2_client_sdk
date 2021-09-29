/*
 * Copyright (C) 2019-2021 Alibaba Group Holding Limited
 */

#ifndef __ID2_PRIV_H__
#define __ID2_PRIV_H__

#include "ls_osa.h"

#if defined(CONFIG_ID2_DEBUG)
#define id2_log_debug(_f, ...)		    ls_osa_print("%s %d: " _f,\
                                                       __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define id2_log_debug(_f, ...)
#endif

#define id2_log_info(_f, ...)		    ls_osa_print("%s %d: " _f,\
                                                            __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define id2_log_error(_f, ...)	            ls_osa_print("%s %d: %s: " _f,\
                                                            __FUNCTION__, __LINE__, "ERROR", ##__VA_ARGS__)

#endif  /* __ID2_PRIV_H__ */

