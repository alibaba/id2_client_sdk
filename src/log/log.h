/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */

#ifndef __LOG_H__
#define __LOG_H__

#include "config.h"

extern void irot_pal_log(const char* fmt, ...);

void id2_log_hex_dump(const char* name, const uint8_t* in_data, uint32_t in_len);

#if ID2_DEBUG
	#define id2_log_debug				irot_pal_log
	#define id2_log_hex_data			id2_log_hex_dump
#else
	#define id2_log_debug 
	#define id2_log_hex_data
#endif

#define id2_log_error					irot_pal_log

#endif
