/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>

int hex_to_char(uint8_t hex);
int char_to_hex(char c);

int hex_to_ascii(const uint8_t* in_data, uint32_t in_len, uint8_t* out_buf, uint32_t* out_len);
int ascii_to_hex(const uint8_t* in_data, uint32_t in_len, uint8_t* out_buf, uint32_t* out_len);
int crc16_ccit_false(const uint8_t* in_data, uint32_t in_len, uint16_t init_value, uint8_t* pout);

int pkcs5_pading(uint8_t* in_data, uint32_t in_len, uint32_t* out_len, uint8_t block_len);
int pkcs5_unpading(uint8_t* in_data, uint32_t in_len, uint32_t* out_len, uint8_t block_len);

#endif

