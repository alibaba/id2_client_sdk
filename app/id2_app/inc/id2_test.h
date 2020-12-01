/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "ls_osa.h"
#include "id2_client.h"

#define ID2_DBG_LOG(_f, ...)    ls_osa_print("%s %d: " _f,\
                                   __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define ID2_AUTH_CODE_BUF_LEN   512

int id2_client_generate_authcode(void);
int id2_client_decrypt_data(char *cipher_data, uint32_t cipher_len);

