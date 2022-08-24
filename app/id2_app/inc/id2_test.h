/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "ls_osa.h"
#include "id2_client.h"
#include "id2_client_kpm.h"

#define ID2_DBG_LOG(_f, ...)    ls_osa_print("%s %d: " _f,\
                                   __FUNCTION__, __LINE__, ##__VA_ARGS__)

typedef struct _kpm_suite_t {
    uint8_t key_idx;
    uint8_t key_info;
    char *import_data;
} kpm_suite_t;

int id2_plat_base64_encode(const uint8_t* input, uint32_t input_len,
                           uint8_t* output, uint32_t* output_len);

int id2_client_unit_test(void);
int id2_client_generate_authcode(kpm_suite_t *suite);
int id2_client_verify_authcode(char *auth_code, uint32_t auth_code_len);
int id2_client_decrypt_data(char *cipher_data, uint32_t cipher_len);

int id2_client_kpm_test(uint8_t key_idx, uint8_t key_info, char *kpm_data);

