/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 */

#ifndef _HAL_TEST_H_
#define _HAL_TEST_H_

#include <stdbool.h>

#include "ls_osa.h"

#define HAL_TEST_INF(_f, _a ...) ls_osa_print("INF %s %d: "_f, __FUNCTION__, __LINE__, ##_a)
#define HAL_TEST_ERR(_f, _a ...) ls_osa_print("ERR %s %d: "_f, __FUNCTION__, __LINE__, ##_a)

int hal_km_test(void);

int hal_sst_test(void);

int hal_aes_test(void);
int hal_rsa_test(void);
int hal_sm2_test(void);
int hal_hash_test(void);
int hal_rand_test(void);
int hal_crypto_test(void);

int hal_dump_data(const char *name, uint8_t *data, uint32_t size);

#endif /* _HAL_TEST_H_ */
