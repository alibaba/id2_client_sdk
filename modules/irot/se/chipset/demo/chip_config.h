/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#ifndef __CHIP_CONFIG_H__
#define __CHIP_CONFIG_H__

////////////////////////////////////////////////////////////////////////////////

#define CONFIG_CHIP_DEBUG
#define CONFIG_CHIP_SEND_SELECT_COMMAND

////////////////////////////////////////////////////////////////////////////////

#define CHIP_KEY_TYPE_NON               0
#define CHIP_KEY_TYPE_3DES              1
#define CHIP_KEY_TYPE_AES               2
#define CHIP_KEY_TYPE_RSA               3
#define CHIP_KEY_TYPE_ECC               4
#define CHIP_KEY_TYPE_SM1               5
#define CHIP_KEY_TYPE_SM2               6
#define CHIP_KEY_TYPE_SM4               7

#define CHIP_TYPE_SE_STD_CMD            1
#define CHIP_TYPE_SE_MTK_CMD            2
#define CHIP_TYPE_SE_STD_HAL            3

#ifndef CONFIG_CHIP_TYPE
#define CONFIG_CHIP_TYPE           CHIP_TYPE_SE_STD_HAL
#endif

////////////////////////////////////////////////////////////////////////////////

#if (CONFIG_CHIP_KEY_TYPE != CHIP_KEY_TYPE_3DES && \
     CONFIG_CHIP_KEY_TYPE != CHIP_KEY_TYPE_AES && \
     CONFIG_CHIP_KEY_TYPE != CHIP_KEY_TYPE_RSA && \
     CONFIG_CHIP_KEY_TYPE != CHIP_KEY_TYPE_SM1 && \
     CONFIG_CHIP_KEY_TYPE != CHIP_KEY_TYPE_SM2 && \
     CONFIG_CHIP_KEY_TYPE != CHIP_KEY_TYPE_SM4)
#error "CONFIG_CHIP_KEY_TYPE error.";
#endif

////////////////////////////////////////////////////////////////////////////////

#endif  /* __CHIP_CONFIG_H__ */

