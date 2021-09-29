/*
 * Copyright (C) 2018 - 2021 Alibaba Group Holding Limited
 */

#ifndef __CHIP_CONFIG_H__
#define __CHIP_CONFIG_H__

////////////////////////////////////////////////////////////////////////////////

#define CHIP_KEY_TYPE_NON             0
#define CHIP_KEY_TYPE_3DES            1
#define CHIP_KEY_TYPE_AES             2
#define CHIP_KEY_TYPE_RSA             3
#define CHIP_KEY_TYPE_ECC             4
#define CHIP_KEY_TYPE_SM1             5
#define CHIP_KEY_TYPE_SM2             6
#define CHIP_KEY_TYPE_SM4             7

#define CHIP_ECDP_TYPE_SECT163K1      1
#define CHIP_ECDP_TYPE_SECT233K1      2
#define CHIP_ECDP_TYPE_SECT283K1      3
#define CHIP_ECDP_TYPE_SECP192K1      4
#define CHIP_ECDP_TYPE_SECP224K1      5
#define CHIP_ECDP_TYPE_SECP256K1      6

#ifndef CONFIG_CHIP_ECDP_TYPE
#define CONFIG_CHIP_ECDP_TYPE         CHIP_ECDP_TYPE_SECP192K1
#endif

////////////////////////////////////////////////////////////////////////////////

#if (CONFIG_CHIP_KEY_TYPE != CHIP_KEY_TYPE_ECC)
#error "CONFIG_CHIP_KEY_TYPE is error.";
#endif

#if (CONFIG_CHIP_ECDP_TYPE != CHIP_ECDP_TYPE_SECT163K1 && \
     CONFIG_CHIP_ECDP_TYPE != CHIP_ECDP_TYPE_SECT233K1 && \
     CONFIG_CHIP_ECDP_TYPE != CHIP_ECDP_TYPE_SECT283K1 && \
     CONFIG_CHIP_ECDP_TYPE != CHIP_ECDP_TYPE_SECP192K1 && \
     CONFIG_CHIP_ECDP_TYPE != CHIP_ECDP_TYPE_SECP224K1 && \
     CONFIG_CHIP_ECDP_TYPE != CHIP_ECDP_TYPE_SECP256K1)
#error "CONFIG_CHIP_ECDP_TYPE is error.";
#endif

////////////////////////////////////////////////////////////////////////////////

#endif  /* __CHIP_CONFIG_H__ */

