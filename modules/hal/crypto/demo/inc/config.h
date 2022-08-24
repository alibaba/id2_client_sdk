/**
* Copyright (C) 2017-2019 Alibaba Group Holding Limited.
**/

#ifndef _DEMO_CONFIG_H
#define _DEMO_CONFIG_H

/* RSA */
#define ALI_ALGO_CIPHER_C
#define CONFIG_ALGO_GENPRIME
#define CONFIG_AES_ROM_TABLES

#ifndef PLATFORM_ANDROID
#define ALI_ALGO_HAVE_ASM
#endif // PLATFORM_ANDROID

/* HASH */
#define ALI_ALGO_MD_C

/* SM2 */
#define IMPL_ECP_NIST_OPTIM
#define IMPL_ECP_DP_SMP256R1_ENABLED

#endif /* _DEMO_CONFIG_H */
