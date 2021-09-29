/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#ifndef __ID2_CONFIG_H__
#define __ID2_CONFIG_H__

#if !defined(CONFIG_ID2_MDU)

////////////////////////////////////////////////////////////////////////////////

#define ID2_KEY_TYPE_NON                0
#define ID2_KEY_TYPE_3DES               1
#define ID2_KEY_TYPE_AES                2
#define ID2_KEY_TYPE_RSA                3
#define ID2_KEY_TYPE_ECC                4
#define ID2_KEY_TYPE_SM1                5
#define ID2_KEY_TYPE_SM2                6
#define ID2_KEY_TYPE_SM4                7

#define ID2_HASH_TYPE_SHA256            2
#define ID2_HASH_TYPE_SM3               3

////////////////////////////////////////////////////////////////////////////////

#if (CONFIG_ID2_KEY_TYPE == ID2_KEY_TYPE_SM1 || \
     CONFIG_ID2_KEY_TYPE == ID2_KEY_TYPE_SM2 || \
     CONFIG_ID2_KEY_TYPE == ID2_KEY_TYPE_SM4)
#define CONFIG_ID2_HASH_TYPE        ID2_HASH_TYPE_SM3
#endif

#ifndef CONFIG_ID2_HASH_TYPE
#define CONFIG_ID2_HASH_TYPE        ID2_HASH_TYPE_SHA256
#endif

////////////////////////////////////////////////////////////////////////////////

#if (CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_3DES && \
     CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_AES &&  \
     CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_RSA &&  \
     CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_ECC &&  \
     CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_SM1 &&  \
     CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_SM2 &&  \
     CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_SM4)
#error "CONFIG_ID2_KEY_TYPE error."
#endif

#if (CONFIG_ID2_HASH_TYPE != ID2_HASH_TYPE_SHA256 && \
     CONFIG_ID2_HASH_TYPE != ID2_HASH_TYPE_SM3)
#error "CONFIG_ID2_HASH_TYPE error."
#endif

#if defined(CONFIG_ID2_OTP)
#if (CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_AES && \
     CONFIG_ID2_KEY_TYPE != ID2_KEY_TYPE_SM4)
#error "CONFIG_ID2_OTP_X_MODE error, which is only supported for AES and SM4."
#endif

#if (CONFIG_ID2_KEY_TYPE == ID2_KEY_TYPE_SM4)
#define CONFIG_ID2_OTP_X_MODE
#endif
#endif

////////////////////////////////////////////////////////////////////////////////

#else  /* CONFIG_ID2_MDU */

#define ID2_MDU_TYPE_QUECTEL     1

#ifndef CONFIG_ID2_MDU_TYPE
#define CONFIG_ID2_MDU_TYPE      ID2_MDU_TYPE_QUECTEL
#endif

#if (CONFIG_ID2_MDU_TYPE != ID2_MDU_TYPE_QUECTEL)
#error "CONFIG_ID2_MDU_TYPE error."
#endif

#endif /* CONFIG_ID2_MDU */

////////////////////////////////////////////////////////////////////////////////

#endif /* __ID2_CONFIG_H__ */
