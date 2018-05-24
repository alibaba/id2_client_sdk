/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */


#ifndef __CONFIG_H__
#define __CONFIG_H__

////////////////////////////////////////////////////////////////////////////////

#define __FUNC_NAME__					__FUNCTION__
#define ID2_DEBUG						1

////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
//Do not change these values!!!

#define ID2_HASH_TYPE_SHA1				1
#define ID2_HASH_TYPE_SHA256		    2

#define ID2_CRYPTO_TYPE_3DES		    1
#define ID2_CRYPTO_TYPE_AES		        2
#define ID2_CRYPTO_TYPE_RSA		        3

#define ID2_HASH_ALG_IN_PAL				1
#define ID2_HASH_ALG_IN_HAL				2

#define ID2_SECURE_TYPE_MCU				1
#define ID2_SECURE_TYPE_STD_SE			2
#define ID2_SECURE_TYPE_MTK_SE			3

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//[you could change these configuration...]

#define ID2_ITLS_SUPPORTED				1
#define ID2_SEND_SELECT_COMMAND			1


#ifndef ID2_SECURE_TYPE_CONFIG
#define ID2_SECURE_TYPE_CONFIG			ID2_SECURE_TYPE_MCU
#endif

#ifndef ID2_HASH_MODE_CONFIG
#define ID2_HASH_MODE_CONFIG			ID2_HASH_ALG_IN_PAL
#endif

#ifndef ID2_HASH_TYPE_CONFIG
#define ID2_HASH_TYPE_CONFIG			ID2_HASH_TYPE_SHA256
#endif

#ifndef ID2_CRYPTO_TYPE_CONFIG
#define ID2_CRYPTO_TYPE_CONFIG		    ID2_CRYPTO_TYPE_3DES
#endif

////////////////////////////////////////////////////////////////////////////////
//check configurations.

#if ((ID2_SECURE_TYPE_CONFIG != ID2_SECURE_TYPE_STD_SE) && (ID2_SECURE_TYPE_CONFIG != ID2_SECURE_TYPE_MTK_SE) && (ID2_SECURE_TYPE_CONFIG != ID2_SECURE_TYPE_MCU))
	#error("ID2_SECURE_TYPE_CONFIG error.");
#endif

#if ((ID2_CRYPTO_TYPE_CONFIG != ID2_CRYPTO_TYPE_3DES) && (ID2_CRYPTO_TYPE_CONFIG != ID2_CRYPTO_TYPE_AES) && (ID2_CRYPTO_TYPE_CONFIG != ID2_CRYPTO_TYPE_RSA))
	#error("ID2_CRYPTO_TYPE_CONFIG error.");
#endif

#if ((ID2_HASH_TYPE_CONFIG != ID2_HASH_TYPE_SHA1) && (ID2_HASH_TYPE_CONFIG != ID2_HASH_TYPE_SHA256))
	#error("ID2_HASH_TYPE_CONFIG error.");
#endif

#if ((ID2_HASH_MODE_CONFIG != ID2_HASH_ALG_IN_PAL) && (ID2_HASH_MODE_CONFIG != ID2_HASH_ALG_IN_HAL))
	#error("ID2_HASH_MODE_CONFIG error.");
#endif

////////////////////////////////////////////////////////////////////////////////

#endif
