/*
 * Copyright (C) 2017-2020  Alibaba Group Holding Limited.
 */

#ifndef ECP_H
#define ECP_H

#include "ls_osa.h"
#include "ali_crypto_types.h"

/*
 * ECP error codes
 */
#define ERR_ECP_BAD_INPUT_DATA         0x4F80  /**< Bad input parameters to function. */
#define ERR_ECP_BUFFER_TOO_SMALL       0x4F00  /**< The buffer is too small to write to. */
#define ERR_ECP_FEATURE_UNAVAILABLE    0x4E80  /**< Requested curve not available. */
#define ERR_ECP_VERIFY_FAILED          0x4E00  /**< The signatsure is not valid. */
#define ERR_ECP_DECRYPT_FAILED         0x4E08  /**< The decryption failed. */
#define ERR_ECP_DH_FAILED              0x4E88  /**< The Diffie-Hellman key exchange failed. */
#define ERR_ECP_ALLOC_FAILED           0x4D80  /**< Memory allocation failed. */
#define ERR_ECP_RANDOM_FAILED          0x4D00  /**< Generation of random value, such as (ephemeral) key, failed. */
#define ERR_ECP_INVALID_KEY            0x4C80  /**< Invalid private or public key. */
#define ERR_ECP_SIG_LEN_MISMATCH       0x4C00  /**< Signature is valid but shorter than the user-supplied length. */

#define ECP_MAX_BITS     521   /**< Maximum bit size of groups */
#define ECP_MAX_BYTES    ( ( ECP_MAX_BITS + 7 ) / 8 )
#define ECP_MAX_PT_LEN   ( 2 * ECP_MAX_BYTES + 1 )

#endif /* ecp.h */