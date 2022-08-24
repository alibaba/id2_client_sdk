/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#ifndef __IROT_HAL_H__
#define __IROT_HAL_H__

#include "ls_osa.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ID2_CLIENT_KEY_ID            0  /* id2 client key */
#define CTID_CLIENT_KEY_ID           1  /* ctid client key */

/* irot hal error code definitions */
#define IROT_SUCCESS                 0  /* The operation was successful */
#define IROT_ERROR_GENERIC          -1  /* The generice error */
#define IROT_ERROR_BAD_PARAMETERS   -2  /* Input parameters are invalid */
#define IROT_ERROR_SHORT_BUFFER     -3  /* The supplied buffer is too short for output */
#define IROT_ERROR_EXCESS_DATA      -4  /* Too much data for the requested operation */
#define IROT_ERROR_OUT_OF_MEMORY    -5  /* Out of memory */
#define IROT_ERROR_COMMUNICATION    -7  /* Communication error */
#define IROT_ERROR_NOT_SUPPORTED    -8  /* The request operation is not supported */
#define IROT_ERROR_NOT_IMPLEMENTED  -9  /* The request operation is not implemented */
#define IROT_ERROR_TIMEOUT          -10 /* Communication timeout */
#define IROT_ERROR_ITEM_NOT_FOUND   -11 /* The item is not exist */
#define IROT_ERROR_ACCESS_CONFLICT  -12 /* The item is already exist */
#define IROT_ERROR_AUTHENTICATION   -13 /* Invalid authentication in asymmetric verify(RSA/ECC/SM2) */

typedef int irot_result_t;

typedef enum {
    BLOCK_MODE_ECB              = 0x00,
    BLOCK_MODE_CBC              = 0x01,
    BLOCK_MODE_CTR              = 0x02,
} block_mode_t;

typedef enum {
    SYM_PADDING_NOPADDING       = 0x00,
    SYM_PADDING_PKCS5           = 0x02,
    SYM_PADDING_PKCS7           = 0x03,
} irot_sym_padding_t;

typedef enum {
    ASYM_RSA_NOPADDING      = 0x00,
    ASYM_RSA_PADDING_PKCS1  = 0x01,
    ASYM_SM2_NOPADDING      = 0x02,
} irot_asym_padding_t;

typedef enum {
    MODE_DECRYPT                = 0x00,
    MODE_ENCRYPT                = 0x01,
} crypto_mode_t;

typedef enum {
    ASYM_TYPE_RSA_MD5_PKCS1     = 0x00,
    ASYM_TYPE_RSA_SHA1_PKCS1    = 0x01,
    ASYM_TYPE_RSA_SHA256_PKCS1  = 0x02,
    ASYM_TYPE_RSA_SHA384_PKCS1  = 0x03,
    ASYM_TYPE_RSA_SHA512_PKCS1  = 0x04,
    ASYM_TYPE_SM2_SM3           = 0x05,
    ASYM_TYPE_ECDSA             = 0x06,
} asym_sign_verify_t;

typedef enum {
    HASH_TYPE_SHA1              = 0x00,
    HASH_TYPE_SHA224            = 0x01,
    HASH_TYPE_SHA256            = 0x02,
    HASH_TYPE_SHA384            = 0x03,
    HASH_TYPE_SHA512            = 0x04,
    HASH_TYPE_SM3               = 0x05,
} hash_t;

typedef enum {
    HAL_KEY_TYPE_RSA = 0,
    HAL_KEY_TYPE_ECC,
    HAL_KEY_TYPE_AES,
    HAL_KEY_TYPE_DES,
    HAL_KEY_TYPE_DES3,
    HAL_KEY_TYPE_SM2,
    HAL_KEY_TYPE_SM4
} hal_key_type_t;

typedef enum {
    HAL_ECP_DP_NONE = 0,
    HAL_ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    HAL_ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    HAL_ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    HAL_ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    HAL_ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    HAL_ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    HAL_ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    HAL_ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    HAL_ECP_DP_CURVE25519,     /*!< Curve25519 */
    HAL_ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    HAL_ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    HAL_ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
    HAL_ECP_DP_SECT163K1,      /*!< 163-bits sect curve */
    HAL_ECP_DP_SECT233K1,      /*!< 233-bits sect curve */
    HAL_ECP_DP_SECT283K1,      /*!< 283-bits sect curve */
    HAL_ECP_DP_SMP256R1,       /*!< 256-bits SM2 curve */
    HAL_ECP_DP_SMP256R2,       /*!< 256-bits SM2 test curve */
} hal_ecc_group_id_t;

typedef struct _sym_crypto_param_t {
    hal_key_type_t key_type;    ///< key_type
    block_mode_t block_mode;    ///< block mode
    irot_sym_padding_t padding_type; ///< padding type
    crypto_mode_t mode;                ///< mode(encrypt or decrypt)
} sym_crypto_param_t;

// key object
typedef struct _rsa_key_object {
    uint32_t n_len;     ///< public modulus length(bytes)
    uint32_t e_len;     ///< public exponent length(bytes)
    uint32_t d_len;     ///< private exponent length(bytes)
    uint32_t p_len;     ///< 1st prime factor length(bytes)
    uint32_t q_len;     ///< 2st prime factor length(bytes)
    uint32_t dp_len;    ///< dp length(bytes)
    uint32_t dq_len;    ///< dq lenghh(bytes)
    uint32_t qp_len;    ///< qp length(bytes)
    uint8_t *n;         ///< public modulus
    uint8_t *e;         ///< public exponent
    uint8_t *d;         ///< private exponent
    uint8_t *p;         ///< 1st prime factor
    uint8_t *q;         ///< 2st prime factor
    uint8_t *dp;        ///< d % (p - 1)
    uint8_t *dq;        ///< d % (q - 1)
    uint8_t *qp;        ///< (1/q) % p
} rsa_key_object;

typedef struct _ecc_key_object {
    hal_ecc_group_id_t group_id;
    uint32_t x_len;
    uint32_t y_len;
    uint32_t d_len;
    uint8_t *x;
    uint8_t *y;
    uint8_t *d;
} ecc_key_object;

typedef struct _sym_key_object {
    uint32_t key_bit; ///< the key length(bits)
    uint8_t *key; ///< the key value
} sym_key_object;

typedef struct {
    hal_key_type_t key_type; ///< the key object type
    union {
        sym_key_object sym_key; ////key_type = HAL_KEY_TYPE_AES | HAL_KEY_TYPE_SM4 | HAL_KEY_TYPE_DES | HAL_KEY_TYPE_MAC
        rsa_key_object rsa_key; //key_type = HAL_KEY_TYPE_RSA
        ecc_key_object ecc_key; //key_type = HAL_KEY_TYPE_SM2 | HAL_KEY_TYPE_ECC
    };
} key_object;

typedef struct {
    uint32_t key_bit;
    uint64_t exponent;
} hal_rsa_gen_param;

typedef struct {
    hal_ecc_group_id_t group_id;
} hal_ecc_gen_param;

typedef struct {
    uint32_t key_bit;
} hal_sym_gen_param;

typedef struct {
    hal_key_type_t key_type;
    union {
        hal_rsa_gen_param rsa_gen_param; //key_type = HAL_KEY_TYPE_RSA
        hal_ecc_gen_param ecc_gen_param; //key_type = HAL_KEY_TYPE_SM2 | HAL_KEY_TYPE_ECC
        hal_sym_gen_param sym_gen_param; //key_type = HAL_KEY_TYPE_AES | HAL_KEY_TYPE_DES | HAL_KEY_TYPE_MAC
    };
} hal_key_gen_param_t;

typedef struct {
    hal_key_type_t key_type;
    uint32_t key_bit;
    uint32_t payload_len;
    uint8_t *payload; //encrypted by id2_key, ECB/PKCS5
} hal_keyring_t;

/*
 * @brief irot hal init.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_init(void);

/*
 * @brief irot hal cleanup.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_cleanup(void);

/**
 * @brief store ID2 id.
 *
 * @param[in] id2:  the ID2 id buffer.
 * @param[in] len:  the ID2 id length;
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_set_id2(uint8_t *id2, uint32_t len);

/**
 * @brief get the ID2 value, the length is 12 bytes with hex format.
 *
 * @param[out]   id2:  output buffer, which size must >= 12 bytes.
 * @param[inout] len:  in - the ID2 buffer size; out - the actual length.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_get_id2(uint8_t *id2, uint32_t *len);

/**
 * @brief get the unique identifier.
 *
 * @param[out]   uid:  the output buffer, which is used to store uid.
 * @param[inout] len:  in - the buffer length;
 *                     out - the actual uid length.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_get_uid(uint8_t *uid, uint32_t *len);

/**
 * @brief encrypt or decrypt the data with symmetric algorithms.
 *
 * @param[in]    key_obj: if the key object is not null, then use this parameter as the key;
 *                        otherwise, use the internal key identified by the key id parameter.
 * @param[in]    key_id:  identify the internal key.
 * @param[in]    in:      the input data.
 * @param[in]    in_len:  the input data length.
 * @param[out]   out:     the output buffer.
 * @param[inout] out_len: in - the buffer size; out - the actual length.
 * @param[in]    crypto_param: see sym_crypto_param_t definition.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_sym_crypto(key_object *key_obj, uint8_t key_id,
                                  uint8_t *iv, uint32_t iv_len,
                                  uint8_t *in, uint32_t in_len,
                                  uint8_t *out, uint32_t *out_len,
                                  sym_crypto_param_t *crypto_param);

/**
 * @brief compute the signature result with the asymmetric algorithms.
 *
 * @param[in]     key_obj: if the key object is not null, then use this parameter as the key;
 *                         otherwise, use the internal key identified by the key id parameter.
 * @param[in]     key_id:        identify the internal key.
 * @param[in]     msg:           the message to be signed.
 * @param[in]     msg_len:       the input message length.
 * @param[out]    signature:     the output buffer, which is used to store signature
 * @param[inout]  signature_len: in - the buffer size; out - the actual length.
 * @param[in]     type:    see asym_sign_verify_t definition.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_asym_priv_sign(key_object *key_obj, uint8_t key_id,
                                      uint8_t *msg, uint32_t msg_len,
                                      uint8_t *signature, uint32_t *signature_len,
                                      asym_sign_verify_t type);

/**
 * @brief decrypt the data with the asymmetric algorithms.
 *
 * @param[in]     key_obj: if the key object is not null, then use this parameter as the key;
 *                         otherwise, use the internal key identified by the key id parameter.
 * @param[in]     key_id:  identify the internal key.
 * @param[in]     in:      the input data.
 * @param[in]     in_len:  the input data length.
 * @param[out]    out:     the output buffer.
 * @param[inout]  out_len: in - the buffer size; out - the actual length.
 * @param[in]     padding: see asym_padding_t definition.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_asym_priv_decrypt(key_object *key_obj, uint8_t key_id,
                                         uint8_t *in, uint32_t in_len,
                                         uint8_t *out, uint32_t *out_len,
                                         irot_asym_padding_t padding);
/**
 * @brief verify signature with ID2 server public key.
 *
 * @param[in] key_obj: if the key object is not null, then use this parameter as the key;
 * @param[in] msg:            the signed message.
 * @param[in] msg_len:        the input message length.
 * @param[in] signature:      the input signature to be verified.
 * @param[in] signature_len:  the input signature length.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_asym_public_verify(key_object *key_obj, uint8_t key_id,
                            uint8_t *msg, uint32_t msg_len,
                            uint8_t *signature, uint32_t signature_len,
                            asym_sign_verify_t type);
/**
 * @brief encrypt data with ID2 server public key.
 *
 * @param[in]    key_obj: if the key object is not null, then use this parameter as the key;
 * @param[in]    in:       the input data to be encrypted.
 * @param[in]    in_len:   the input data length.
 * @param[out]   out:      the output buffer, which is used to store cipher data.
 * @param[inout] out_len:  in - the buffer length;
 *                         out - the actual cipher data length.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_asym_public_encrypt(key_object *key_obj, uint8_t key_id,
                                         uint8_t *in, uint32_t in_len,
                                         uint8_t *out, uint32_t *out_len,
                                         irot_asym_padding_t padding);

/**
 * @brief compute the hash with the hash type.
 *
 * @param[in]    in:      the input data.
 * @param[in]    in_len:  the input data length.
 * @param[out]   out:     the output data buffer.
 * @param[inout] out_len: in - the buffer size; out - the actual length.
 * @param[in]    type:    the hash type.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_hash_sum(uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len, hash_t type);

/**
 * @brief generate random number with the given length.
 *
 * @param[in] buf: the output buffer.
 * @param[in] len: the output length to be generated with random bytes.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_get_random(uint8_t *buf, uint32_t len);

/*
 * check if key exists
 * @param[in]  key_id:     identify the internal key.
 * @param[out] state:      0: key does not exists
 *                         1: key exist
 *
 * @return @see error code definitions.
 * */
irot_result_t irot_hal_get_prov_state(uint8_t key_id, uint32_t *state);

/*
 * get key type
 * @param[in]  key_id:     identify the internal key.
 * @param[out] key_type:    key type
 *
 * @return @see error code definitions.
 * */
irot_result_t irot_hal_get_key_type(uint8_t key_id, hal_key_type_t *key_type);

/*
 * @brief irot hal generate key.
 *
 * @param[in]     key_id:  identify the internal key.
 * @param[in]     arg:     the parameters for generate key.

 * @return @see error code definitions.
 */
irot_result_t irot_hal_generate_key(uint8_t key_id, hal_key_gen_param_t *arg);

/*
 * @brief irot hal export public key.
 *
 * @param[in]    key_id:          identify the internal key.
 * @param[out]   export_data:     the output buffer.
 * @param[inout] export_data_len: in - the buffer size; out - the actual length.

 * @return @see error code definitions.
 */
irot_result_t irot_hal_export_key(uint8_t key_id, uint8_t *export_data, uint32_t *export_data_len);

/*
 * irot import key to SE
 * @param[in]: key_obj:    input key data to import to se
 * @param[in]  key_id:     identify the internal key.
 *
 * @return @see error code definitions.
 * */
irot_result_t irot_hal_import_key(key_object *key_obj, uint8_t key_id);

/*
 * load keyring and import key to SE
 * @param[in]  key_id:     identify the internal key.
 * @param[in]  keyring:    the encrypted key info.
 *
 * @return @see error code definitions.
 * */
irot_result_t irot_hal_import_keyring(uint8_t key_id, hal_keyring_t *keyring);

/*
 * @brief irot hal delete key.
 *
 * @param[in]     key_id:  identify the internal key.

 * @return @see error code definitions.
 */
irot_result_t irot_hal_delete_key(uint8_t key_id);

/**
 * @brief set internal object data.
 * @param[in]:   obj_name      identify the internal object.
 * @param[in]    data:       the input data to be set.
 * @param[in]    data_len:   the input data length.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_object_set(char *obj_name, void *data, uint32_t data_len);

/**
 * @brief get internal object data.
 *
 * @param[in]    obj_name:        identity the internal object.
 * @param[out]   data:      the output data, which is used to store object dara.
 * @param[inout] data_len:  in - the data length;
 *                          out - the actual object data length.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_object_get(char *obj_name, void *data, uint32_t *data_len);

/**
 * @brief delete internal object data.
 *
 * @param[in]    obj_name:        identity the internal object.
 *
 * @return @see error code definitions.
 */
irot_result_t irot_hal_object_delete(char *obj_name);

#ifdef __cplusplus
}
#endif

#endif  /* __IROT_HAL_H__ */

