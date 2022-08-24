/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#ifndef _KM_H_
#define _KM_H_

#if defined(__ARMCC_VERSION)
#pragma anon_unions
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

//the max key name len that KM can support
#define KM_MAX_NAME_LEN 16

//km error code
#define KM_SUCCESS               0x00000000
#define KM_ERR_GENERIC           0xffff0000
#define KM_ERR_AUTHENTICATION    0xffff0001
#define KM_ERR_BAD_PARAMS        0xffff0002
#define KM_ERR_NOT_SUPPORTED     0xffff0003
#define KM_ERR_BAD_FORMAT        0xffff0004
#define KM_ERR_SHORT_BUFFER      0xffff0005
#define KM_ERR_OUT_OF_MEMORY     0xffff0006
#define KM_ERR_ACCESS_CONFLICT   0xffff0007
#define KM_ERR_ITEM_NOT_FOUND    0xffff0008
#define KM_ERR_CORRUPT_KEY       0xffff0009
#define KM_ERR_OVERFLOW          0xffff000A
#define KM_ERR_ACCESS_DENIED     0xffff000B

typedef void * km_op_handle_t;

/* for import key only support KM_KEY_FORMAT_RAW now */
/* for export key only support KM_KEY_FORMAT_X509 now */
typedef enum {
    KM_KEY_FORMAT_X509 = 0, /* for public key export, asn1 encode */
    KM_KEY_FORMAT_PKCS8 = 1, /* for asymmetric key pair import*/
    KM_KEY_FORMAT_RAW = 2, /*  follow km_key_data_t struct */
} km_format_t;

typedef enum {
    KM_IROT_TYPE_NONE = 0,
    KM_IROT_TYPE_KM   = 1,
    KM_IROT_TYPE_SE   = 2,
    KM_IROT_TYPE_PUF  = 3,
    KM_IROT_TYPE_TEE  = 4,
    KM_IROT_TYPE_DEMO = 5
} km_irot_type;

typedef enum {
    KM_RSA = 0,
    KM_ECC,
    KM_AES,
    KM_DES,
    KM_DES3,
    KM_HMAC,
    KM_SM2,
    KM_SM4
} km_key_type;

typedef enum {
    KM_ECB = 0,
    KM_CBC,
    KM_CTR,
    KM_XTS, //not support yet
    KM_GCM, //not support yet
} km_block_mode_type;

typedef enum {
    KM_NO_PADDING = 0,
    KM_PKCS1,
    KM_PKCS5,
    KM_PKCS7,
} km_padding_type;

typedef enum {
    KM_DIGEST_NONE = 0,
    KM_MD5,
    KM_SHA1,
    KM_SHA256,
    KM_SHA384,
    KM_SHA512,
    KM_SM3,
} km_digest_type;

typedef enum {
    KM_ECP_DP_NONE = 0,
    KM_ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    KM_ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    KM_ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    KM_ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    KM_ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    KM_ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    KM_ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    KM_ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    KM_ECP_DP_CURVE25519,     /*!< Curve25519 */
    KM_ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    KM_ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    KM_ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
    KM_ECP_DP_SECT163K1,      /*!< 163-bits sect curve */
    KM_ECP_DP_SECT233K1,      /*!< 233-bits sect curve */
    KM_ECP_DP_SECT283K1,      /*!< 283-bits sect curve */
    KM_ECP_DP_SMP256R1,       /*!< 256-bits SM2 curve */
    KM_ECP_DP_SMP256R2,       /*!< 256-bits SM2 test curve */
} km_ecc_group_id_t;

typedef enum {
    KM_PURPOSE_ENCRYPT = 0,
    KM_PURPOSE_DECRYPT,
    KM_PURPOSE_SIGN,
    KM_PURPOSE_VERIFY,
} km_purpose_type;

typedef struct _km_rsa_gen_param {
    uint32_t key_bit;
    uint64_t exponent;
} km_rsa_gen_param;

typedef struct _km_ecc_gen_param {
    km_ecc_group_id_t group_id;
} km_ecc_gen_param;

typedef struct _km_sym_gen_param {
    uint32_t key_bit;
} km_sym_gen_param;

typedef struct _km_gen_param_t {
    km_key_type key_type;
    union {
        km_rsa_gen_param rsa_gen_param; //key_type = KM_RSA
        km_ecc_gen_param ecc_gen_param; //key_type = KM_SM2 | KM_ECDSA
        km_sym_gen_param sym_gen_param; //key_type = KM_AES | KM_DES | KM_MAC
    };
} km_gen_param_t;

typedef struct _km_sign_param {
    km_key_type key_type;
    km_padding_type padding_type;
    km_digest_type digest_type;
} km_sign_param;

typedef struct _km_enc_param {
    km_key_type key_type;
    km_padding_type padding_type;
} km_enc_param;

typedef struct _km_cipher_param {
    km_purpose_type purpose_type;
    km_block_mode_type block_mode;
    km_padding_type padding_type;
} km_cipher_param;

typedef struct _km_hmac_param {
    km_digest_type hash_type;
} km_hmac_param;

typedef struct _km_sym_param {
    km_key_type key_type;
    union {
        km_cipher_param cipher_param;
        km_hmac_param hmac_param;
    };
} km_sym_param;

//for import raw format
typedef struct _km_rsa_key_t {
    uint32_t n_len;
    uint32_t e_len;
    uint32_t d_len;
    uint32_t p_len;
    uint32_t q_len;
    uint32_t dp_len;
    uint32_t dq_len;
    uint32_t qp_len;
    uint8_t *n;
    uint8_t *e;
    uint8_t *d;
    uint8_t *p;
    uint8_t *q;
    uint8_t *dp;
    uint8_t *dq;
    uint8_t *qp;
} km_rsa_key_t;

typedef struct _km_ecc_key_t {
    km_ecc_group_id_t group_id;
    uint32_t x_len;
    uint32_t y_len;
    uint32_t d_len;
    uint8_t *x;
    uint8_t *y;
    uint8_t *d;
} km_ecc_key_t;

typedef struct _km_sym_key_t {
    uint32_t key_bit;
    uint8_t *key;
} km_sym_key_t;

typedef struct _km_key_data_t {
    km_key_type type;
    union {
        km_rsa_key_t rsa_key;
        km_sym_key_t sym_key;
        km_ecc_key_t ecc_key;
    };
} km_key_data_t;

typedef struct _km_keyring_t {
    km_key_type key_type; //key type for the key which need to import to km
    uint32_t key_bit;
    uint32_t payload_len;
    uint8_t *payload; //key data which is encrypted by id2_key
} km_keyring_t;

/*
 * km generate key
 * param: in: name: key name
 * param: in: mame_len: key name len
 * param: in: key_type: generated key type, see km_key_type
 * param: in: arg: the parameters for generate key
 *                 km_rsa_gen_param type for rsa key
 *                 km_sym_gen_param type for sym key
 * return: see km error code
 * */
uint32_t km_generate_key(const char *name, uint32_t name_len, km_gen_param_t *arg);

/*
 * km import key
 * param: in: name: key name
 * param: in: nam_len: key name len
 * param: in: format: the format for key data
 * param: in: key_data: key data to import
 * param: in: key_data_len: the len of key data
 * return: see km error code
 * */
uint32_t km_import_key(const char *name, uint32_t name_len, km_format_t format,
                   const km_key_data_t *key_data, uint32_t key_data_len);

/*
 * km export key
 * param: in:     name: key name
 * param: in:     name_len: key name len
 * param: in:     format: the format for export data
 * param: out:    export_data: the data of exported key
 * param: in_out: export_data_size:
 *                in: the length of export_data buffer
 *                out: the real length of export_data
 * return: see km error code
 * */
uint32_t km_export_key(const char *name, uint32_t name_len, km_format_t format,
                   uint8_t *export_data, size_t *export_data_len);

/*
 * km mac: computer mac
 * param: in:     name: key name
 * param: in:     name_len: key name len
 * param: in:     mac_params: the params to computer mac
 * param: in:     iv: iv for computer mac , if no need can pass NULL
 * param: in:     iv_len: the length for iv buffer
 * param: in:     src: the source for computer mac
 * param: in:     src_len: the lengthof src buffer
 * param: out:    mac: output mac
 * param: in_out: mac_len
 *                in: the length of mac buffer
 *                out: the real length of mac result
 * return: see km error code
 * */
uint32_t km_mac(const char *name, uint32_t name_len, km_sym_param *mac_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *mac, uint32_t *mac_len);

/*
 * km_delete_key: delete key stored in km
 * param: in:     name: key name
 * param: in:     name_len: key name len
 * return: see km error code
 * */
uint32_t km_delete_key(const char *name, uint32_t name_len);

/*
 * km_delete_all: delete all key stored in km
 * return: see km error code
 * */
uint32_t km_delete_all(void);

/*
 * km_envelope_begin: to generate a digit envelope
 * param: out:      ctx
 * param: in:       name: the root key for the envelope
 * param: in:       name_len: the length of the name
 * param: in/out:   protected_key: the encrypted sub_key
 *                  in: for parse envelope
 *                  out: for generate envelope
 * param: in_out:   protected_key_len:
 *                  in: the length of protected_key buffer
 *                  out: the real length of protected_key
 * param: in:   purpose: to generate envelope or to parse envelope
 *                  KM_PURPOSE_ENCRYPT for parse envelope
 *                  KM_PURPOSE_DECRYPT for generate envelope
 * return: see km error code
 *
 * */
uint32_t km_envelope_begin(void **ctx, const char *name,
        uint32_t name_len,
        uint8_t *iv, uint32_t iv_len,
        uint8_t *protected_key, uint32_t *protected_key_len, km_purpose_type purpose);

/*
 * km_envelope_update: to generate a digit envelope
 * param: in:       ctx
 * param: in:       src: the source data to encrypt
 * param: in:       src_len: the length of the src
 * param: out:      dest: the out buffer
 * param: in_out:   dest_len:
 *                  in: the length of dest buffer
 *                  out: the real length of dest buffer
 * return: see km error code
 * */

uint32_t km_envelope_update(void *ctx, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len);

/*
 * km_envelope_update: to generate a digit
 * param: in:       ctx
 * param: in:       src: the source data to encrypt
 * param: in:       src_len: the length of the src
 * param: out:      dest: the out buffer
 * param: in_out:   dest_len:
 *                  in: the length of dest buffer
 *                  out: the real length of dest buffer
 * return: see km error code
 *
 * */
uint32_t km_envelope_finish(void *ctx, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len);

/*
 * to get device id
 * param: out: id: the out buffer
 * param: in_out: id_len
 *        in: length of id buffer
 *        out: the real length of id

 * return: see km error code
 * */
uint32_t km_get_attestation(uint8_t *id, uint32_t *id_len);

/*
 * to get message signature
 * param: in:     name: key name
 * param: in:     name_len: key name len
 * param: in:     sign_params: the params to sign
 * param: in:     id: user identifier(can be NULL)
 *        in:     id_len: length of id buffer
 *        in:     msg: the message
 *        in:     msg_len: the length of msg
 * param: out:    signature: the out buf
 *                for sm2: r(32 byte) | s(32 byte)
 * param: in_out: signature_len:
 *                in: the length of out buffer
 *                out: the real length of out
 * return: see km error code
 * */
uint32_t km_msg_sign(const char *name, uint32_t name_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t *signature_len);

/*
 * to get message signature
 * param: in:     name: key name
 * param: in:     name_len: key name len
 * param: in:     sign_params: the params to sign
 * param: in:     id: user identifier(can be NULL)
 *        in:     id_len: length of id buffer
 *        in:     msg: the message
 *        in:     msg_len: the length of msg
 * param: in:     signature: the signature
 *                for sm2: r(32 byte) | s(32 byte)
 * param: in:     signature_len: the length of signature
 * return: see km error code
 * */
uint32_t km_msg_verify(const char *name, uint32_t name_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t signature_len);

/*
 * km sign
 * param: in:      name: key name
 * param: in:      name_len: key name len
 * param: in:      sign_params: the params to sign
 *                 km_sign_param: for rsa sign
 * param: in:      digest: the dgest to sign
 * param: in:      digest_len: the length for digest
 * param: out:     signature: the out buf
 *                 for sm2: r(32 byte) | s(32 byte)
 * param: in_out:  signature_len:
 *                 in: the length of out buffer
 *                 out: the real length of out
 * return: see km error code
 *
 * */
uint32_t km_sign(const char *name, uint32_t name_len,
             km_sign_param *sign_params,
             uint8_t *digest, uint32_t digest_len,
             uint8_t *signature, uint32_t *signature_len);

/*
 * km verify
 * param: in:      name: key name
 * param: in:      name_len: key name len
 * param: in:      sign_params: the params to verify
 *                 km_sign_param: for rsa sign
 * param: in:      digest: the digest to verify
 * param: in:      digest_len: the length for digest
 * param: in:      signature: the signature buffer
 *                 for sm2: r(32 byte) | s(32 byte)
 * param: in:      signature_len: the length of signature buffer
 * return: see km error code
 *
 * */
uint32_t km_verify(const char *name, uint32_t name_len,
               km_sign_param *sign_params,
               const uint8_t *digest, uint32_t digest_len,
               const uint8_t *signature, uint32_t signature_len);

/*
 * km asymmetric encrypt
 * param: in:      name: key name
 * param: in:      name_len: key name len
 * param: in:      enc_params: the params to encrypt
 *                 km_enc_param: for rsa encrypt
 * param: in:      src: the source data to encrypt
 * param: in:      src_len: the length for src
 * param: out:     dest: the out buffer
 *                       for sm2 C1 | C3 | C2
 * param: in_out:  dest_len:
 *                 in: the length of dest buffer
 *                 out: the real length of dest
 * return: see km error code
 * */
uint32_t km_asym_encrypt(const char *name, uint32_t name_len, km_enc_param *enc_params,
                uint8_t *src, uint32_t src_len,
             uint8_t *dest, uint32_t *dest_len);
/*
 * km asymmetric decrypt
 * param: in:      name: key name
 * param: in:      name_len: key name len
 * param: in:      enc_params: the params to decrypt
 *                 km_enc_param: for rsa encrypt
 * param: in:      src: the source data to encrypt
 *                      for sm2 C1 | C3 | C2
 * param: in:      src_len: the length for src
 * param: out:     dest: the out buffer
 * param: in_out:  dest_len:
 *                 in: the length of dest buffer
 *                 out: the real length of dest
 * return: see km error code
 * */
uint32_t km_asym_decrypt(const char *name, uint32_t name_len, km_enc_param *enc_params,
                uint8_t *src, uint32_t src_len,
               uint8_t *dest, uint32_t *dest_len);

/*
 * km symmetric cipher
 * param: in:      name: key name
 * param: in:      name_len: key name len
 * param: in:      cipher_params: the params to symmetric cipher
 * param: in:      iv: the iv for symmetric cipher
 * param: in:      iv_len: the length of input iv
 * param: in:      src: the source data to cipher
 * param: in:      src_len: the length for src
 * param: out:     dest: the out buffer
 * param: in_out:  dest_len:
 *                 in: the length of dest buffer
 *                 out: the real length of dest
 * return: see km error code
 * */

uint32_t km_cipher(const char *name, uint32_t name_len, km_sym_param *cipher_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len);
/*
 * km import keyring
 * param: in: name: key name
 * param: in: nam_len: key name len
 * param: in: keyring: keyring
 * return: see km error code
 * */
uint32_t km_import_keyring(const char *name, uint32_t name_len,
                       km_keyring_t *keyring);

/*
 * to get key state
 * param: in:     name: key name
 * param: in:     name_len: key name len
 * param: out:    state :prov state
 *                       0: key not exist
 *                       1: key exist
  * return: see km error code
 * */
uint32_t km_get_prov_state(const char *name, uint32_t name_len, uint32_t *state);

/*
 * to get key type
 * param: in:     name: key name
 * param: in:     name_len: key name len
 * param: out:    key_type
 * return: see km error code
 * */
uint32_t km_get_key_type(const char *name, uint32_t name_len, km_key_type *key_type);

/*
 * to show km version and new file for no rsvd part platform
 * return: see km error code
 * */

uint32_t km_init(void);

/*
 * to clean resource
 * */

void km_cleanup(void);

/*
 * to get irot type
 * return: irot type enum value
 * */
uint32_t km_get_irot_type(void);

/*
 * to get id2 id
 * param: out: the out buffer
 * param: in_out:
 *        in: length of id2
 *        out: the real length of id2
 * return: see km error code
 * */
uint32_t km_get_id2(uint8_t *id2, uint32_t *len);
/*
 * to set id2 id
 * param: in: the id buffer
 * param: in: the id len
 * return: see km error code
 * */
uint32_t km_set_id2(uint8_t *id2, uint32_t len);

/*
 * to set id2 prov state
 * param: in: prov state
 * return: see km error code
 * */
uint32_t km_set_id2_state(uint32_t state);
/*
 * to get id2 prov state
 * param: out: the prov state
 * return: see km error code
 * */
uint32_t km_get_id2_state(uint32_t *state);

/*********************************************************************/
/*********************************************************************/
/*****************for kpm: key is stored in kpm not km ***************/
/*********************************************************************/
/*********************************************************************/
/*
 * km generate key blob
 * param: in:     arg: the parameters for generate key
 *                     km_rsa_gen_param type for rsa key
 *                     km_sym_gen_param type for sym key
 * param: out:    key_blob: the encrypted key
 * param: in_out: key_blob_len:
 *                in: the length of key_blob buffer
 *                out: the needed length of key_blob
 * return: see km error code
 * */
uint32_t km_generate_key_blob(km_gen_param_t *arg, uint8_t *key_blob, uint32_t *key_blob_len);

/*
 * km import key blob
 * param: in:     format: the format for key data
 * param: in:     key_data: key data to import
 * param: in:     key_data_len: the len of key data
 * param: out:    key_blob: the encrypted key
 * param: in_out: key_blob_len:
 *                in: the length of key_blob buffer
 *                out: the needed length of key_blob
 * return: see km error code
 * */
uint32_t km_import_key_blob(km_format_t format,
                   const km_key_data_t *key_data, uint32_t key_data_len,
                   uint8_t *key_blob, uint32_t *key_blob_len);
/*
 * km export key
 * param: in:     key_blob: the encrypted key
 * param: in:     key_blob_len: the length of key_blob
 * param: in:     format: the format for export data
 * param: out:    export_data: the data of exported key
 *                for rsa and sm2 key : asn1 code
 * param: in_out: export_data_size:
 *                in: the length of export_data buffer
 *                out: the real length of export_data
 * return: see km error code
 * */
uint32_t km_blob_export_key(uint8_t *blob, uint32_t key_blob_len, km_format_t format,
                   uint8_t *export_data, size_t *export_data_size);

/*
 * km blob mac: compute mac with key_blob
 * param: in:     key_blob: the encrypted key which is used to compute mac
 * param: in:     key_blob_len: the length of key_blob
 * param: in:     mac_params: the params to computer mac
 * param: in:     iv: iv for computer mac , if no need can pass NULL
 * param: in:     iv_len: the length for iv buffer
 * param: in:     src: the source for computer mac
 * param: in:     src_len: the lengthof src buffer
 * param: out:    mac: output mac
 * param: in_out: mac_len
 *                in: the length of mac buffer
 *                out: the real length of mac result
 * return: see km error code
 * */
uint32_t km_blob_mac(uint8_t *key_blob, uint32_t key_blob_len, km_sym_param *mac_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *mac, uint32_t *mac_len);

/*
 * to get message signature
 * param: in:     key_blob: the encrypted key which is used to sign
 * param: in:     key_blob_len: the length of key_blob
 * param: in:     sign_params: the params to sign
 * param: in:     id: user identifier
 *        in:     id_len: length of id buffer
 *        in:     msg: the message
 *        in:     msg_len: the length of msg
 * param: out:    signature: the out buf
 *                for sm2: r(32 byte) | s(32 byte)
 * param: in_out: signature_len:
 *                in: the length of out buffer
 *                out: the real length of out
 * return: see km error code
 * */
uint32_t km_blob_msg_sign(uint8_t *key_blob, uint32_t key_blob_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t *signature_len);

/*
 * to get message signature
 * param: in:     key_blob: the encrypted key which is used to sign
 * param: in:     key_blob_len: the length of key_blob
 * param: in:     sign_params: the params to sign
 * param: in:     id: user identifier
 *        in:     id_len: length of id buffer
 *        in:     msg: the message
 *        in:     msg_len: the length of msg
 * param: in:     signature: the signature buffer
 *                for sm2: r(32 byte) | s(32 byte)
 * param: in:     signature_len: the length of out buffer
 * return: see km error code
 * */
uint32_t km_blob_msg_verify(uint8_t *key_blob, uint32_t key_blob_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t signature_len);

/*
 * km blob sign
 * param: in:      key_blob: the encrypted key which is used to sign
 * param: in:      key_blob_len: the length of key_blob
 * param: in:      sign_params: the params to sign
 * param: in:      digest: the data to sign
 * param: in:      digest_len: the length for digest
 * param: out:     signature: the out buf
 *                 for sm2: r(32 byte) | s(32 byte)
 * param: in_out:  signature_len:
 *                 in: the length of out buffer
 *                 out: the real length of out
 * return: see km error code
 *
 * */
uint32_t km_blob_sign(uint8_t *key_blob, uint32_t key_blob_len,
             km_sign_param *sign_params,
             uint8_t *digest, uint32_t digest_len,
             uint8_t *signature, uint32_t *signature_len);
/*
 * km blob verify
 * param: in:      key_blob: the encrypted key which is used to verify
 * param: in:      key_blob_len: the length of key_blob
 * param: in:      sign_params: the params to verify
 * param: in:      digest: the data to verify
 * param: in:      digest_len: the length for digest
 * param: in:      signature: the signature buffer
 *                 for sm2: r(32 byte) | s(32 byte)
 * param: in:      signature_len: the length of signature buffer
 * return: see km error code
 *
 * */
uint32_t km_blob_verify(uint8_t *key_blob, uint32_t key_blob_len,
               km_sign_param *sign_params,
               const uint8_t *digest, uint32_t digest_len,
               const uint8_t *signature, uint32_t signature_len);
/*
 * km blob asymmetric encrypt
 * param: in:      key_blob: the encrypted key which is used to asym encrypt
 * param: in:      key_blob_len: the length of key_blob
 * param: in:      enc_params: the params to encrypt
 * param: in:      src: the source data to encrypt
 * param: in:      src_len: the length for src
 * param: out:     dest: the out buffer
 *                       for sm2 C1 | C3 | C2
 * param: in_out:  dest_len:
 *                 in: the length of dest buffer
 *                 out: the real length of dest
 * return: see km error code
 * */
uint32_t km_blob_asym_encrypt(uint8_t *key_blob, uint32_t key_blob_len, km_enc_param *enc_params,
                uint8_t *src, uint32_t src_len,
             uint8_t *dest, uint32_t *dest_len);
/*
 * km asymmetric decrypt
 * param: in:      key_blob: the encrypted key which is used to asym decrypt
 * param: in:      key_blob_len: the length of key_blob
 * param: in:      enc_params: the params to decrypt
 * param: in:      src: the source data to decrypt
 *                      for sm2 C1 | C3 | C2
 * param: in:      src_len: the length for src
 * param: out:     dest: the out buffer
 * param: in_out:  dest_len:
 *                 in: the length of dest buffer
 *                 out: the real length of dest
 * return: see km error code
 * */
uint32_t km_blob_asym_decrypt(uint8_t *key_blob, uint32_t key_blob_len, km_enc_param *enc_params,
                uint8_t *src, uint32_t src_len,
               uint8_t *dest, uint32_t *dest_len);
/*
 * km blob symmetric cipher
 * param: in:      key_blob: the encrypted key which is used to asym decrypt
 * param: in:      key_blob_len: the length of key_blob
 * param: in:      cipher_params: the params to symmetric cipher
 * param: in:      iv: the iv for symmetric cipher
 * param: in:      iv_len: the length of input iv
 * param: in:      src: the source data to cipher
 * param: in:      src_len: the length for src
 * param: out:     dest: the out buffer
 * param: in_out:  dest_len:
 *                 in: the length of dest buffer
 *                 out: the real length of dest
 * return: see km error code
 * */
uint32_t km_blob_cipher(uint8_t *key_blob, uint32_t key_blob_len, km_sym_param *cipher_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len);

#ifdef __cplusplus
}
#endif

#endif /* _KM_H_ */

