/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 **/

#ifndef _ALI_CRYPTO_H_
#define _ALI_CRYPTO_H_

#include "ali_crypto_types.h"

#define CRYPTO_DBG_LOG(_f, ...) \
        ls_osa_print("%s %d: "_f, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define CRYPTO_ERR_LOG(_f, ...) \
        ls_osa_print("E %s %d: "_f, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define HASH_SIZE(type) (((type) == SHA1) ? (SHA1_HASH_SIZE) : (     \
                        ((type) == SHA224) ? (SHA224_HASH_SIZE) : ( \
                        ((type) == SHA256) ? (SHA256_HASH_SIZE) : ( \
                        ((type) == SM3   ) ? (SM3_HASH_SIZE   ) : ( \
                        ((type) == SHA384) ? (SHA384_HASH_SIZE) : ( \
                        ((type) == SHA512) ? (SHA512_HASH_SIZE) : ( \
                        ((type) == MD5) ? (MD5_HASH_SIZE) : (0))))))))

// malloc d and copy from s to d
#define _MALLOC_COPY(d, s, size) do { \
                                        if (s != NULL) {                         \
                                            d = (uint8_t *)ls_osa_malloc(size);  \
                                            if (d == NULL) goto cleanup;         \
                                            memcpy(d, s, size);                  \
                                        }                                        \
                                    } while( 0 );
// free
#define _FREE_BUF(s) do { if (s) ls_osa_free(s);} while( 0 );

/********************************************************************/
/*                             SYM                                  */
/********************************************************************/
/* aes */

/*
 * type[in]:       must be AES_ECB/AES_CBC/AES_CTR/AES_CFB
 * size[out]:      check size != NULL
 *                   -- caller will alloc "size" memory as context buffer later
 */
ali_crypto_result ali_aes_get_ctx_size(aes_type_t type, size_t *size);

/*
 * type[in]:        must be AES_ECB/AES_CBC/AES_CTR/AES_CFB
 * is_enc[in]:      [true] for encrypt, [false] for decrypt
 * key1[in]:        the encrypt key
 * key2[in]:        the tweak encrypt key for XTS mode
 * keybytes[in]:    the key length of the keys(each) in bytes, should be 16/24/32 bytes
 * iv[in]:          only valid for AES_CBC/AES_CTR
 *                    -- function can read 16 bytes from this address as the internal iv
 * context[in/out]: caller allocated memory used as internal context, which size is got through ali_aes_get_ctx_size
 *                    -- [in]:  status of context should be CLEAN or FINISHED
 *                    -- [out]: status of context is changed to INITIALIZED
 */
ali_crypto_result ali_aes_init(aes_type_t type, bool is_enc,
                               const uint8_t *key1, const uint8_t *key2,
                               size_t keybytes, const uint8_t *iv, void *context);

/*
 * src[in]:         plaintext for encrypt, ciphertext for decrypt
 * dst[out]:        ciphertext for encrypt, plaintext for decrypt
 * size[in]:        the number of bytes to process
 *                    -- ECB/CBC, must be multiple of the cipher block size
 *                    -- CTR/CFB, any positive integer
 * context[in/out]: internal context
 *                    -- [in]:  status of context should be INITED or PROCESSING
 *                    -- [out]: status of context is changed to PROCESSING
 */
ali_crypto_result ali_aes_process(const uint8_t *src, uint8_t *dst,
                                  size_t size, void *context);

/*
 * src[in]:          source data, plaintext for encrypt/ciphertext for decrypt
 *                     -- may be NULL, which identify that no input data, only terminate crypto
 * src_size[in]:     the number of bytes to process, src_size == 0 if src == NULL
 *                     -- encrypt: SYM_NOPAD - must be multiple of the cipher block size
 *                     -- decrypt: ECB/CBC - must be multiple of the cipher block size
 * dst[out]:         destination data, which is used to save processed data
 *                     -- may be NULL if no input src data(src == NULL && src_size == 0)
 *                     -- ciphertext for encrypt, plaintext for decrypt
 *                     -- if no SYM_NOPAD, should remove padding data accordingly
 * dst_size[in/out]: the length of processed data, may be NULL if dst == NULL
 *                     -- [in]:  buffer size
 *                     -- [out]: the actual encrypted/decrypted data size
 * padding[in]:      padding type for aes mode
 *                     -- ECB/CBC: only support SYM_NOPAD
 *                     -- CTR/CFB: padding is ignored
 * context[in/out]:  internal context
 *                     -- [in]:  status of context should be INITED or PROCESSING
 *                     -- [out]: status of context is changed to FINISHED
 */
ali_crypto_result ali_aes_finish(const uint8_t *src, size_t src_size,
                                 uint8_t *dst, size_t *dst_size,
                                 sym_padding_t padding, void *context);

ali_crypto_result ali_aes_reset(void *context);

/* sm4 */

/*
 * type[in]:       must be SM4_ECB/SM4_CBC/SM4_CTR/SM4_CTS/SM4_XTS
 * size[out]:      check size != NULL
 *                   -- caller will alloc "size" memory as context buffer later
 */
ali_crypto_result ali_sm4_get_ctx_size(sm4_type_t type, size_t *size);

/*
 * type[in]:        must be SM4_ECB/SM4_CBC/SM4_CTR/SM4_CTS/SM4_XTS
 * is_enc[in]:      [true] for encrypt, [false] for decrypt
 * key1[in]:        the encrypt key
 * key2[in]:        the tweak encrypt key for XTS mode
 * keybytes[in]:    the key length of the keys(each) in bytes, should be 16/24/32 bytes
 * iv[in]:          only valid for SM4_CBC/SM4_CTR/SM4_CTS/SM4_XTS
 *                    -- function can read 16 bytes from this address as the internal iv
 * context[in/out]: caller allocated memory used as internal context, which size is got through ali_sm4_get_ctx_size
 *                    -- [in]:  status of context should be CLEAN or FINISHED
 *                    -- [out]: status of context is changed to INITIALIZED
 */
ali_crypto_result ali_sm4_init(sm4_type_t type, bool is_enc,
                               const uint8_t *key1, const uint8_t *key2,
                               size_t keybytes, const uint8_t *iv, void *context);

/*
 * src[in]:         plaintext for encrypt, ciphertext for decrypt
 * dst[out]:        ciphertext for encrypt, plaintext for decrypt
 * size[in]:        the number of bytes to process
 *                    -- ECB/CBC/CTS/XTS, must be multiple of the cipher block size
 *                    -- CTR, any positive integer
 * context[in/out]: internal context
 *                    -- [in]:  status of context should be INITED or PROCESSING
 *                    -- [out]: status of context is changed to PROCESSING
 */
ali_crypto_result ali_sm4_process(const uint8_t *src, uint8_t *dst,
                                  size_t size, void *context);

/* drc[in]:          source data, plaintext for encrypt/ciphertext for decrypt
 *                     -- may be NULL, which identify that no input data, only terminate crypto
 * src_size[in]:     the number of bytes to process, src_size == 0 if src == NULL
 *                     -- encrypt: SYM_NOPAD - must be multiple of the cipher block size
 *                     -- decrypt: ECB/CBC - must be multiple of the cipher block size
 * dst[out]:         destination data, which is used to save processed data
 *                     -- may be NULL if no input src data(src == NULL && src_size == 0)
 *                     -- ciphertext for encrypt, plaintext for decrypt
 *                     -- if no SYM_NOPAD, should remove padding data accordingly
 * dst_size[in/out]: the length of processed data, may be NULL if dst == NULL
 *                     -- [in]:  buffer size
 *                     -- [out]: the actual encrypted/decrypted data size
 * padding[in]:      padding type for aes mode
 *                     -- ECB/CBC: only support SYM_NOPAD
 *                     -- CTR/CTS/XTS: padding is ignored
 * context[in/out]:  internal context
 *                     -- [in]:  status of context should be INITED or PROCESSING
 *                     -- [out]: status of context is changed to FINISHED
 */
ali_crypto_result ali_sm4_finish(const uint8_t *src, size_t src_size,
                          uint8_t *dst, size_t *dst_size,
                              sym_padding_t padding, void *context);

ali_crypto_result ali_sm4_reset(void *context);
ali_crypto_result ali_sm4_copy_context(void *dst_ctx, void *src_ctx);

/* des */
ali_crypto_result ali_des_get_ctx_size(des_type_t type, size_t *size);

/*
type:       must be DES_ECB/DES_CBC/DES3_ECB/DES3_CBC
is_enc:     [true] for encrypt, [false] for decrypt.
key:        function will read 'keybytes' of data as key.
keybytes:   for DES_ECB/DES_CBC, must be 64.
            for DES3_ECB/DES3_CBC, must be 128 or 192.
iv:         for DES_ECB/DES3_ECB: must be NULL.
            for DES_CBC/DES3_CBC: function will read 8 bytes as algo iv.
context:    function will use size which return from function 'ali_des_get_ctx_size'
            as internal context.
            function will check the [status[ of 'context', must be CLEAN or FINISH.
            function will initialize the [status] of 'context' to INIT.
            function will save the 'type', 'is_enc', or maybe 'iv', 'key', 'keybytes' in 'context'.
            function will initialize the 'context' to a valid context.
*/
ali_crypto_result ali_des_init(des_type_t type, bool is_enc,
                               const uint8_t *key, size_t keybytes,
                               const uint8_t *iv, void *context);

/*
src:        function will read 'size' of data from this area as source data.
            MUST be NULL if 'size' is 0
dst:        function will write 'size' of data to this area as destination data.
            MUST be NULL if 'size' is 0
size:       the length of source data.
            must be multiple of 8 bytes. or 0.
            if size == 0, src MUST be NULL, dst MUST be NULL, return TEE_SUCCESS.
context:    function will use size which return from function 'ali_des_get_ctx_size'
            as internal context.
            function will check it is a valid context.
            function will check the [status] of 'context', must be INIT or PROCESS.
            function will change the [status] of 'context' to PROCESS.
            function will do encrypt or decrypt indicated by the content in 'context'.
*/
ali_crypto_result ali_des_process(const uint8_t *src, uint8_t *dst,
                                  size_t size, void *context);
/*
src:        function will read 'src_size' of data from this area as source data.
            MUST be NULL if 'src_size' is 0.
src_size:   the length of source data. this have different rules for differnt 'type' and 'padding'.
            a. for 'padding' is SYM_NOPAD:
                a.1 MUST be multiple of 16 bytes. or 0.
            b. for other 'padding':
                b.1 can be any integer or 0.
            if 'src_size' == 0, 'src' MUST be NULL, 'dst' MUST be NULL, and this function will reaturn SUCCESS.
dst:        function will write certain length which is retuned by 'dst_size'
            of data to this area as destination data.
            MUST be NULL if 'size' is 0
dst_size:   function will wirte some integer to this area to indicate the length of destination data.
            the return value depends on 'src_size' and 'padding'
            a.1 for 'padding' is SYM_NOPAD, dst_size is equal to src_size.
            a.2 for other 'padding', 'dst_size' is 16 bytes align up of 'src_size'.
padding:    the padding type of finish.
            can be anyone of SYM_NOPAD/SYM_PKCS5_PAD/SYM_ZERO_PAD.
context:    function will use size which return from function 'ali_des_get_ctx_size'
            as internal context.
            function will check it is a valid context.
            function will check the [status] of 'context', must be INIT or PROCESS.
            function will change the [status] of 'context' to FINISH.
            function will do encrypt or decrypt indicated by the content in 'context'.
            function MUST clean the content of context before this fucntion return.
*/
ali_crypto_result ali_des_finish(const uint8_t *src, size_t src_size,
                                 uint8_t *dst, size_t *dst_size,
                                 sym_padding_t padding, void *context);

ali_crypto_result ali_des_reset(void *context);

/********************************************************************/
/*                             HASH                                 */
/********************************************************************/

/*
 * Get sha1 context size
 * size[in]:       size pointer
 */
ali_crypto_result ali_sha1_get_ctx_size(size_t *size);

/*
 * Initialize sha1 context size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_sha1_init(void *context);

/*
 * sha1 update process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_sha1_update(const uint8_t *src, size_t size, void *context);

/*
 * SHA1 digest process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * dgst[out]:  ali hash context
 */
ali_crypto_result ali_sha1_digest(const uint8_t *src,
                                  size_t size, uint8_t *dgst);

/*
 * sha1 final process
 * dgst[out]:    input buffer
 * context[in]:  ali hash context
 */
ali_crypto_result ali_sha1_final(uint8_t *dgst, void *context);

/*
 * Get sha1 context size
 * size[in]:       size pointer
 */
ali_crypto_result ali_sha256_get_ctx_size(size_t *size);

/*
 * Initialize sha256 context size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_sha256_init(void *context);

/*
 * sha256 update process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_sha256_update(const uint8_t *src, size_t size, void *context);

/*
 * sha256 final process
 * dgst[out]:    input buffer
 * context[in]:  ali hash context
 */
ali_crypto_result ali_sha256_final(uint8_t *dgst, void *context);

/*
 * SHA256 digest process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * dgst[out]:  ali hash context
 */
ali_crypto_result ali_sha256_digest(const uint8_t *src,
                                    size_t size, uint8_t *dgst);

/*
 * Get md5 context size
 * size[in]:       size pointer
 */
ali_crypto_result ali_md5_get_ctx_size(size_t *size);

/*
 * Initialize md5 context size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_md5_init(void *context);

/*
 * md5 update process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_md5_update(const uint8_t *src, size_t size, void *context);

/*
 * md5 final process
 * dgst[out]:    input buffer
 * context[in]:  ali hash context
 */
ali_crypto_result ali_md5_final(uint8_t *dgst, void *context);

/*
 * MD5 digest process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * dgst[out]:  ali hash context
 */
ali_crypto_result ali_md5_digest(const uint8_t *src,
                                 size_t size, uint8_t *dgst);

/*
 * Get sm3 context size
 * size[in]:       size pointer
 */
ali_crypto_result ali_sm3_get_ctx_size(size_t *size);

/*
 * Initialize sm3 context size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_sm3_init(void *context);

/*
 * sm3 update process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * context[in]:    ali hash context
 */
ali_crypto_result ali_sm3_update(const uint8_t *src, size_t size, void *context);

/*
 * sm3 final process
 * dgst[out]:    input buffer
 * context[in]:  ali hash context
 */
ali_crypto_result ali_sm3_final(uint8_t *dgst, void *context);

/*
 * sm3 digest process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * dgst[out]:  ali hash context
 */
ali_crypto_result ali_sm3_digest(const uint8_t *src,
                                 size_t size, uint8_t *dgst);

/*
 * Get context size
 * type[in]: only supports SHA1/SHA256/MD5
 * size[in]: size pointer
 */
ali_crypto_result ali_hash_get_ctx_size(hash_type_t type, size_t *size);

/*
 * Initialize context
 * type[in]:    only supports SHA1/SHA256/MD5
 * context[in]: ali hash context
 */
ali_crypto_result ali_hash_init(hash_type_t type, void *context);

/*
 * HASH update process
 * src[in]:     input buffer
 * size[in]:    input buffer size
 * context[in]: ali hash context
 */
ali_crypto_result ali_hash_update(const uint8_t *src, size_t size, void *context);

/*
 * HASH final process
 * dgst[out]:    input buffer
 * context[in]:  ali hash context
 */
ali_crypto_result ali_hash_final(uint8_t *dgst, void *context);

/*
 * HASH digest process
 * src[in]:    input buffer
 * size[in]:   input buffer size
 * dgst[out]:  ali hash context
 */
ali_crypto_result ali_hash_digest(hash_type_t type,
                                  const uint8_t *src, size_t size, uint8_t *dgst);

/*
 * Reset ali hash context
 * context[in]: ali hash context
 */
ali_crypto_result ali_hash_reset(void *context);

/********************************************************************/
/*                             MAC                                  */
/********************************************************************/
/*
 * Get context size
 * type: only supports SHA1/SHA256/MD5
 * size[in]:       size pointer
 */
ali_crypto_result ali_hmac_get_ctx_size(hash_type_t type, size_t *size);

/*
 * Initialize Hmac context
 * type: only supports SHA1/SHA256/MD5
 * key[in]:  key buffer
 * keybytes[in]: key length in bytes
 * context:  context pointer
 */
ali_crypto_result ali_hmac_init(hash_type_t type,
                                const uint8_t *key, size_t keybytes, void *context);
/*
 * Initialize Hmac context
 * src[in]:  data buffer
 * size[in]: data buffer length in bytes
 * context:  context pointer
 */
ali_crypto_result ali_hmac_update(const uint8_t *src, size_t size, void *context);

/*
 * Hmac finalize process
 * dgst[out]:  data buffer
  * context:  context pointer
 */
ali_crypto_result ali_hmac_final(uint8_t *dgst, void *context);

/*
 * Initialize Hmac context
 * type: only supports SHA1/SHA256/MD5
 * key[in]:  key buffer
 * keybytes[in]: key length in bytes
 * src[in]:  data buffer
 * size[in]: data buffer length in bytes
 * dgst[out]: output buffer
 */
ali_crypto_result ali_hmac_digest(hash_type_t type,
                                  const uint8_t *key, size_t keybytes,
                                  const uint8_t *src, size_t size, uint8_t *dgst);

/*
 * Reset ali hmac context
 * context[in]: ali hmac context
 */
ali_crypto_result ali_hmac_reset(void *context);

/********************************************************************/
/*                             ASYM                                 */
/********************************************************************/
/* RSA */
/*
 * e:  Public exponent
 * d:  Private exponent
 * n:  Modulus
 *
 * Optional CRT parameters
 * p, q:  N = pq
 * qp:  1/q mod p
 * dp:  d mod (p-1)
 * dq:  d mod (q-1)
 */

/*
 * RSA Init Key Type
 */
typedef enum {
    RSA_PUBKEY  = 0,    // RSA Public Key
    RSA_KEYPAIR,        // RSA Key Pair
} rsa_key_type_t;

/*
 * Initialize key handler accroding to keytype
 *
 * rsa_key[out]:   rsa_key struct
 * type[in]:       key type (RSA_PUBKEY/RSA_KEYPAIR)
 * key_bytes[in]:  key length in bytes
 * n/n_size[in]:   rsa modulus data and size in bytes
 * e/e_size[in]:   rsa public exponent data and size in bytes
 * d/d_size[in]:   rsa private exponent data and size in bytes
 * p/p_size[in]:   rsa prime1 data and size in bits, may be NULL/0
 * q/q_size[in]:   rsa prime2 data and size in bits, may be NULL/0
 * dp/dp_size[in]: rsa exponent2 data and size in bits, may be NULL/0
 * dq/dq_size[in]: rsa exponent2 data and size in bits, may be NULL/0
 * dq/dq_size[in]: rsa coefficient data and size in bits, may be NULL/0
 */
ali_crypto_result ali_rsa_init_key(rsa_key_t *rsa_key,
                                   rsa_key_type_t type,
                                   size_t key_bytes,
                                   uint8_t *n,  size_t n_size,
                                   uint8_t *e,  size_t e_size,
                                   uint8_t *d,  size_t d_size,
                                   uint8_t *p,  size_t p_size,
                                   uint8_t *q,  size_t q_size,
                                   uint8_t *dp, size_t dp_size,
                                   uint8_t *dq, size_t dq_size,
                                   uint8_t *qp, size_t qp_size);

/*
 * Cleanup key handler
 *
 * key[in]: rsa_key struct
 * type[in]: key type (RSA_PUBKEY/RSA_KEYPAIR)
 */
void ali_rsa_clean(rsa_key_t *key);

/*
 * Generate RSA keypair
 *
 * keybits[in]:   rsa key length in bits
 * e:             public exponent
 * keypair[out]:  output buffer, which is used to save generated rsa key pair
 */
ali_crypto_result ali_rsa_gen_keypair(size_t keybits, int exponent,
                                      rsa_key_t *keypair);

/*
 * Get key attribute
 *
 * attr[in]:      rsa key attribute ID
 * rsa_key[in]:   rsa key struct
 * buffer[out]:   buffer, which is used to save required attribute
 * size[in/out]:  buffer max size and key attribute actual size in bytes
 */
ali_crypto_result ali_rsa_get_key_attr(rsa_key_attr_t attr,
                                       const rsa_key_t *rsa_key,
                                       void *buffer, size_t *size);

/*
 * Encrypt with rsa public key
 *
 * rsa_key[in]:   rsa key struct
 * src[in]:       buffer, to be encrypted
 * src_size:      src length in bytes
 * dst[in]:       dst, to save the encrypted result
 * dst_size:      dst length pointer
 * padding:       rsa padding type
 */
ali_crypto_result ali_rsa_public_encrypt(const rsa_key_t *rsa_key,
                                         const uint8_t *src, size_t src_size,
                                         uint8_t *dst, size_t *dst_size,
                                         rsa_padding_t padding);

/*
 * Decrypt with rsa private key
 *
 * rsa_key[in]:  rsa key struct
 * src[in]:       buffer, to be decrypted
 * src_size:      src length in bytes
 * dst[in]:       dst, to save the decrypted result
 * dst_size:      dst length pointer
 * padding:       rsa padding type
 */
ali_crypto_result ali_rsa_private_decrypt(const rsa_key_t *rsa_key,
                                          const uint8_t *src, size_t src_size,
                                          uint8_t *dst, size_t *dst_size,
                                          rsa_padding_t padding);

/*
 * Sign with rsa keypair
 *
 * rsa_key[in]:      rsa key pair
 * dig[in]:          the digest to sign
 * dig_size[in]:     the length of the digest to sign (byte)
 * sig[out]:         the signature data
 * sig_size[in/out]: the buffer size and resulting size of signature
 */
ali_crypto_result ali_rsa_sign(const rsa_key_t *rsa_key,
                               const uint8_t *dig, size_t dig_size,
                               uint8_t *sig, size_t *sig_size, rsa_padding_t padding);

/*
 * Verify with rsa public key
 *
 * dig[in]:      the digest of message that was signed
 * dig_size[in]: the digest size in bytes
 * sig[in]:      the signature data
 * sig_size[in]: the length of the signature data (byte)
 *
 * return: ali_crypto_result error code
 */
ali_crypto_result ali_rsa_verify(const rsa_key_t *rsa_key,
                                 const uint8_t *dig, size_t dig_size,
                                 const uint8_t *sig, size_t sig_size,
                                 rsa_padding_t padding, bool *result);

/* ecc */

/*
 * ECC Init Key Type
 */
typedef enum {
    ECC_PUBKEY  = 3,   // ECC Public Key
    ECC_KEYPAIR,       // ECC Key Pair
} ecc_key_type_t;

/*
 * Initialize ecc key handler(sm2 belongs to ecc key type)
 *
 * key[out]:       ecc key struct
 * keytype[in]:    ecc key type(defined in ecc_key_type_t)
 * curve[in]:      curve type id
 * x[in]:          x coordinate of pub key
 * x_size[in]:     x length in bytes
 * y[in]:          y coordinate of pub key
 * y_size[in]:     y length in bytes
 * d[in]:          secret value
 * d_size:         secret length in bytes
 *
 * return: ali_crypto_result error code
 */
ali_crypto_result ali_ecc_init_key(ecc_key_t *key,
                                   ecc_key_type_t keytype,
                                   ecp_curve_id_t curve,
                                   uint8_t *x, size_t x_size,
                                   uint8_t *y, size_t y_size,
                                   uint8_t *d, size_t d_size);

/*
 * Cleanup ecc key
 *
 * key[in]:  ecc key struct
 * type[in]: key type (RSA_PUBKEY/RSA_KEYPAIR)
 */
void ali_ecc_clean(ecc_key_t *key);

/*
 * Generate ecc key pair(sm2 belongs to ecc key type)
 *
 * curve[in]:   curve type id
 * key[out]:    output buffer, which is used to save generated ecc key pair
 *
 * return:      ali_crypto_result error code
 */
ali_crypto_result ali_ecc_gen_keypair(ecp_curve_id_t curve, ecc_key_t *key);

/*
 * Encrypt with sm2 public key
 *
 * sm2_key[in]:   sm2 key struct
 * src[in]:       buffer, to be encrypted
 * src_size:      src length in bytes
 * dst[in]:       dst, to save the encrypted result
 * dst_size:      dst length pointer
 * padding:       sm2 padding type
 *
 * return:        ali_crypto_result error code
 */
ali_crypto_result ali_sm2_public_encrypt(const ecc_key_t *key,
                                         const uint8_t *src, size_t src_size,
                                         uint8_t *dst, size_t *dst_size);

/*
 * Decrypt with sm2 private key
 *
 * key[in]:       sm2 key struct
 * src[in]:       buffer, to be decrypted
 * src_size:      src length in bytes
 * dst[out]:      dst, to save the decrypted result
 * dst_size:      dst length pointer
 *
 * return:        ali_crypto_result error code
 */
ali_crypto_result ali_sm2_private_decrypt(const ecc_key_t *key,
                                          const uint8_t *src, size_t src_size,
                                          uint8_t *dst, size_t *dst_size);

/*
 * [Note: only need this api in case user id is considered]
 * Compute signature with raw msg and id and sm2 key
 *
 * key[in]:       sm2 key struct
 * hash:          hash type
 * id:            user identifier
 * id_size:       id length in bytes
 * msg:           input message
 * msg_size:      message length in bytes
 * sig[out]:      signature
 * sig_size:      signature length pointer
 *
 * return:        ali_crypto_result error code
 */
ali_crypto_result ali_sm2_msg_sign(const ecc_key_t *key,
                                   hash_type_t hash,
                                   const uint8_t *id,  size_t id_size,
                                   const uint8_t *msg, size_t msg_size,
                                   uint8_t *sig, size_t *sig_size);

/*
 * [Note: only need this api in case user id is considered]
 * Verify signature accroding to raw msg and id and sm2 key
 *
 * key[in]:       sm2 key struct
 * hash:          hash type
 * id:            user identifier
 * id_size:       id length in bytes
 * msg:           input message
 * msg_size:      message length in bytes
 * sig[in]:       signature value to be verified
 * sig_size:      signature length pointer
 * result[out]:   true: verify pass, false: verify fail
 *
 * return:        ali_crypto_result error code
 */
ali_crypto_result ali_sm2_msg_verify(const ecc_key_t *key,
                                     hash_type_t hash,
                                     const uint8_t *id,  size_t id_size,
                                     const uint8_t *msg, size_t msg_size,
                                     const uint8_t *sig, size_t sig_size,
                                     bool *result);

/*
 * Sign with SM2 Private Key
 *
 * key[in]:       sm2 key struct
 * dig[in]:       digest, to be signed
 * dig_size:      msg length in bytes
 * sig[out]:      signature, to save the signed result
 * sig_size:      signature buffer length pointer
 *
 * return:        ali_crypto_result error code
 */
ali_crypto_result ali_sm2_sign(const ecc_key_t *key,
                               const uint8_t *dig, size_t dig_size,
                               uint8_t *sig, size_t *sig_size);

/*
 * Verify with SM2 Public Key
 *
 * key[in]:       sm2 key struct
 * dig[in]:       digest, to be signed
 * dig_size:      digest length in bytes
 * sig[in]:       sigature buffer to be verified
 * sig_size:      signaure buffer length
 * result[out]:   true: verify pass, false: verify fail
 *
 * return:        ali_crypto_result error code
 */
ali_crypto_result ali_sm2_verify(const ecc_key_t *key,
                                 const uint8_t *dig, size_t dig_size,
                                 const uint8_t *sig, size_t sig_size,
                                 bool *result);

/*
 * Set seed for random generator
 * seed[in]: seed data buffer
 * seed_len: length of seed data buffer
 */
ali_crypto_result ali_seed(uint8_t *seed, size_t seed_len);

/*
 * Generate random data and fill input buf
 * buf[in]: input data buffer
 * len[in]: length of buf
 */
ali_crypto_result ali_rand_gen(uint8_t *buf, size_t len);

/*
 * Write a public key to a ASN1(DER) structure
 *
 * key[in]       public key to write away
 * key_type[in]  key type(rsa/ec/sm)
 * buf[out]      buffer to write to
 * size[inout]    size of the buffer
 *
 * return        error code
 */
ali_crypto_result ali_pk_write_pubkey_der(icrypt_key_data_t *key, uint8_t *buf, size_t *size);

/*
 * Parse a public key ASN1(DER) format to key struct(RSA/ECC)
 *
 * buf[in]       input buffer
 * size[in]      size of the buffer
 * key[out]      key struct
 *
 * return        error code
 */
ali_crypto_result ali_pk_parse_public_key(uint8_t *buf, size_t size, icrypt_key_data_t *key);

/*
 * Initialize(Optional)
 */
ali_crypto_result ali_crypto_init(void);

/*
 * Cleanup(Optional)
 */
void ali_crypto_cleanup(void);

#endif /* _ALI_CRYPTO_H_ */
