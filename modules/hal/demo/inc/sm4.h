/**
* Copyright (C) 2017-2019 Alibaba Group Holding Limited.
**/

#ifndef SM4_H
#define SM4_H

#include "ls_osa.h"

/* padlock.c rely on these values! */
#define IMPL_SM4_ENCRYPT     1
#define IMPL_SM4_DECRYPT     0

#define SM4_INVALID_KEY_LENGTH                -0x0020  /* Invalid key length. */
#define SM4_INVALID_INPUT_LENGTH              -0x0022  /* Invalid data input length. */

#define CHASKEY_BLOCK_SIZE   16
#define SM4_BLOCK_SIZE       16
#define SM4_IV_SIZE          16

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM4 context structure
 *
 * \note           buf is able to hold extra bytes, which can be used:
 *                 - for alignment purposes if VIA padlock is used
 *                 - to simplify key expansion 
 */
typedef struct
{
    int nr;                     /*!<  number of rounds  */
    uint32_t *rk;               /*!<  SM4 round keys    */
    uint32_t buf[68];           /*!<  unaligned data    */
}
impl_sm4_context;

typedef enum _impl_sm4_type_t {
    HAL_SM4_ECB         = 0,
    HAL_SM4_CBC         = 1,
    HAL_SM4_CTR         = 2,
} impl_sm4_type_t;

typedef struct {
    uint32_t             mode;
    impl_sm4_type_t      type;
    uint8_t              iv[SM4_IV_SIZE];
    size_t               offset;
    uint8_t              stream_block[CHASKEY_BLOCK_SIZE];
    impl_sm4_context     ctx;
} impl_sm4_ctx_t;

/**
 * \brief          Initialize SM4 context
 *
 * \param ctx      SM4 context to be initialized
 */
void impl_sm4_init(impl_sm4_context *ctx);

/**
 * \brief          Clear SM4 context
 *
 * \param ctx      SM4 context to be cleared
 */
void impl_sm4_free(impl_sm4_context *ctx);

/**
 * \brief          SM4 key schedule 
 *
 * \param ctx      SM4 context to be initialized
 * \param key      encryption or decryption key
 * \param keybits  must be 128
 *
 * \return         0 if successful, or SM4_INVALID_KEY_LENGTH
 */
int impl_sm4_setkey(impl_sm4_context *ctx,
                    const unsigned char *key,
                    unsigned int keybits );
/**
 * \brief          SM4-ECB block encryption/decryption
 *
 * \param ctx      SM4 context
 * \param mode     ALI_ALGO_SM4_ENCRYPT or ALI_ALGO_SM4_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful
 */
int impl_sm4_crypt_ecb(impl_sm4_context *ctx,
                       int mode,
                       const unsigned char input[16],
                       unsigned char output[16] );

/**
 * \brief          SM4-CBC block encryption/decryption
 *
 * \param ctx      SM4 context
 * \param mode     ALI_ALGO_SM4_ENCRYPT or ALI_ALGO_SM4_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful
 */
int impl_sm4_crypt_cbc(impl_sm4_context *ctx,
                       int mode,
                       size_t length,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output);

/**
 * \brief          SM4-CTR block encryption/decryption
 *
 * Warning: You have to keep the maximum use of your counter in mind!
 *
 * Note: Due to the nature of CTR you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * ali_algo_sm4_setkey_enc() for both ALI_ALGO_SM4_ENCRYPT and ALI_ALGO_SM4_DECRYPT.
 *
 * \param ctx           SM4 context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 128-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return         0 if successful
 */
int impl_sm4_crypt_ctr(impl_sm4_context *ctx,
                       size_t length, size_t *nc_off,
                       unsigned char nonce_counter[16],
			           unsigned char stream_block[16],
			           const unsigned char *input,
                       unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif /* sm4.h */
