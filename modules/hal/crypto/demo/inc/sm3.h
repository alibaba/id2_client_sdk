/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

#ifndef __SM3_H__
#define __SM3_H__

#include "ls_osa.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IMPL_SM3_HASH_LEN (32)

/**
 * \brief          SM3 context structure
 */
typedef struct {
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[8];          /*!< intermediate digest state  */
    uint8_t buffer[64];         /*!< data block being processed */
} impl_sm3_context;

typedef struct {
    impl_sm3_context context;
} impl_sm3_ctx_t;

/**
 * \brief          Initialize SM3 context
 *
 * \param ctx      SM3 context to be initialized
 */
void impl_sm3_init(impl_sm3_context *ctx);

/**
 * \brief          Clear SM3 context
 *
 * \param ctx      SM3 context to be cleared
 */
void impl_sm3_free(impl_sm3_context *ctx);

/**
 * \brief          Clone (the state of) a SM3 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void impl_sm3_clone(impl_sm3_context *dst,
                    const impl_sm3_context *src);

/**
 * \brief          SM3 context setup
 *
 * \param ctx      context to be initialized
 */
void impl_sm3_starts(impl_sm3_context *ctx);

/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void impl_sm3_update(impl_sm3_context *ctx, const uint8_t *input, size_t ilen);

/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 * \param output   SM3 checksum result
 */
void impl_sm3_finish(impl_sm3_context *ctx, uint8_t output[20]);

/* Internal use */
void impl_sm3_process(impl_sm3_context *ctx, const uint8_t data[64]);

#ifdef __cplusplus
}
#endif

#endif /* __SM3_H__ */
