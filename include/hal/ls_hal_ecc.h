/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

#ifndef __LS_HAL_ECC_H__
#define __LS_HAL_ECC_H__

/********************************************************************/
/*              ECC HAL CRYPTO API                                 */
/********************************************************************/

/*
 * hal ecc key pair struct definition
 * 
 * x/y/d: ecc key pair elements
 *
 */
typedef struct _hal_ecc_keypair_t {
    size_t   key_bytes;
    uint8_t  *x;
    size_t   x_size;
    uint8_t  *y;
    size_t   y_size;
    uint8_t  *d;
    size_t   d_size;
} hal_ecc_keypair_t;

/*
 * Return the hal ecc ctx size for hal ecc process
 * the hal ctx should defined by the user according 
 * to the user's implementation
 */
int ls_hal_ecc_get_ctx_size(void);

/*
 * Initialize the hal_ecc_ctx
 *
 * context[in]: hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_ecc_get_ctx_size()
 */
int ls_hal_ecc_init(void *context);

/*
 * Initialize the ctx for ecc public key operation
 *
 * ctx[in]: hal_ctx, must be pre-allocated by the caller,
 *          the size is got through ls_hal_ecc_get_ctx_size()
 * grpid:   ecp group id(defined in impl_ecp_group_id)
 * x/y:     elements required to generate ecc public key
 */
int ls_hal_ecc_init_pubkey(void *ctx, int grp_id,
                           const uint8_t *x, size_t x_size,
                           const uint8_t *y, size_t y_size);

/*
 * Initialize the ctx for ecc keypair operation
 *
 * ctx[in]: hal_ctx, must be pre-allocated by the caller,
 *          the size is got through ls_hal_ecc_get_ctx_size()
 * grpid:   ecp group id(defined in impl_ecp_group_id)
 * x/y/d:   ecc key pair elements
 */
int ls_hal_ecc_init_keypair(void *context, int grp_id,
                            const uint8_t *x, size_t x_size,
                            const uint8_t *y, size_t y_size,
                            const uint8_t *d, size_t d_size);

/* 
 * ecc keypair generation
 *
 * context[in]: hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_ecc_get_ctx_size()
 * f_rng:       Random function
 * p_rng:       Random seed
 * nbits:       number of key bits
 * exponent:    exponent
 * keypair:     generated keypair contents (in format of hal_ecc_keypair_t)
 */
int ls_hal_ecc_gen_keypair(void *context,
                           int grp_id,
                           int (*f_rng)(void *, uint8_t *, size_t),
                           void *p_rng,
                           hal_ecc_keypair_t *keypair);

/**
 * \brief          Free the components of an SM2 key
 *
 * \param ctx      SM2 Context to free
 */
void ls_hal_ecc_cleanup(void *context);

#endif // __LS_HAL_ECC_H__
