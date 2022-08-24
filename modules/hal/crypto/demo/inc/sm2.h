/*
 * Copyright (C) 2018  Alibaba Group Holding Limited.
 */

#ifndef SM2_H
#define SM2_H

#include "ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IMPL_SM2_KEY_LEN (32)

/**
 * \brief Compute key derive function
 * \param K            shared key to be returned
 * \param klen         the bit length of K
 * \param Z            the input data 
 * \param zlen         the byte length of Z
 * 
 */
void KDF( unsigned char *K, size_t klen, const unsigned char *Z, size_t zlen );

int impl_sm2_sign( impl_ecp_keypair *context,
                   const unsigned char *src, size_t src_size,
                   uint8_t *sig, size_t *sig_size,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int impl_sm2_verify( impl_ecp_keypair *context,
                     const uint8_t *src, size_t src_size,
                     const uint8_t *sig, size_t sig_size );

int impl_sm2_encrypt( impl_ecp_keypair *ctx,
                      const unsigned char *src, size_t src_size,
                      unsigned char *dst, size_t *dst_size,
                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int impl_sm2_decrypt( impl_ecp_keypair *ctx,
                      const unsigned char *C, size_t clen,
                      unsigned char *M, size_t *mlen );

int impl_sm2dh_compute_shared( impl_ecp_group *grp,
                               impl_mpi *K, const size_t secret_size,
                               const impl_mpi *ZA, const impl_mpi *ZB,
                               const impl_mpi *dA, const impl_mpi *rA,
                               const impl_ecp_point *RA,
                               const impl_ecp_point *RB,
                               const impl_ecp_point *PB );
/*
 * derive sm2 public key from d
 */
int impl_sm2_derive_p( impl_ecp_keypair *context,
                       unsigned char *dst, size_t *dst_size);

#ifdef __cplusplus
}
#endif

#endif /* sm2.h */
