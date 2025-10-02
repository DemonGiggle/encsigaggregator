#ifndef HYBRID_CRYPTO_H
#define HYBRID_CRYPTO_H

#include "crypto.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hybrid algorithm identifiers overlaying primitive crypto algorithms */
typedef enum {
    CRYPTO_ALG_RSA4096_LMS = CRYPTO_ALG_ENUM_END,
    CRYPTO_ALG_RSA4096_MLDSA87,
    CRYPTO_ALG_LMS_MLDSA87,
} hybrid_alg;

int crypto_is_hybrid_alg(int alg);
int crypto_hybrid_get_algs(hybrid_alg alg, crypto_alg *first, crypto_alg *second);
int crypto_hybrid_get_sig_lens(hybrid_alg alg, size_t *len1, size_t *len2);

int hybrid_crypto_keygen(hybrid_alg alg, crypto_key privs[2], crypto_key pubs[2]);
int hybrid_crypto_load_keypair(hybrid_alg alg, const char *priv_paths,
                               const char *pub_paths, crypto_key privs[2],
                               crypto_key pubs[2]);
int hybrid_crypto_sign(hybrid_alg alg, const crypto_key privs[2],
                       const uint8_t *msg, size_t msg_len,
                       uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE],
                       size_t sig_lens[2]);
int hybrid_crypto_verify(hybrid_alg alg, const crypto_key pubs[2],
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE],
                         const size_t sig_lens[2]);
int hybrid_crypto_export_keypairs(hybrid_alg alg, const crypto_key privs[2],
                                  const crypto_key pubs[2],
                                  crypto_key out_privs[2],
                                  crypto_key out_pubs[2]);

/**
 * hybrid_crypto_export_pk - export raw public keys for a hybrid algorithm
 * @alg: hybrid algorithm identifier
 * @pubs: array of two public keys corresponding to @alg
 * @out_pks: output array of two pointers that will receive allocated buffers
 * @out_lens: output array of lengths for each public key buffer
 *
 * Return: 0 on success, -1 on error.
 */
int hybrid_crypto_export_pk(hybrid_alg alg, const crypto_key pubs[2],
                            uint8_t **out_pks, size_t out_lens[2]);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_CRYPTO_H */
