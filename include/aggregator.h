#ifndef AGGREGATOR_H
#define AGGREGATOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AGG_ALG_RSA4096,
    AGG_ALG_LMS,
    AGG_ALG_MLDSA87
} agg_alg;

typedef struct {
    agg_alg alg;
    void *key;
    size_t key_len;
} agg_key;

int agg_keygen(agg_alg alg, agg_key *out_priv, agg_key *out_pub);
int agg_sign(agg_alg alg, const agg_key *priv, const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len);
int agg_verify(agg_alg alg, const agg_key *pub, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len);

int agg_encrypt_aes256cbc(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t *in, size_t len, uint8_t *out);
int agg_decrypt_aes256cbc(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t *in, size_t len, uint8_t *out);

void agg_free_key(agg_key *key);

#ifdef __cplusplus
}
#endif

#endif /* AGGREGATOR_H */
