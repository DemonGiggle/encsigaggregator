#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRYPTO_ALG_RSA4096,
    CRYPTO_ALG_LMS,
    CRYPTO_ALG_MLDSA87
} crypto_alg;

typedef struct {
    crypto_alg alg;
    void *key;
    size_t key_len;
} crypto_key;

int crypto_keygen(crypto_alg alg, crypto_key *out_priv, crypto_key *out_pub);
int crypto_load_keypair(crypto_alg alg, const char *priv_path, const char *pub_path,
                        crypto_key *out_priv, crypto_key *out_pub);
int crypto_init_aes(size_t bits, const char *key_path, const char *iv_path,
                    uint8_t *key_out, uint8_t iv_out[16]);
int crypto_sign(crypto_alg alg, const crypto_key *priv, const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len);
int crypto_verify(crypto_alg alg, const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

int crypto_encrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[16],
                          const uint8_t *in, size_t len, uint8_t *out);
int crypto_decrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[16],
                          const uint8_t *in, size_t len, uint8_t *out);

int crypto_sha384(const uint8_t *in, size_t len, uint8_t out[48]);

void crypto_free_key(crypto_key *key);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
