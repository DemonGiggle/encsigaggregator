#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Algorithm related constants */
#define CRYPTO_AES_KEY_BITS_128 128
#define CRYPTO_AES_KEY_BITS_192 192
#define CRYPTO_AES_KEY_BITS_256 256

#define CRYPTO_AES_IV_SIZE 16
#define CRYPTO_AES_MAX_KEY_SIZE 32

#define CRYPTO_RSA_BITS 4096
#define CRYPTO_RSA_EXPONENT 65537
#define CRYPTO_RSA_SIG_SIZE (CRYPTO_RSA_BITS / 8)

#define CRYPTO_SHA384_DIGEST_SIZE 48

#define CRYPTO_LMS_SEED_SIZE 32

#define CRYPTO_MAX_SIG_SIZE 10240

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
                    uint8_t *key_out, uint8_t iv_out[CRYPTO_AES_IV_SIZE]);
int crypto_sign(crypto_alg alg, const crypto_key *priv, const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len);
int crypto_verify(crypto_alg alg, const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

int crypto_encrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[CRYPTO_AES_IV_SIZE],
                          const uint8_t *in, size_t len, uint8_t *out);
int crypto_decrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[CRYPTO_AES_IV_SIZE],
                          const uint8_t *in, size_t len, uint8_t *out);

int crypto_sha384(const uint8_t *in, size_t len,
                  uint8_t out[CRYPTO_SHA384_DIGEST_SIZE]);

void crypto_free_key(crypto_key *key);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
