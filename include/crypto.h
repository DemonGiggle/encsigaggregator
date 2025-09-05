#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AES key sizes in bits */
#define CRYPTO_AES_KEY_BITS_128 128
#define CRYPTO_AES_KEY_BITS_192 192
#define CRYPTO_AES_KEY_BITS_256 256

/* Size of the CBC initialization vector in bytes */
#define CRYPTO_AES_IV_SIZE 16
/* Maximum AES key size in bytes (AES-256) */
#define CRYPTO_AES_MAX_KEY_SIZE 32

/* Parameters for RSA4096 key generation */
#define CRYPTO_RSA_BITS 4096       /* modulus size in bits */
#define CRYPTO_RSA_EXPONENT 65537  /* public exponent */
/* RSA signature size in bytes for a 4096-bit key */
#define CRYPTO_RSA_SIG_SIZE (CRYPTO_RSA_BITS / 8)

/* Output size of SHA-384 in bytes */
#define CRYPTO_SHA384_DIGEST_SIZE 48

/* Length of the random seed used to generate LMS keys */
#define CRYPTO_LMS_SEED_SIZE 32

/* Buffer large enough to hold any supported signature */
#define CRYPTO_MAX_SIG_SIZE 10240

typedef enum {
    CRYPTO_ALG_RSA4096,
    CRYPTO_ALG_LMS,
    CRYPTO_ALG_MLDSA87,
    CRYPTO_ALG_RSA4096_LMS,
    CRYPTO_ALG_RSA4096_MLDSA87,
    CRYPTO_ALG_LMS_MLDSA87
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
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len);
int crypto_decrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[CRYPTO_AES_IV_SIZE],
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len);

int crypto_sha384(const uint8_t *in, size_t len,
                  uint8_t out[CRYPTO_SHA384_DIGEST_SIZE]);

int crypto_export_keypair(crypto_alg alg, const crypto_key *priv,
                          const crypto_key *pub, crypto_key *out_priv,
                          crypto_key *out_pub);

int crypto_hybrid_export_keypairs(crypto_alg alg, const crypto_key *priv,
                                  const crypto_key *pub,
                                  crypto_key out_priv[2],
                                  crypto_key out_pub[2]);

int crypto_hybrid_get_sig_lens(crypto_alg alg, size_t *len1, size_t *len2);

void crypto_free_key(crypto_key *key);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
