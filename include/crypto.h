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

/* Modulus size in bits for RSA-4096 */
#define CRYPTO_RSA_BITS 4096
/* Public exponent for RSA key generation */
#define CRYPTO_RSA_EXPONENT 65537
/* RSA signature size in bytes for a 4096-bit key */
#define CRYPTO_RSA_SIG_SIZE (CRYPTO_RSA_BITS / 8)

/* Output size of SHA-384 in bytes */
#define CRYPTO_SHA384_DIGEST_SIZE 48

/* Length of the random seed used to generate LMS keys */
#define CRYPTO_LMS_SEED_SIZE 32

/* Buffer large enough to hold any supported signature */
#define CRYPTO_MAX_SIG_SIZE 10240

/**
 * enum crypto_alg - supported cryptographic algorithm identifiers
 * @CRYPTO_ALG_RSA4096: RSA with 4096-bit modulus
 * @CRYPTO_ALG_LMS: Leighton-Micali Signature scheme
 * @CRYPTO_ALG_MLDSA87: ML-DSA with 87-byte signatures
 * @CRYPTO_ALG_RSA4096_LMS: Hybrid RSA-4096 and LMS
 * @CRYPTO_ALG_RSA4096_MLDSA87: Hybrid RSA-4096 and ML-DSA87
 * @CRYPTO_ALG_LMS_MLDSA87: Hybrid LMS and ML-DSA87
 */
typedef enum {
    CRYPTO_ALG_RSA4096,
    CRYPTO_ALG_LMS,
    CRYPTO_ALG_MLDSA87,
    CRYPTO_ALG_RSA4096_LMS,
    CRYPTO_ALG_RSA4096_MLDSA87,
    CRYPTO_ALG_LMS_MLDSA87
} crypto_alg;

/**
 * enum crypto_key_type - distinguishes public and private keys
 * @CRYPTO_KEY_TYPE_PRIVATE: private key
 * @CRYPTO_KEY_TYPE_PUBLIC: public key
 */
typedef enum {
    CRYPTO_KEY_TYPE_PRIVATE,
    CRYPTO_KEY_TYPE_PUBLIC,
} crypto_key_type;

/**
 * struct crypto_key - generic wrapper for algorithm-specific key material
 * @alg:     algorithm this key is for
 * @type:    whether the key is private or public
 * @key:     pointer to algorithm-specific key data
 * @key_len: length of key data in bytes
 */
typedef struct {
    crypto_alg alg;
    crypto_key_type type;
    void *key;
    size_t key_len;
} crypto_key;

/**
 * crypto_keygen - generate a key pair for the specified algorithm
 * @alg: algorithm identifier
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_keygen(crypto_alg alg, crypto_key *out_priv, crypto_key *out_pub);

/**
 * crypto_load_keypair - load an existing key pair or generate a new one
 * @alg: algorithm identifier
 * @priv_path: path to private key file or NULL
 * @pub_path: path to public key file or NULL
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_load_keypair(crypto_alg alg, const char *priv_path, const char *pub_path,
                        crypto_key *out_priv, crypto_key *out_pub);

/**
 * crypto_init_aes - initialize an AES key and IV
 * @bits: key size in bits
 * @key_path: optional path to key file
 * @iv_path: optional path to IV file
 * @key_out: buffer for generated key
 * @iv_out: buffer for generated IV
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_init_aes(size_t bits, const char *key_path, const char *iv_path,
                    uint8_t *key_out, uint8_t iv_out[CRYPTO_AES_IV_SIZE]);

/**
 * crypto_sign - sign the input message using the given private key
 * @alg: algorithm identifier
 * @priv: private key
 * @msg: message to sign
 * @msg_len: length of the message
 * @sig: output buffer for the signature
 * @sig_len: in/out signature length
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_sign(crypto_alg alg, const crypto_key *priv, const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len);

/**
 * crypto_verify - verify a signature against the input message and public key
 * @alg: algorithm identifier
 * @pub: public key
 * @msg: message that was signed
 * @msg_len: length of the message
 * @sig: signature to verify
 * @sig_len: length of the signature
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_verify(crypto_alg alg, const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

/**
 * crypto_encrypt_aescbc - encrypt using AES-CBC with PKCS#7 padding
 * @key: AES key
 * @bits: key size in bits
 * @iv: initialization vector
 * @in: input buffer
 * @len: length of input buffer
 * @out: output buffer
 * @out_len: on return, length of output
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_encrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[CRYPTO_AES_IV_SIZE],
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len);

/**
 * crypto_decrypt_aescbc - decrypt using AES-CBC with PKCS#7 padding
 * @key: AES key
 * @bits: key size in bits
 * @iv: initialization vector
 * @in: input buffer
 * @len: length of input buffer
 * @out: output buffer
 * @out_len: on return, length of output
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_decrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[CRYPTO_AES_IV_SIZE],
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len);

/**
 * crypto_sha384 - compute SHA-384 over the input buffer
 * @in: input buffer
 * @len: length of input
 * @out: output hash buffer
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_sha384(const uint8_t *in, size_t len,
                  uint8_t out[CRYPTO_SHA384_DIGEST_SIZE]);

/**
 * crypto_export_keypair - serialize a key pair to memory buffers
 * @alg: algorithm identifier
 * @priv: private key
 * @pub: public key
 * @out_priv: serialized private key output
 * @out_pub: serialized public key output
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_export_keypair(crypto_alg alg, const crypto_key *priv,
                          const crypto_key *pub, crypto_key *out_priv,
                          crypto_key *out_pub);

/**
 * crypto_hybrid_export_keypairs - export both components of a hybrid key pair
 * @alg: hybrid algorithm identifier
 * @priv: private hybrid key
 * @pub: public hybrid key
 * @out_priv: array to receive component private keys
 * @out_pub: array to receive component public keys
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_hybrid_export_keypairs(crypto_alg alg, const crypto_key *priv,
                                  const crypto_key *pub,
                                  crypto_key out_priv[2],
                                  crypto_key out_pub[2]);

/**
 * crypto_is_hybrid_alg - test if algorithm identifier represents a hybrid scheme
 * @alg: algorithm identifier
 *
 * Return: non-zero if @alg is a hybrid scheme, 0 otherwise.
 */
int crypto_is_hybrid_alg(crypto_alg alg);

/**
 * crypto_hybrid_get_algs - determine the underlying algorithms for a hybrid scheme
 * @alg: hybrid algorithm identifier
 * @first: receives first algorithm
 * @second: receives second algorithm
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_hybrid_get_algs(crypto_alg alg, crypto_alg *first,
                           crypto_alg *second);

/**
 * crypto_hybrid_get_sig_lens - get signature lengths for a hybrid algorithm
 * @alg: hybrid algorithm identifier
 * @len1: receives first signature length
 * @len2: receives second signature length
 *
 * Return: 0 on success, -1 on error.
 */
int crypto_hybrid_get_sig_lens(crypto_alg alg, size_t *len1, size_t *len2);

/**
 * crypto_free_key - release any resources held by a key
 * @key: key to free
 */
void crypto_free_key(crypto_key *key);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
