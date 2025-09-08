#ifndef RSA_H
#define RSA_H

#include "crypto.h"
#include <mbedtls/ctr_drbg.h>

/** @brief Generate an RSA-4096 key pair using the provided DRBG. */
int rsa_keygen(mbedtls_ctr_drbg_context *drbg, crypto_key *out_priv, crypto_key *out_pub);

/** @brief Load an RSA key pair from files. */
int rsa_load_keypair(const char *priv_path, const char *pub_path,
                     crypto_key *out_priv, crypto_key *out_pub);

/** @brief Produce an RSA signature. */
int rsa_sign(mbedtls_ctr_drbg_context *drbg, const crypto_key *priv,
             const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len);

/** @brief Verify an RSA signature. */
int rsa_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len);

/** @brief Serialize an RSA key pair. */
int rsa_export_keypair(const crypto_key *priv, const crypto_key *pub,
                       crypto_key *out_priv, crypto_key *out_pub);

/** @brief Release resources associated with an RSA key. */
void rsa_free_key(crypto_key *key);

#endif /* RSA_H */
