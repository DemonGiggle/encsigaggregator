#ifndef LMS_H
#define LMS_H

#include "crypto.h"
#include <mbedtls/ctr_drbg.h>

/** @brief Generate an LMS key pair using the provided DRBG. */
int lms_keygen(mbedtls_ctr_drbg_context *drbg, crypto_key *out_priv, crypto_key *out_pub);

/** @brief Load an LMS key pair from files; currently always generates a fresh pair. */
int lms_load_keypair(const char *priv_path, const char *pub_path,
                     crypto_key *out_priv, crypto_key *out_pub);

/** @brief Sign a message with an LMS private key. */
int lms_sign(mbedtls_ctr_drbg_context *drbg, const crypto_key *priv,
             const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len);

/** @brief Verify an LMS signature. */
int lms_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len);

/** @brief Serialize an LMS key pair. */
int lms_export_keypair(const crypto_key *priv, const crypto_key *pub,
                       crypto_key *out_priv, crypto_key *out_pub);

/** @brief Release resources associated with an LMS key. */
void lms_free_key(crypto_key *key);

#endif /* LMS_H */
