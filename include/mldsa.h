#ifndef MLDSA_H
#define MLDSA_H

#include "crypto.h"
#include "api.h"

/** @brief Generate an ML-DSA key pair. */
int mldsa_keygen(crypto_key *out_priv, crypto_key *out_pub);

/** @brief Load an ML-DSA key pair from the given files. */
int mldsa_load_keypair(const char *priv_path, const char *pub_path,
                       crypto_key *out_priv, crypto_key *out_pub);

/** @brief Produce an ML-DSA signature. */
int mldsa_sign(const crypto_key *priv, const uint8_t *msg, size_t msg_len,
               uint8_t *sig, size_t *sig_len);

/** @brief Verify an ML-DSA signature. */
int mldsa_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len);

/** @brief Serialize an ML-DSA key pair. */
int mldsa_export_keypair(const crypto_key *priv, const crypto_key *pub,
                         crypto_key *out_priv, crypto_key *out_pub);

/** @brief Release resources for an ML-DSA key. */
void mldsa_free_key(crypto_key *key);

#endif /* MLDSA_H */
