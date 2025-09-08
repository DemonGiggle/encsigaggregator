#ifndef MLDSA_H
#define MLDSA_H

#include "crypto.h"
#include "api.h"

/**
 * mldsa_keygen - generate an ML-DSA key pair
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int mldsa_keygen(crypto_key *out_priv, crypto_key *out_pub);

/**
 * mldsa_load_keypair - load an ML-DSA key pair from files
 * @priv_path: path to private key file or NULL
 * @pub_path: path to public key file or NULL
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int mldsa_load_keypair(const char *priv_path, const char *pub_path,
                       crypto_key *out_priv, crypto_key *out_pub);

/**
 * mldsa_sign - produce an ML-DSA signature
 * @priv: private key
 * @msg: message to sign
 * @msg_len: length of the message
 * @sig: output buffer for the signature
 * @sig_len: in/out signature length
 *
 * Return: 0 on success, -1 on error.
 */
int mldsa_sign(const crypto_key *priv, const uint8_t *msg, size_t msg_len,
               uint8_t *sig, size_t *sig_len);

/**
 * mldsa_verify - verify an ML-DSA signature
 * @pub: public key
 * @msg: signed message
 * @msg_len: length of the message
 * @sig: signature to verify
 * @sig_len: length of the signature
 *
 * Return: 0 on success, -1 on error.
 */
int mldsa_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len);

/**
 * mldsa_export_keypair - serialize an ML-DSA key pair
 * @priv: private key
 * @pub: public key
 * @out_priv: serialized private key output
 * @out_pub: serialized public key output
 *
 * Return: 0 on success, -1 on error.
 */
int mldsa_export_keypair(const crypto_key *priv, const crypto_key *pub,
                         crypto_key *out_priv, crypto_key *out_pub);

/**
 * mldsa_free_key - release resources for an ML-DSA key
 * @key: key to free
 */
void mldsa_free_key(crypto_key *key);

#endif /* MLDSA_H */
