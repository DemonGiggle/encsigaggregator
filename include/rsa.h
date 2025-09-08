#ifndef RSA_H
#define RSA_H

#include "crypto.h"
#include <mbedtls/ctr_drbg.h>

/**
 * rsa_keygen - generate an RSA-4096 key pair using the provided DRBG
 * @drbg: DRBG context
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int rsa_keygen(mbedtls_ctr_drbg_context *drbg, crypto_key *out_priv, crypto_key *out_pub);

/**
 * rsa_load_keypair - load an RSA key pair from files
 * @priv_path: path to private key file or NULL
 * @pub_path: path to public key file or NULL
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int rsa_load_keypair(const char *priv_path, const char *pub_path,
                     crypto_key *out_priv, crypto_key *out_pub);

/**
 * rsa_sign - produce an RSA signature
 * @drbg: DRBG context
 * @priv: private key
 * @msg: message to sign
 * @msg_len: length of the message
 * @sig: output buffer for the signature
 * @sig_len: in/out signature length
 *
 * Return: 0 on success, -1 on error.
 */
int rsa_sign(mbedtls_ctr_drbg_context *drbg, const crypto_key *priv,
             const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len);

/**
 * rsa_verify - verify an RSA signature
 * @pub: public key
 * @msg: signed message
 * @msg_len: length of the message
 * @sig: signature to verify
 * @sig_len: length of the signature
 *
 * Return: 0 on success, -1 on error.
 */
int rsa_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len);

/**
 * rsa_export_keypair - serialize an RSA key pair
 * @priv: private key
 * @pub: public key
 * @out_priv: serialized private key output
 * @out_pub: serialized public key output
 *
 * Return: 0 on success, -1 on error.
 */
int rsa_export_keypair(const crypto_key *priv, const crypto_key *pub,
                       crypto_key *out_priv, crypto_key *out_pub);

/**
 * rsa_free_key - release resources associated with an RSA key
 * @key: key to free
 */
void rsa_free_key(crypto_key *key);

#endif /* RSA_H */
