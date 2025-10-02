#ifndef LMS_H
#define LMS_H

#include "crypto.h"
#include <mbedtls/ctr_drbg.h>

/**
 * lms_keygen - generate an LMS key pair using the provided DRBG
 * @drbg: DRBG context
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int lms_keygen(mbedtls_ctr_drbg_context *drbg, crypto_key *out_priv, crypto_key *out_pub);

/**
 * lms_load_keypair - load an LMS key pair from files
 * @priv_path: path to private key file or NULL
 * @pub_path: path to public key file or NULL
 * @out_priv: private key output
 * @out_pub: public key output
 *
 * Return: 0 on success, -1 on error.
 */
int lms_load_keypair(const char *priv_path, const char *pub_path,
                     crypto_key *out_priv, crypto_key *out_pub);

/**
 * lms_sign - sign a message with an LMS private key
 * @drbg: DRBG context
 * @priv: private key
 * @msg: message to sign
 * @msg_len: length of the message
 * @sig: output buffer for the signature
 * @sig_len: in/out signature length
 *
 * Return: 0 on success, -1 on error.
 */
int lms_sign(mbedtls_ctr_drbg_context *drbg, const crypto_key *priv,
             const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len);

/**
 * lms_verify - verify an LMS signature
 * @pub: public key
 * @msg: signed message
 * @msg_len: length of the message
 * @sig: signature to verify
 * @sig_len: length of the signature
 *
 * Return: 0 on success, -1 on error.
 */
int lms_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len);

/**
 * lms_export_keypair - serialize an LMS key pair
 * @priv: private key
 * @pub: public key
 * @out_priv: serialized private key output
 * @out_pub: serialized public key output
 *
 * Return: 0 on success, -1 on error.
 */
int lms_export_keypair(const crypto_key *priv, const crypto_key *pub,
                       crypto_key *out_priv, crypto_key *out_pub);

/**
 * lms_export_raw_pk - export the raw bytes of an LMS public key
 * @pub: public key to export
 * @out_pk: on success, pointer to allocated buffer with key bytes
 * @out_len: on success, length of the exported buffer
 *
 * Return: 0 on success, -1 on error.
 */
int lms_export_raw_pk(const crypto_key *pub, uint8_t **out_pk, size_t *out_len);

/**
 * lms_free_key - release resources associated with an LMS key
 * @key: key to free
 */
void lms_free_key(crypto_key *key);

#endif /* LMS_H */
