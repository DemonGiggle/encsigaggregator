#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

/**
 * read_file - read the entire file at path into a newly allocated buffer
 * @path: path to file
 * @buf: receives allocated buffer
 * @len: receives number of bytes read
 *
 * Return: 0 on success, -1 on failure.
 */
int read_file(const char *path, uint8_t **buf, size_t *len);

/**
 * ensure_outputs_not_exist - verify that all expected output files are absent
 * @out_path: base output path for ciphertext
 * @include_keys: non-zero when key and AES component files will be produced
 * @alg: signing algorithm that determines hybrid component requirements
 *
 * Return: 0 when no expected output files are present, -1 otherwise.
 */
int ensure_outputs_not_exist(const char *out_path, int include_keys, int alg);

int ensure_keygen_outputs_not_exist(int include_pk, int include_aes, int alg);

/**
 * write_outputs - write encrypted data, signature, and optional keys to files
 * @out_path: output file path
 * @include_keys: non-zero to include keys
 * @alg: signing algorithm
 * @privs: private keys (index 0 for first scheme, 1 for second if hybrid)
 * @pubs: public keys (index 0 for first scheme, 1 for second if hybrid)
 * @aes_key: AES key buffer
 * @aes_key_len: length of AES key
 * @iv: initialization vector
 * @sigs: signature buffers (index 0 for first scheme, 1 for second if hybrid)
 * @sig_lens: lengths of signatures (index 0 for first scheme, 1 for second if hybrid)
 * @enc: encrypted data
 * @enc_len: length of encrypted data
 *
 * Return: 0 on success, -1 on failure.
 */
int write_outputs(const char *out_path, int include_keys, int alg,
                  const crypto_key privs[2], const crypto_key pubs[2],
                  const uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE],
                  size_t aes_key_len,
                  const uint8_t iv[CRYPTO_AES_IV_SIZE],
                  const uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE],
                  const size_t sig_lens[2],
                  const uint8_t *enc, size_t enc_len);

int write_keygen_outputs(int alg, int include_pk, int include_aes,
                         const crypto_key privs[2], const crypto_key pubs[2],
                         const uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE],
                         size_t aes_key_len,
                         const uint8_t iv[CRYPTO_AES_IV_SIZE]);

#endif /* UTIL_H */
