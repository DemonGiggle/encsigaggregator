#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

/**
 * @brief Read the entire file at path into a newly allocated buffer.
 *
 * On success, @p *buf will point to the allocated data and @p *len contains
 * the number of bytes read. The caller is responsible for freeing @p *buf.
 *
 * @return 0 on success, -1 on failure.
 */
int read_file(const char *path, uint8_t **buf, size_t *len);

/** @brief Write encrypted data, signature, and optional keys to output files. */
int write_outputs(const char *out_path, int include_keys,
                  const crypto_key *priv, const crypto_key *pub,
                  const uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE],
                  size_t aes_key_len,
                  const uint8_t iv[CRYPTO_AES_IV_SIZE],
                  const uint8_t *sig, size_t sig_len,
                  const uint8_t *enc, size_t enc_len);

#endif /* UTIL_H */
