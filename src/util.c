#include "util.h"
#include "api.h"
#include <mbedtls/lms.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int read_file(const char *path, uint8_t **buf, size_t *len)
{
    int ret = -1;
    FILE *f = fopen(path, "rb");
    uint8_t *tmp = NULL;
    if (f == NULL) {
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) {
        goto cleanup;
    }
    fseek(f, 0, SEEK_SET);
    tmp = malloc(sz);
    if (tmp == NULL) {
        goto cleanup;
    }
    if (fread(tmp, 1, sz, f) != (size_t)sz) {
        goto cleanup;
    }
    *buf = tmp;
    *len = sz;
    tmp = NULL;
    ret = 0;

cleanup:
    free(tmp);
    if (f != NULL) {
        fclose(f);
    }
    return ret;
}

/* write binary and hex representations to files */
static int write_bin_hex_pair(const char *bin_path, const char *hex_path,
                              const uint8_t *data, size_t len)
{
    FILE *f = fopen(bin_path, "wb");
    if (f == NULL) {
        return -1;
    }
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);

    f = fopen(hex_path, "w");
    if (f == NULL) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "0x%02x", data[i]);
        if (i + 1 < len) {
            fputc(',', f);
        }
        if ((i + 1) % 16 == 0) {
            fputc('\n', f);
        }
    }
    if (len % 16) {
        fputc('\n', f);
    }
    fclose(f);
    return 0;
}

static int write_component(const char *name, const uint8_t *data, size_t len)
{
    char bin_path[PATH_MAX];
    char hex_path[PATH_MAX];

    if (snprintf(bin_path, sizeof(bin_path), "%s.bin", name) >=
        (int)sizeof(bin_path)) {
        return -1;
    }
    if (snprintf(hex_path, sizeof(hex_path), "%s.hex", name) >=
        (int)sizeof(hex_path)) {
        return -1;
    }

    int ret = write_bin_hex_pair(bin_path, hex_path, data, len);
    if (ret == 0) {
        printf("%s binary: %s\n", name, bin_path);
        printf("%s hex: %s\n", name, hex_path);
    }
    return ret;
}

int write_outputs(const char *out_path, int include_keys,
                  const crypto_key *priv, const crypto_key *pub,
                  const uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE],
                  size_t aes_key_len, const uint8_t iv[CRYPTO_AES_IV_SIZE],
                  const uint8_t *sig, size_t sig_len, const uint8_t *enc,
                  size_t enc_len)
{
    char hex_path[PATH_MAX];

    if (snprintf(hex_path, sizeof(hex_path), "%s.hex", out_path) >=
        (int)sizeof(hex_path)) {
        return -1;
    }

    if (write_bin_hex_pair(out_path, hex_path, enc, enc_len) != 0) {
        return -1;
    }

    printf("ciphertext binary: %s\n", out_path);
    printf("ciphertext hex: %s\n", hex_path);

    int hybrid = crypto_is_hybrid_alg(priv->alg);
    size_t sig_lens[2] = {0};
    if (hybrid) {
        if (crypto_hybrid_get_sig_lens(priv->alg, &sig_lens[0],
                                       &sig_lens[1]) != 0) {
            return -1;
        }
        if (sig_len != sig_lens[0] + sig_lens[1]) {
            return -1;
        }
        if (write_component("sig0", sig, sig_lens[0]) != 0) {
            return -1;
        }
        if (write_component("sig1", sig + sig_lens[0], sig_lens[1]) != 0) {
            return -1;
        }
    } else {
        if (write_component("sig0", sig, sig_len) != 0) {
            return -1;
        }
    }

    if (include_keys) {
        int ret = 0;
        crypto_key privs[2] = {{0}};
        crypto_key pubs[2] = {{0}};
        crypto_key priv_ser = {0}, pub_ser = {0};

        if (write_component("aes_iv", iv, CRYPTO_AES_IV_SIZE) != 0) {
            goto error;
        }
        if (write_component("aes", aes_key, aes_key_len) != 0) {
            goto error;
        }

        if (hybrid) {
            if (crypto_hybrid_export_keypairs(priv->alg, priv, pub, privs,
                                              pubs) != 0) {
                goto error;
            }

            if (write_component("sk0", privs[0].key, privs[0].key_len) != 0) {
                goto error;
            }
            if (write_component("sk1", privs[1].key, privs[1].key_len) != 0) {
                goto error;
            }
            if (write_component("pk0", pubs[0].key, pubs[0].key_len) != 0) {
                goto error;
            }
            if (write_component("pk1", pubs[1].key, pubs[1].key_len) != 0) {
                goto error;
            }
        } else {
            if (crypto_export_keypair(priv->alg, priv, pub, &priv_ser,
                                      &pub_ser) != 0) {
                goto error;
            }
            if (write_component("sk0", priv_ser.key, priv_ser.key_len) != 0) {
                goto error;
            }
            if (write_component("pk0", pub_ser.key, pub_ser.key_len) != 0) {
                goto error;
            }
        }
        goto cleanup;

    error:
        ret = -1;

    cleanup:
        free(privs[0].key);
        free(privs[1].key);
        free(pubs[0].key);
        free(pubs[1].key);
        free(priv_ser.key);
        free(pub_ser.key);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}
