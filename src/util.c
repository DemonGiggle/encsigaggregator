#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *tmp = malloc(sz ? sz : 1);
    if (!tmp) {
        fclose(f);
        return -1;
    }
    if (fread(tmp, 1, sz, f) != (size_t)sz) {
        fclose(f);
        free(tmp);
        return -1;
    }
    fclose(f);
    *buf = tmp;
    *len = sz;
    return 0;
}

/* write binary and hex representations to files */
static int write_bin_hex_pair(const char *bin_path, const char *hex_path,
                              const uint8_t *data, size_t len)
{
    FILE *f = fopen(bin_path, "wb");
    if (!f)
        return -1;
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);

    f = fopen(hex_path, "w");
    if (!f)
        return -1;
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "0x%02x", data[i]);
        if (i + 1 < len)
            fputc(',', f);
        if ((i + 1) % 16 == 0)
            fputc('\n', f);
    }
    if (len % 16)
        fputc('\n', f);
    fclose(f);
    return 0;
}

static int write_component(const char *dir, const char *name,
                           const uint8_t *data, size_t len)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    /* dir already includes trailing '/' if needed */
    char *bin_path = malloc(dir_len + name_len + 4 + 1);
    char *hex_path = malloc(dir_len + name_len + 4 + 1);
    if (!bin_path || !hex_path) {
        free(bin_path);
        free(hex_path);
        return -1;
    }
    sprintf(bin_path, "%s%s.bin", dir, name);
    sprintf(hex_path, "%s%s.hex", dir, name);
    int ret = write_bin_hex_pair(bin_path, hex_path, data, len);
    if (ret == 0) {
        printf("%s binary: %s\n", name, bin_path);
        printf("%s hex: %s\n", name, hex_path);
    }
    free(bin_path);
    free(hex_path);
    return ret;
}

int write_outputs(const char *out_path, int include_keys,
                  const crypto_key *priv, const crypto_key *pub,
                  const uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE],
                  size_t aes_key_len,
                  const uint8_t iv[CRYPTO_AES_IV_SIZE],
                  const uint8_t *sig, size_t sig_len,
                  const uint8_t *enc, size_t enc_len)
{
    size_t out_len = strlen(out_path);
    char *hex_path = malloc(out_len + 4 + 1);
    if (!hex_path)
        return -1;
    sprintf(hex_path, "%s.hex", out_path);
    if (write_bin_hex_pair(out_path, hex_path, enc, enc_len) != 0) {
        free(hex_path);
        return -1;
    }
    printf("ciphertext binary: %s\n", out_path);
    printf("ciphertext hex: %s\n", hex_path);
    free(hex_path);

    if (include_keys) {
        const char *slash = strrchr(out_path, '/');
        char *dir = NULL;
        if (slash) {
            size_t dir_len = slash - out_path + 1; /* include '/' */
            dir = malloc(dir_len + 1);
            if (!dir)
                return -1;
            memcpy(dir, out_path, dir_len);
            dir[dir_len] = '\0';
        } else {
            dir = malloc(3);
            if (!dir)
                return -1;
            strcpy(dir, "./");
        }
        int ret = 0;
        if (write_component(dir, "aes_iv", iv, CRYPTO_AES_IV_SIZE) != 0)
            ret = -1;
        else if (write_component(dir, "aes", aes_key, aes_key_len) != 0)
            ret = -1;
        else if (write_component(dir, "sk", priv->key, priv->key_len) != 0)
            ret = -1;
        else if (write_component(dir, "pk", pub->key, pub->key_len) != 0)
            ret = -1;
        else if (write_component(dir, "sig", sig, sig_len) != 0)
            ret = -1;
        free(dir);
        if (ret != 0)
            return -1;
    }
    return 0;
}
