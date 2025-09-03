#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/lms.h>
#include "api.h"

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

static int write_component(const char *name,
                           const uint8_t *data, size_t len)
{
    size_t name_len = strlen(name);
    char *bin_path = malloc(name_len + 4 + 1);
    char *hex_path = malloc(name_len + 4 + 1);
    if (!bin_path || !hex_path) {
        free(bin_path);
        free(hex_path);
        return -1;
    }
    sprintf(bin_path, "%s.bin", name);
    sprintf(hex_path, "%s.hex", name);
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
        int ret = 0;
        if (write_component("aes_iv", iv, CRYPTO_AES_IV_SIZE) != 0)
            ret = -1;
        else if (write_component("aes", aes_key, aes_key_len) != 0)
            ret = -1;
        else if (priv->alg == CRYPTO_ALG_RSA4096_LMS ||
                 priv->alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
                 priv->alg == CRYPTO_ALG_LMS_MLDSA87) {
            crypto_key privs[2] = {{0}};
            crypto_key pubs[2] = {{0}};
            size_t len1 = 0, len2 = 0;
            if (crypto_export_keypair_components(priv->alg, priv, pub,
                                                 privs, pubs) != 0)
                ret = -1;
            else if (priv->alg == CRYPTO_ALG_RSA4096_LMS) {
                len1 = CRYPTO_RSA_SIG_SIZE;
                len2 = MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10,
                                           MBEDTLS_LMOTS_SHA256_N32_W8);
            } else if (priv->alg == CRYPTO_ALG_RSA4096_MLDSA87) {
                len1 = CRYPTO_RSA_SIG_SIZE;
                len2 = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
            } else {
                len1 = MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10,
                                           MBEDTLS_LMOTS_SHA256_N32_W8);
                len2 = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
            }
            if (ret == 0 && sig_len == len1 + len2) {
                if (write_component("sk0", privs[0].key, privs[0].key_len) != 0)
                    ret = -1;
                else if (write_component("sk1", privs[1].key, privs[1].key_len) != 0)
                    ret = -1;
                else if (write_component("pk0", pubs[0].key, pubs[0].key_len) != 0)
                    ret = -1;
                else if (write_component("pk1", pubs[1].key, pubs[1].key_len) != 0)
                    ret = -1;
                else if (write_component("sig0", sig, len1) != 0)
                    ret = -1;
                else if (write_component("sig1", sig + len1, len2) != 0)
                    ret = -1;
            } else {
                ret = -1;
            }
            free(privs[0].key);
            free(privs[1].key);
            free(pubs[0].key);
            free(pubs[1].key);
        } else {
            crypto_key priv_ser = {0}, pub_ser = {0};
            if (crypto_export_keypair(priv->alg, priv, pub,
                                      &priv_ser, &pub_ser) != 0)
                ret = -1;
            else if (write_component("sk", priv_ser.key, priv_ser.key_len) != 0)
                ret = -1;
            else if (write_component("pk", pub_ser.key, pub_ser.key_len) != 0)
                ret = -1;
            else if (write_component("sig", sig, sig_len) != 0)
                ret = -1;
            free(priv_ser.key);
            free(pub_ser.key);
        }
        if (ret != 0)
            return -1;
    }
    return 0;
}
