#include "util.h"
#include "api.h"
#include "hybrid_crypto.h"
#include <mbedtls/lms.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_OUTPUT_COMPONENTS 16

typedef struct {
    char component[32];
    char bin_path[PATH_MAX];
    char hex_path[PATH_MAX];
} output_component;

static int record_entry(output_component *entry, const char *name,
                        const char *bin_path, const char *hex_path)
{
    int n;

    n = snprintf(entry->component, sizeof(entry->component), "%s", name);
    if (n < 0 || (size_t)n >= sizeof(entry->component)) {
        return -1;
    }

    n = snprintf(entry->bin_path, sizeof(entry->bin_path), "%s", bin_path);
    if (n < 0 || (size_t)n >= sizeof(entry->bin_path)) {
        return -1;
    }

    n = snprintf(entry->hex_path, sizeof(entry->hex_path), "%s", hex_path);
    if (n < 0 || (size_t)n >= sizeof(entry->hex_path)) {
        return -1;
    }

    return 0;
}

static int append_component(output_component *entries, size_t *count,
                            const char *name, const char *bin_path,
                            const char *hex_path)
{
    if (*count >= MAX_OUTPUT_COMPONENTS) {
        return -1;
    }

    if (record_entry(&entries[*count], name, bin_path, hex_path) != 0) {
        return -1;
    }

    (*count)++;
    return 0;
}

static int ensure_not_exists(const char *path)
{
    if (access(path, F_OK) == 0) {
        errno = EEXIST;
        return -1;
    }

    if (errno != ENOENT) {
        return -1;
    }

    errno = 0;
    return 0;
}

static int ensure_component_paths_free(const char *name)
{
    char bin_path[PATH_MAX];
    char hex_path[PATH_MAX];
    int  n;

    n = snprintf(bin_path, sizeof(bin_path), "%s.bin", name);
    if (n < 0 || (size_t)n >= sizeof(bin_path)) {
        return -1;
    }

    n = snprintf(hex_path, sizeof(hex_path), "%s.hex", name);
    if (n < 0 || (size_t)n >= sizeof(hex_path)) {
        return -1;
    }

    if (ensure_not_exists(bin_path) != 0) {
        return -1;
    }

    if (ensure_not_exists(hex_path) != 0) {
        return -1;
    }

    return 0;
}

int ensure_outputs_not_exist(const char *out_path, int include_keys, int alg)
{
    char hex_path[PATH_MAX];
    int n;

    if (out_path == NULL) {
        errno = EINVAL;
        return -1;
    }

    n = snprintf(hex_path, sizeof(hex_path), "%s.hex", out_path);
    if (n < 0 || (size_t)n >= sizeof(hex_path)) {
        return -1;
    }

    if (ensure_not_exists(out_path) != 0) {
        return -1;
    }

    if (ensure_not_exists(hex_path) != 0) {
        return -1;
    }

    int hybrid = crypto_is_hybrid_alg(alg);
    if (ensure_component_paths_free("sig0") != 0) {
        return -1;
    }

    if (hybrid && ensure_component_paths_free("sig1") != 0) {
        return -1;
    }

    if (!include_keys) {
        return 0;
    }

    if (ensure_component_paths_free("aes_iv") != 0 ||
        ensure_component_paths_free("aes") != 0 ||
        ensure_component_paths_free("sk0") != 0 ||
        ensure_component_paths_free("pk0") != 0) {
        return -1;
    }

    if (hybrid &&
        (ensure_component_paths_free("sk1") != 0 ||
         ensure_component_paths_free("pk1") != 0)) {
        return -1;
    }

    return 0;
}

static void print_summary(const output_component *entries, size_t count)
{
    if (count == 0) {
        fprintf(stderr, "Output summary:\n  (no components written)\n");
        return;
    }

    size_t comp_width = strlen("Component");
    size_t bin_width  = strlen("Binary file");
    size_t hex_width  = strlen("Hex file");

    for (size_t i = 0; i < count; i++) {
        size_t len = strlen(entries[i].component);
        if (len > comp_width) {
            comp_width = len;
        }
        len = strlen(entries[i].bin_path);
        if (len > bin_width) {
            bin_width = len;
        }
        len = strlen(entries[i].hex_path);
        if (len > hex_width) {
            hex_width = len;
        }
    }

    int comp_w = (comp_width > (size_t)INT_MAX) ? INT_MAX : (int)comp_width;
    int bin_w  = (bin_width > (size_t)INT_MAX) ? INT_MAX : (int)bin_width;
    int hex_w  = (hex_width > (size_t)INT_MAX) ? INT_MAX : (int)hex_width;

    fprintf(stderr, "Output summary:\n");
    fprintf(stderr, "  %-*s  %-*s  %-*s\n", comp_w, "Component", bin_w,
            "Binary file", hex_w, "Hex file");

    fprintf(stderr, "  ");
    for (int i = 0; i < comp_w; i++) {
        fputc('-', stderr);
    }
    fprintf(stderr, "  ");
    for (int i = 0; i < bin_w; i++) {
        fputc('-', stderr);
    }
    fprintf(stderr, "  ");
    for (int i = 0; i < hex_w; i++) {
        fputc('-', stderr);
    }
    fputc('\n', stderr);

    for (size_t i = 0; i < count; i++) {
        fprintf(stderr, "  %-*s  %-*s  %-*s\n", comp_w,
                entries[i].component, bin_w, entries[i].bin_path, hex_w,
                entries[i].hex_path);
    }
}

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

static int write_component(const char *name, const uint8_t *data, size_t len,
                           output_component *entries, size_t *count)
{
    char bin_path[PATH_MAX];
    char hex_path[PATH_MAX];
    int n;

    n = snprintf(bin_path, sizeof(bin_path), "%s.bin", name);
    if (n < 0 || (size_t)n >= sizeof(bin_path)) {
        return -1;
    }
    n = snprintf(hex_path, sizeof(hex_path), "%s.hex", name);
    if (n < 0 || (size_t)n >= sizeof(hex_path)) {
        return -1;
    }

    if (write_bin_hex_pair(bin_path, hex_path, data, len) != 0) {
        return -1;
    }

    return append_component(entries, count, name, bin_path, hex_path);
}

int write_outputs(const char *out_path, int include_keys, int alg,
                  const crypto_key privs[2], const crypto_key pubs[2],
                  const uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE],
                  size_t aes_key_len, const uint8_t iv[CRYPTO_AES_IV_SIZE],
                  const uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE],
                  const size_t sig_lens[2], const uint8_t *enc,
                  size_t enc_len)
{
    char hex_path[PATH_MAX];
    int n;
    output_component outputs[MAX_OUTPUT_COMPONENTS];
    size_t output_count = 0;
    crypto_key priv_blobs[2] = {{0}};
    crypto_key pub_blobs[2] = {{0}};
    int result = -1;

    n = snprintf(hex_path, sizeof(hex_path), "%s.hex", out_path);
    if (n < 0 || (size_t)n >= sizeof(hex_path)) {
        goto cleanup;
    }

    if (write_bin_hex_pair(out_path, hex_path, enc, enc_len) != 0) {
        goto cleanup;
    }

    if (append_component(outputs, &output_count, "ciphertext", out_path,
                         hex_path) != 0) {
        goto cleanup;
    }

    int hybrid = crypto_is_hybrid_alg(alg);
    if (write_component("sig0", sigs[0], sig_lens[0], outputs,
                        &output_count) != 0) {
        goto cleanup;
    }
    if (hybrid) {
        if (write_component("sig1", sigs[1], sig_lens[1], outputs,
                            &output_count) != 0) {
            goto cleanup;
        }
    }

    if (include_keys) {
        if (write_component("aes_iv", iv, CRYPTO_AES_IV_SIZE, outputs,
                            &output_count) != 0) {
            goto cleanup;
        }
        if (write_component("aes", aes_key, aes_key_len, outputs,
                            &output_count) != 0) {
            goto cleanup;
        }

        if (hybrid) {
            if (hybrid_crypto_export_keypairs((hybrid_alg)alg, privs, pubs,
                                              priv_blobs, pub_blobs) != 0) {
                goto cleanup;
            }
            if (write_component("sk0", priv_blobs[0].key,
                                priv_blobs[0].key_len, outputs,
                                &output_count) != 0) {
                goto cleanup;
            }
            if (write_component("sk1", priv_blobs[1].key,
                                priv_blobs[1].key_len, outputs,
                                &output_count) != 0) {
                goto cleanup;
            }
            if (write_component("pk0", pub_blobs[0].key,
                                pub_blobs[0].key_len, outputs,
                                &output_count) != 0) {
                goto cleanup;
            }
            if (write_component("pk1", pub_blobs[1].key,
                                pub_blobs[1].key_len, outputs,
                                &output_count) != 0) {
                goto cleanup;
            }
        } else {
            if (crypto_export_keypair((crypto_alg)alg, &privs[0], &pubs[0],
                                      &priv_blobs[0], &pub_blobs[0]) != 0) {
                goto cleanup;
            }
            if (write_component("sk0", priv_blobs[0].key,
                                priv_blobs[0].key_len, outputs,
                                &output_count) != 0) {
                goto cleanup;
            }
            if (write_component("pk0", pub_blobs[0].key,
                                pub_blobs[0].key_len, outputs,
                                &output_count) != 0) {
                goto cleanup;
            }
        }
    }

    result = 0;

cleanup:
    free(priv_blobs[0].key);
    free(priv_blobs[1].key);
    free(pub_blobs[0].key);
    free(pub_blobs[1].key);
    if (result == 0) {
        print_summary(outputs, output_count);
    }
    return result;
}
