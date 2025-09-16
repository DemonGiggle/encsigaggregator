#include "verify_mode.h"

#include "crypto.h"
#include "hybrid_crypto.h"
#include "util.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int split_paths(const char *paths, char first[PATH_MAX], char second[PATH_MAX])
{
    if (!paths || !first || !second) {
        return -1;
    }
    const char *comma = strchr(paths, ',');
    if (!comma) {
        return -1;
    }
    size_t len0 = (size_t)(comma - paths);
    if (len0 == 0 || len0 >= PATH_MAX) {
        return -1;
    }
    memcpy(first, paths, len0);
    first[len0] = '\0';
    size_t len1 = strlen(comma + 1);
    if (len1 == 0 || len1 >= PATH_MAX) {
        return -1;
    }
    memcpy(second, comma + 1, len1 + 1);
    return 0;
}

int verify_sig_mode(const cli_options *opts)
{
    if (!opts || !opts->sig_path || !opts->infile) {
        fprintf(stderr, "Verification requires input and signature files\n");
        return 1;
    }
    if (!opts->pk_path || !opts->sk_path) {
        fprintf(stderr, "Public and private key files must be specified for verification\n");
        return 1;
    }

    int      ret     = 1;
    uint8_t *msg     = NULL;
    size_t   msg_len = 0;
    if (read_file(opts->infile, &msg, &msg_len) != 0) {
        perror("input");
        goto cleanup;
    }

    crypto_key privs[2]                      = {{0}};
    crypto_key pubs[2]                       = {{0}};
    uint8_t *sig_files[2]                    = {NULL, NULL};
    size_t   sig_file_lens[2]                = {0, 0};
    uint8_t  sig_bufs[2][CRYPTO_MAX_SIG_SIZE] = {{0}};
    size_t   sig_lens[2]                     = {0, 0};

    int is_hybrid = crypto_is_hybrid_alg(opts->alg);
    if (is_hybrid) {
        if (hybrid_crypto_load_keypair((hybrid_alg)opts->alg, opts->sk_path,
                                       opts->pk_path, privs, pubs) != 0) {
            fprintf(stderr, "Key init failed\n");
            goto cleanup;
        }
        char sig0_path[PATH_MAX] = {0};
        char sig1_path[PATH_MAX] = {0};
        if (split_paths(opts->sig_path, sig0_path, sig1_path) != 0) {
            fprintf(stderr,
                    "Hybrid signature verification requires two comma-separated paths\n");
            goto cleanup;
        }
        if (read_file(sig0_path, &sig_files[0], &sig_file_lens[0]) != 0) {
            fprintf(stderr, "Failed to read signature file %s\n", sig0_path);
            goto cleanup;
        }
        if (read_file(sig1_path, &sig_files[1], &sig_file_lens[1]) != 0) {
            fprintf(stderr, "Failed to read signature file %s\n", sig1_path);
            goto cleanup;
        }
        if (sig_file_lens[0] > CRYPTO_MAX_SIG_SIZE ||
            sig_file_lens[1] > CRYPTO_MAX_SIG_SIZE) {
            fprintf(stderr, "Signature too large\n");
            goto cleanup;
        }
        memcpy(sig_bufs[0], sig_files[0], sig_file_lens[0]);
        memcpy(sig_bufs[1], sig_files[1], sig_file_lens[1]);
        sig_lens[0] = sig_file_lens[0];
        sig_lens[1] = sig_file_lens[1];

        if (hybrid_crypto_verify((hybrid_alg)opts->alg, pubs, msg, msg_len,
                                 sig_bufs, sig_lens) != 0) {
            fprintf(stderr, "Signature verification failed\n");
            goto cleanup;
        }
    } else {
        if (crypto_load_keypair((crypto_alg)opts->alg, opts->sk_path, opts->pk_path,
                                &privs[0], &pubs[0]) != 0) {
            fprintf(stderr, "Key init failed\n");
            goto cleanup;
        }
        if (read_file(opts->sig_path, &sig_files[0], &sig_file_lens[0]) != 0) {
            fprintf(stderr, "Failed to read signature file %s\n", opts->sig_path);
            goto cleanup;
        }
        if (sig_file_lens[0] > CRYPTO_MAX_SIG_SIZE) {
            fprintf(stderr, "Signature too large\n");
            goto cleanup;
        }
        memcpy(sig_bufs[0], sig_files[0], sig_file_lens[0]);
        sig_lens[0] = sig_file_lens[0];
        if (crypto_verify((crypto_alg)opts->alg, &pubs[0], msg, msg_len,
                          sig_bufs[0], sig_lens[0]) != 0) {
            fprintf(stderr, "Signature verification failed\n");
            goto cleanup;
        }
    }

    printf("Signature verification succeeded\n");
    ret = 0;

cleanup:
    free(msg);
    free(sig_files[0]);
    free(sig_files[1]);
    crypto_free_key(&privs[0]);
    crypto_free_key(&privs[1]);
    crypto_free_key(&pubs[0]);
    crypto_free_key(&pubs[1]);
    return ret;
}
