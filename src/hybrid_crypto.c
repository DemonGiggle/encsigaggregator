#include "hybrid_crypto.h"
#include "util.h"
#include "lms.h"
#include "rsa.h"
#include "mldsa.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#include <mbedtls/lms.h>

/* Split a comma-separated path list into two buffers */
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
    if (len0 >= PATH_MAX) {
        return -1;
    }
    memcpy(first, paths, len0);
    first[len0] = '\0';
    size_t len1 = strlen(comma + 1);
    if (len1 >= PATH_MAX) {
        return -1;
    }
    memcpy(second, comma + 1, len1 + 1);
    return 0;
}

/* Signature length for the LMS parameter set used */
#define LMS_SIG_LEN \
    MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10, MBEDTLS_LMOTS_SHA256_N32_W8)

int crypto_is_hybrid_alg(int alg)
{
    return alg >= CRYPTO_ALG_RSA4096_LMS && alg <= CRYPTO_ALG_LMS_MLDSA87;
}

int crypto_hybrid_get_algs(hybrid_alg alg, crypto_alg *first, crypto_alg *second)
{
    if (!first || !second) {
        return -1;
    }
    switch (alg) {
    case CRYPTO_ALG_RSA4096_LMS:
        *first = CRYPTO_ALG_RSA4096;
        *second = CRYPTO_ALG_LMS;
        return 0;
    case CRYPTO_ALG_RSA4096_MLDSA87:
        *first = CRYPTO_ALG_RSA4096;
        *second = CRYPTO_ALG_MLDSA87;
        return 0;
    case CRYPTO_ALG_LMS_MLDSA87:
        *first = CRYPTO_ALG_LMS;
        *second = CRYPTO_ALG_MLDSA87;
        return 0;
    }
    return -1;
}

int crypto_hybrid_get_sig_lens(hybrid_alg alg, size_t *len1, size_t *len2)
{
    if (len1 == NULL || len2 == NULL) {
        return -1;
    }
    if (alg == CRYPTO_ALG_RSA4096_LMS) {
        *len1 = CRYPTO_RSA_SIG_SIZE;
        *len2 = LMS_SIG_LEN;
        return 0;
    } else if (alg == CRYPTO_ALG_RSA4096_MLDSA87) {
        *len1 = CRYPTO_RSA_SIG_SIZE;
        *len2 = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        return 0;
    } else if (alg == CRYPTO_ALG_LMS_MLDSA87) {
        *len1 = LMS_SIG_LEN;
        *len2 = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        return 0;
    }
    return -1;
}

int hybrid_crypto_keygen(hybrid_alg alg, crypto_key privs[2], crypto_key pubs[2])
{
    if (!privs || !pubs) {
        return -1;
    }
    crypto_alg first, second;
    if (crypto_hybrid_get_algs(alg, &first, &second) != 0) {
        return -1;
    }
    if (crypto_keygen(first, &privs[0], &pubs[0]) != 0 ||
        crypto_keygen(second, &privs[1], &pubs[1]) != 0) {
        crypto_free_key(&privs[0]);
        crypto_free_key(&pubs[0]);
        crypto_free_key(&privs[1]);
        crypto_free_key(&pubs[1]);
        return -1;
    }
    return 0;
}

int hybrid_crypto_load_keypair(hybrid_alg alg, const char *priv_paths,
                               const char *pub_paths, crypto_key privs[2],
                               crypto_key pubs[2])
{
    if (!privs || !pubs) {
        return -1;
    }
    if (!priv_paths || !pub_paths) {
        return hybrid_crypto_keygen(alg, privs, pubs);
    }
    char priv0[PATH_MAX] = {0};
    char priv1[PATH_MAX] = {0};
    char pub0[PATH_MAX] = {0};
    char pub1[PATH_MAX] = {0};
    if (split_paths(priv_paths, priv0, priv1) != 0 ||
        split_paths(pub_paths, pub0, pub1) != 0) {
        return -1;
    }
    crypto_alg first, second;
    if (crypto_hybrid_get_algs(alg, &first, &second) != 0) {
        return -1;
    }
    if (crypto_load_keypair(first, priv0, pub0, &privs[0], &pubs[0]) != 0 ||
        crypto_load_keypair(second, priv1, pub1, &privs[1], &pubs[1]) != 0) {
        crypto_free_key(&privs[0]);
        crypto_free_key(&pubs[0]);
        crypto_free_key(&privs[1]);
        crypto_free_key(&pubs[1]);
        return -1;
    }
    return 0;
}

int hybrid_crypto_sign(hybrid_alg alg, const crypto_key privs[2],
                       const uint8_t *msg, size_t msg_len,
                       uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE],
                       size_t sig_lens[2])
{
    if (!privs || !msg || !sigs || !sig_lens) {
        return -1;
    }
    crypto_alg first, second;
    if (crypto_hybrid_get_algs(alg, &first, &second) != 0 ||
        crypto_hybrid_get_sig_lens(alg, &sig_lens[0], &sig_lens[1]) != 0) {
        return -1;
    }
    if (privs[0].alg != first || privs[1].alg != second) {
        return -1;
    }
    if (crypto_sign(first, &privs[0], msg, msg_len, sigs[0], &sig_lens[0]) != 0) {
        return -1;
    }
    if (crypto_sign(second, &privs[1], msg, msg_len, sigs[1], &sig_lens[1]) != 0) {
        return -1;
    }
    return 0;
}

int hybrid_crypto_verify(hybrid_alg alg, const crypto_key pubs[2],
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE],
                         const size_t sig_lens[2])
{
    if (!pubs || !msg || !sigs || !sig_lens) {
        return -1;
    }
    crypto_alg first, second;
    if (crypto_hybrid_get_algs(alg, &first, &second) != 0) {
        return -1;
    }
    if (pubs[0].alg != first || pubs[1].alg != second) {
        return -1;
    }
    if (crypto_verify(first, &pubs[0], msg, msg_len, sigs[0], sig_lens[0]) != 0) {
        return -1;
    }
    if (crypto_verify(second, &pubs[1], msg, msg_len, sigs[1], sig_lens[1]) != 0) {
        return -1;
    }
    return 0;
}

int hybrid_crypto_export_keypairs(hybrid_alg alg, const crypto_key privs[2],
                                  const crypto_key pubs[2], crypto_key out_privs[2],
                                  crypto_key out_pubs[2])
{
    if (!privs || !pubs || !out_privs || !out_pubs) {
        return -1;
    }
    crypto_alg first, second;
    if (crypto_hybrid_get_algs(alg, &first, &second) != 0) {
        return -1;
    }
    if (crypto_export_keypair(first, &privs[0], &pubs[0], &out_privs[0], &out_pubs[0]) != 0 ||
        crypto_export_keypair(second, &privs[1], &pubs[1], &out_privs[1], &out_pubs[1]) != 0) {
        free(out_privs[0].key);
        free(out_pubs[0].key);
        free(out_privs[1].key);
        free(out_pubs[1].key);
        return -1;
    }
    return 0;
}


