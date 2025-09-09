#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#include "util.h"
#include "lms.h"
#include "rsa.h"
#include "mldsa.h"

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/lms.h>

/**
 * struct hybrid_pair - key material for algorithms composed of two schemes
 * @first_priv: first private key
 * @first_pub: first public key
 * @second_priv: second private key
 * @second_pub: second public key
 */
typedef struct {
    crypto_key first_priv;
    crypto_key first_pub;
    crypto_key second_priv;
    crypto_key second_pub;
} hybrid_pair;

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


int crypto_init_aes(size_t bits, const char *key_path, const char *iv_path,
                    uint8_t *key_out, uint8_t iv_out[CRYPTO_AES_IV_SIZE])
{
    if (!key_out || !iv_out ||
        (bits != CRYPTO_AES_KEY_BITS_128 &&
         bits != CRYPTO_AES_KEY_BITS_192 &&
         bits != CRYPTO_AES_KEY_BITS_256)) {
        return -1;
    }

    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;

    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);

    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, NULL, 0) != 0) {
        return -1;
    }

    uint8_t *tmp = NULL;
    size_t   len = 0;

    if (key_path && read_file(key_path, &tmp, &len) == 0 && len == bits / 8) {
        memcpy(key_out, tmp, len);
        free(tmp);
    } else {
        if (tmp) {
            free(tmp);
        }
        mbedtls_ctr_drbg_random(&drbg, key_out, bits / 8);
    }

    tmp = NULL;
    len = 0;
    if (iv_path && read_file(iv_path, &tmp, &len) == 0 && len == CRYPTO_AES_IV_SIZE) {
        memcpy(iv_out, tmp, CRYPTO_AES_IV_SIZE);
        free(tmp);
    } else {
        if (tmp) {
            free(tmp);
        }
        mbedtls_ctr_drbg_random(&drbg, iv_out, CRYPTO_AES_IV_SIZE);
    }

    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    return 0;
}


int crypto_keygen(crypto_alg alg, crypto_key *out_priv, crypto_key *out_pub)
{
    if (!out_priv || !out_pub) {
        return -1;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        return -1;
    }

    int ret = -1;
    if (alg == CRYPTO_ALG_RSA4096) {
        ret = rsa_keygen(&drbg, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_LMS) {
        ret = lms_keygen(&drbg, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        ret = mldsa_keygen(out_priv, out_pub);
    } else if (crypto_is_hybrid_alg(alg)) {
        hybrid_pair *pair = calloc(1, sizeof(*pair));
        if (!pair) {
            ret = -1;
            goto cleanup;
        }
        crypto_alg first;
        crypto_alg second;
        if (crypto_hybrid_get_algs(alg, &first, &second) != 0) {
            free(pair);
            ret = -1;
            goto cleanup;
        }
        if (crypto_keygen(first, &pair->first_priv, &pair->first_pub) != 0 ||
            crypto_keygen(second, &pair->second_priv, &pair->second_pub) != 0) {
            int first_shared  = pair->first_pub.key == pair->first_priv.key;
            int second_shared = pair->second_pub.key == pair->second_priv.key;
            crypto_free_key(&pair->first_priv);
            if (first_shared) {
                pair->first_pub.key = NULL;
                pair->first_pub.key_len = 0;
            } else {
                crypto_free_key(&pair->first_pub);
            }
            crypto_free_key(&pair->second_priv);
            if (second_shared) {
                pair->second_pub.key = NULL;
                pair->second_pub.key_len = 0;
            } else {
                crypto_free_key(&pair->second_pub);
            }
            free(pair);
            ret = -1;
            goto cleanup;
        }
        out_priv->alg     = alg;
        out_pub->alg      = alg;
        out_priv->key     = pair;
        out_pub->key      = pair;
        out_priv->key_len = sizeof(*pair);
        out_pub->key_len  = sizeof(*pair);
        ret = 0;
    }

cleanup:
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

static int load_simple_keypair(crypto_alg alg, const char *priv_path, const char *pub_path,
                               crypto_key *out_priv, crypto_key *out_pub)
{
    int ret = -1;
    if (alg == CRYPTO_ALG_RSA4096) {
        ret = rsa_load_keypair(priv_path, pub_path, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_LMS) {
        ret = lms_load_keypair(priv_path, pub_path, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        ret = mldsa_load_keypair(priv_path, pub_path, out_priv, out_pub);
    }
    if (ret != 0) {
        return crypto_keygen(alg, out_priv, out_pub);
    }
    return ret;
}

static int load_hybrid_keypair(crypto_alg alg, const char *priv_path, const char *pub_path,
                               crypto_key *out_priv, crypto_key *out_pub)
{
    char priv0[PATH_MAX];
    char priv1[PATH_MAX];
    char pub0[PATH_MAX];
    char pub1[PATH_MAX];
    hybrid_pair *pair = NULL;
    crypto_alg first, second;

    if (split_paths(priv_path, priv0, priv1) != 0 ||
        split_paths(pub_path, pub0, pub1) != 0) {
        return -1;
    }

    pair = calloc(1, sizeof(*pair));
    if (!pair) {
        return -1;
    }

    if (crypto_hybrid_get_algs(alg, &first, &second) != 0 ||
        crypto_load_keypair(first, priv0, pub0, &pair->first_priv, &pair->first_pub) != 0 ||
        crypto_load_keypair(second, priv1, pub1, &pair->second_priv, &pair->second_pub) != 0) {
        int first_shared  = pair->first_pub.key == pair->first_priv.key;
        int second_shared = pair->second_pub.key == pair->second_priv.key;
        crypto_free_key(&pair->first_priv);
        if (first_shared) {
            pair->first_pub.key = NULL;
            pair->first_pub.key_len = 0;
        } else {
            crypto_free_key(&pair->first_pub);
        }
        crypto_free_key(&pair->second_priv);
        if (second_shared) {
            pair->second_pub.key = NULL;
            pair->second_pub.key_len = 0;
        } else {
            crypto_free_key(&pair->second_pub);
        }
        free(pair);
        return -1;
    }

    out_priv->alg = alg;
    out_pub->alg  = alg;
    out_priv->key = pair;
    out_pub->key  = pair;
    out_priv->key_len = sizeof(*pair);
    out_pub->key_len  = sizeof(*pair);
    return 0;
}

int crypto_load_keypair(crypto_alg alg, const char *priv_path, const char *pub_path,
                        crypto_key *out_priv, crypto_key *out_pub)
{
    if (!out_priv || !out_pub) {
        return -1;
    }
    if (!priv_path || !pub_path) {
        return crypto_keygen(alg, out_priv, out_pub);
    }

    if (crypto_is_hybrid_alg(alg)) {
        return load_hybrid_keypair(alg, priv_path, pub_path, out_priv, out_pub);
    }
    return load_simple_keypair(alg, priv_path, pub_path, out_priv, out_pub);
}

int crypto_sign(crypto_alg alg, const crypto_key *priv, const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len)
{
    if (!priv || !msg || !sig || !sig_len) {
        return -1;
    }
    if (alg != priv->alg) {
        return -1;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        return -1;
    }

    int ret = -1;
    if (alg == CRYPTO_ALG_RSA4096) {
        ret = rsa_sign(&drbg, priv, msg, msg_len, sig, sig_len);
    } else if (alg == CRYPTO_ALG_LMS) {
        ret = lms_sign(&drbg, priv, msg, msg_len, sig, sig_len);
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        ret = mldsa_sign(priv, msg, msg_len, sig, sig_len);
    } else if (crypto_is_hybrid_alg(alg)) {
        hybrid_pair *pair = priv->key;
        size_t len1 = 0;
        size_t len2 = 0;
        crypto_alg first;
        crypto_alg second;

        if (crypto_hybrid_get_algs(alg, &first, &second) != 0 ||
            crypto_hybrid_get_sig_lens(alg, &len1, &len2) != 0) {
            ret = -1;
        } else {
            size_t tmp = len1;
            if (crypto_sign(first, &pair->first_priv, msg, msg_len, sig, &tmp) != 0 ||
                tmp != len1) {
                ret = -1;
            } else {
                tmp = len2;
                if (crypto_sign(second, &pair->second_priv, msg, msg_len, sig + len1, &tmp) != 0 ||
                    tmp != len2) {
                    ret = -1;
                } else {
                    *sig_len = len1 + len2;
                    ret = 0;
                }
            }
        }
    }

    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int crypto_verify(crypto_alg alg, const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len)
{
    if (!pub || !msg || !sig) {
        return -1;
    }
    if (alg != pub->alg) {
        return -1;
    }
    if (alg == CRYPTO_ALG_RSA4096) {
        return rsa_verify(pub, msg, msg_len, sig, sig_len);
    } else if (alg == CRYPTO_ALG_LMS) {
        return lms_verify(pub, msg, msg_len, sig, sig_len);
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        return mldsa_verify(pub, msg, msg_len, sig, sig_len);
    } else if (crypto_is_hybrid_alg(alg)) {
        hybrid_pair *pair = pub->key;
        size_t len1 = 0;
        size_t len2 = 0;
        crypto_alg first;
        crypto_alg second;

        if (crypto_hybrid_get_algs(alg, &first, &second) != 0 ||
            crypto_hybrid_get_sig_lens(alg, &len1, &len2) != 0) {
            return -1;
        }
        if (sig_len != len1 + len2) {
            return -1;
        }
        if (crypto_verify(first, &pair->first_pub, msg, msg_len, sig, len1) != 0) {
            return -1;
        }
        if (crypto_verify(second, &pair->second_pub, msg, msg_len, sig + len1, len2) != 0) {
            return -1;
        }
        return 0;
    }
    return -1;
}

static int aes_setkey(mbedtls_aes_context *aes, const uint8_t *key, size_t bits, int enc)
{
    if (bits != CRYPTO_AES_KEY_BITS_128 &&
        bits != CRYPTO_AES_KEY_BITS_192 &&
        bits != CRYPTO_AES_KEY_BITS_256) {
        return -1;
    }
    if (enc) {
        return mbedtls_aes_setkey_enc(aes, key, (unsigned int)bits);
    } else {
        return mbedtls_aes_setkey_dec(aes, key, (unsigned int)bits);
    }
}

int crypto_encrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[CRYPTO_AES_IV_SIZE],
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len)
{
    if (!key || !iv || !in || !out || !out_len) {
        return -1;
    }

    size_t pad = CRYPTO_AES_IV_SIZE - (len % CRYPTO_AES_IV_SIZE);
    if (pad == 0) {
        pad = CRYPTO_AES_IV_SIZE;
    }

    size_t        padded_len = len + pad;
    unsigned char *buf       = malloc(padded_len);
    if (!buf) {
        return -1;
    }

    memcpy(buf, in, len);
    memset(buf + len, (unsigned char)pad, pad);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (aes_setkey(&aes, key, bits, 1) != 0) {
        free(buf);
        mbedtls_aes_free(&aes);
        return -1;
    }

    unsigned char iv_copy[CRYPTO_AES_IV_SIZE];
    memcpy(iv_copy, iv, CRYPTO_AES_IV_SIZE);
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy, buf, out) != 0) {
        free(buf);
        mbedtls_aes_free(&aes);
        return -1;
    }

    mbedtls_aes_free(&aes);
    free(buf);
    *out_len = padded_len;
    return 0;
}

int crypto_decrypt_aescbc(const uint8_t *key, size_t bits,
                          const uint8_t iv[CRYPTO_AES_IV_SIZE],
                          const uint8_t *in, size_t len, uint8_t *out,
                          size_t *out_len)
{
    if (!key || !iv || !in || !out || !out_len ||
        len == 0 || (len % CRYPTO_AES_IV_SIZE) != 0) {
        return -1;
    }
    unsigned char *buf = malloc(len);
    if (!buf) {
        return -1;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (aes_setkey(&aes, key, bits, 0) != 0) {
        free(buf);
        mbedtls_aes_free(&aes);
        return -1;
    }

    unsigned char iv_copy[CRYPTO_AES_IV_SIZE];
    memcpy(iv_copy, iv, CRYPTO_AES_IV_SIZE);
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv_copy, in, buf) != 0) {
        free(buf);
        mbedtls_aes_free(&aes);
        return -1;
    }

    mbedtls_aes_free(&aes);
    unsigned char pad = buf[len - 1];
    if (pad == 0 || pad > CRYPTO_AES_IV_SIZE || pad > len) {
        free(buf);
        return -1;
    }

    for (size_t i = 0; i < pad; ++i) {
        if (buf[len - 1 - i] != pad) {
            free(buf);
            return -1;
        }
    }

    size_t plen = len - pad;
    memcpy(out, buf, plen);
    free(buf);
    *out_len = plen;
    return 0;
}

int crypto_sha384(const uint8_t *in, size_t len,
                  uint8_t out[CRYPTO_SHA384_DIGEST_SIZE])
{
    if (!in || !out) {
        return -1;
    }
    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                      in, len, out);
}

static int export_simple(crypto_alg alg, const crypto_key *priv,
                         const crypto_key *pub, crypto_key *out_priv,
                         crypto_key *out_pub)
{
    if (!priv || !pub || !out_priv || !out_pub) {
        return -1;
    }
    if (alg == CRYPTO_ALG_RSA4096) {
        return rsa_export_keypair(priv, pub, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_LMS) {
        return lms_export_keypair(priv, pub, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        return mldsa_export_keypair(priv, pub, out_priv, out_pub);
    }
    return -1;
}

int crypto_is_hybrid_alg(crypto_alg alg)
{
    switch (alg) {
    case CRYPTO_ALG_RSA4096_LMS:
    case CRYPTO_ALG_RSA4096_MLDSA87:
    case CRYPTO_ALG_LMS_MLDSA87:
        return 1;
    default:
        return 0;
    }
}

int crypto_hybrid_get_algs(crypto_alg alg, crypto_alg *first,
                           crypto_alg *second)
{
    if (first == NULL || second == NULL) {
        return -1;
    }
    if (alg == CRYPTO_ALG_RSA4096_LMS) {
        *first  = CRYPTO_ALG_RSA4096;
        *second = CRYPTO_ALG_LMS;
        return 0;
    } else if (alg == CRYPTO_ALG_RSA4096_MLDSA87) {
        *first  = CRYPTO_ALG_RSA4096;
        *second = CRYPTO_ALG_MLDSA87;
        return 0;
    } else if (alg == CRYPTO_ALG_LMS_MLDSA87) {
        *first  = CRYPTO_ALG_LMS;
        *second = CRYPTO_ALG_MLDSA87;
        return 0;
    }
    return -1;
}

int crypto_hybrid_export_keypairs(crypto_alg alg, const crypto_key *priv,
                                  const crypto_key *pub,
                                  crypto_key out_priv[2],
                                  crypto_key out_pub[2])
{
    if (!priv || !pub || !out_priv || !out_pub) {
        return -1;
    }

    memset(out_priv, 0, sizeof(crypto_key) * 2);
    memset(out_pub, 0, sizeof(crypto_key) * 2);

    const hybrid_pair *pair = priv->key;
    crypto_alg first;
    crypto_alg second;

    if (crypto_hybrid_get_algs(alg, &first, &second) != 0 ||
        export_simple(first, &pair->first_priv, &pair->first_pub,
                      &out_priv[0], &out_pub[0]) != 0 ||
        export_simple(second, &pair->second_priv, &pair->second_pub,
                      &out_priv[1], &out_pub[1]) != 0) {
        free(out_priv[0].key);
        free(out_pub[0].key);
        free(out_priv[1].key);
        free(out_pub[1].key);
        memset(out_priv, 0, sizeof(crypto_key) * 2);
        memset(out_pub, 0, sizeof(crypto_key) * 2);
        return -1;
    }
    return 0;
}

int crypto_hybrid_get_sig_lens(crypto_alg alg, size_t *len1, size_t *len2)
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

int crypto_export_keypair(crypto_alg alg, const crypto_key *priv,
                          const crypto_key *pub, crypto_key *out_priv,
                          crypto_key *out_pub)
{
    if (!priv || !pub || !out_priv || !out_pub) {
        return -1;
    }
    if (crypto_is_hybrid_alg(alg)) {
        const hybrid_pair *pair = priv->key;
        crypto_key first_priv = {0}, first_pub = {0};
        crypto_key second_priv = {0}, second_pub = {0};
        crypto_alg first;
        crypto_alg second;

        if (crypto_hybrid_get_algs(alg, &first, &second) != 0) {
            return -1;
        }

        int ret = -1;
        if (export_simple(first, &pair->first_priv, &pair->first_pub,
                          &first_priv, &first_pub) != 0 ||
            export_simple(second, &pair->second_priv, &pair->second_pub,
                          &second_priv, &second_pub) != 0) {
            goto cleanup;
        }

        out_priv->key_len = first_priv.key_len + second_priv.key_len;
        out_pub->key_len  = first_pub.key_len + second_pub.key_len;
        out_priv->key = malloc(out_priv->key_len);
        out_pub->key  = malloc(out_pub->key_len);
        if (!out_priv->key || !out_pub->key) {
            goto cleanup;
        }

        memcpy(out_priv->key, first_priv.key, first_priv.key_len);
        memcpy((unsigned char *)out_priv->key + first_priv.key_len,
               second_priv.key, second_priv.key_len);
        memcpy(out_pub->key, first_pub.key, first_pub.key_len);
        memcpy((unsigned char *)out_pub->key + first_pub.key_len,
               second_pub.key, second_pub.key_len);
        out_priv->alg = alg;
        out_pub->alg  = alg;
        ret = 0;
    cleanup:
        if (ret != 0) {
            free(out_priv->key);
            free(out_pub->key);
            out_priv->key = NULL;
            out_pub->key = NULL;
        }
        free(first_priv.key);
        free(first_pub.key);
        free(second_priv.key);
        free(second_pub.key);
        return ret;
    }
    return export_simple(alg, priv, pub, out_priv, out_pub);
}

void crypto_free_key(crypto_key *key)
{
    if (!key || !key->key) {
        return;
    }
    if (key->alg == CRYPTO_ALG_RSA4096) {
        rsa_free_key(key);
    } else if (key->alg == CRYPTO_ALG_LMS) {
        lms_free_key(key);
    } else if (key->alg == CRYPTO_ALG_MLDSA87) {
        mldsa_free_key(key);
    } else if (crypto_is_hybrid_alg(key->alg)) {
        hybrid_pair *pair = key->key;
        int first_shared  = pair->first_pub.key == pair->first_priv.key;
        int second_shared = pair->second_pub.key == pair->second_priv.key;
        crypto_free_key(&pair->first_priv);
        if (first_shared) {
            pair->first_pub.key = NULL;
            pair->first_pub.key_len = 0;
        } else {
            crypto_free_key(&pair->first_pub);
        }
        crypto_free_key(&pair->second_priv);
        if (second_shared) {
            pair->second_pub.key = NULL;
            pair->second_pub.key_len = 0;
        } else {
            crypto_free_key(&pair->second_pub);
        }
        free(pair);
        key->key     = NULL;
        key->key_len = 0;
        return;
    } else {
        key->key = NULL;
        key->key_len = 0;
        return;
    }
    key->key     = NULL;
    key->key_len = 0;
}
