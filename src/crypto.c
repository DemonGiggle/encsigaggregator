#include "crypto.h"
#include <stdlib.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/lms.h>

#include "api.h" /* PQClean ml-dsa-87 */

typedef struct {
    mbedtls_lms_private_t priv;
    mbedtls_lms_public_t pub;
} lms_pair;

static int rng_callback(void *ctx, unsigned char *out, size_t len) {
    return mbedtls_ctr_drbg_random((mbedtls_ctr_drbg_context *)ctx, out, len);
}

int crypto_keygen(crypto_alg alg, crypto_key *out_priv, crypto_key *out_pub) {
    if (!out_priv || !out_pub)
        return -1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
        return -1;

    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_rsa_context *rsa = calloc(1, sizeof(*rsa));
        if (!rsa) return -1;
        mbedtls_rsa_init(rsa);
        if (mbedtls_rsa_gen_key(rsa, rng_callback, &drbg, 4096, 65537) != 0) {
            mbedtls_rsa_free(rsa);
            free(rsa);
            return -1;
        }
        out_priv->alg = out_pub->alg = CRYPTO_ALG_RSA4096;
        out_priv->key = rsa;
        out_pub->key = rsa; /* RSA uses same context for priv/pub */
        out_priv->key_len = out_pub->key_len = sizeof(*rsa);
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
        lms_pair *pair = calloc(1, sizeof(*pair));
        if (!pair) return -1;
        mbedtls_lms_private_init(&pair->priv);
        mbedtls_lms_public_init(&pair->pub);
        unsigned char seed[32];
        if (mbedtls_ctr_drbg_random(&drbg, seed, sizeof(seed)) != 0 ||
            mbedtls_lms_generate_private_key(&pair->priv,
                                             MBEDTLS_LMS_SHA256_M32_H10,
                                             MBEDTLS_LMOTS_SHA256_N32_W8,
                                             rng_callback, &drbg,
                                             seed, sizeof(seed)) != 0 ||
            mbedtls_lms_calculate_public_key(&pair->pub, &pair->priv) != 0) {
            mbedtls_lms_private_free(&pair->priv);
            mbedtls_lms_public_free(&pair->pub);
            free(pair);
            return -1;
        }
        out_priv->alg = out_pub->alg = CRYPTO_ALG_LMS;
        out_priv->key = pair;
        out_pub->key = pair; /* same struct contains priv/pub */
        out_priv->key_len = out_pub->key_len = sizeof(*pair);
        return 0;
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        unsigned char *pk = NULL, *sk = NULL;
        pk = malloc(PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES);
        sk = malloc(PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES);
        if (!pk || !sk) {
            free(pk); free(sk); return -1;
        }
        if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
            free(pk); free(sk); return -1;
        }
        out_pub->alg = out_priv->alg = CRYPTO_ALG_MLDSA87;
        out_pub->key = pk;
        out_pub->key_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;
        out_priv->key = sk;
        out_priv->key_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;
        return 0;
    }
    return -1;
}

int crypto_sign(crypto_alg alg, const crypto_key *priv, const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len) {
    if (!priv || !msg || !sig || !sig_len)
        return -1;
    if (alg != priv->alg)
        return -1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
        return -1;
    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_rsa_context *rsa = priv->key;
        unsigned char hash[48];
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                       msg, msg_len, hash) != 0 ||
            mbedtls_rsa_pkcs1_sign(rsa, rng_callback, &drbg,
                                   MBEDTLS_MD_SHA384, 0, hash, sig) != 0) {
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            return -1;
        }
        *sig_len = mbedtls_rsa_get_len(rsa);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
        lms_pair *pair = priv->key;
        size_t olen = 0;
        if (mbedtls_lms_sign(&pair->priv, rng_callback, &drbg,
                              msg, msg_len, sig, *sig_len, &olen) != 0) {
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            return -1;
        }
        *sig_len = olen;
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        return 0;
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, sig_len,
                                                         msg, msg_len,
                                                         priv->key) != 0) {
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            return -1;
        }
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        return 0;
    }
    return -1;
}

int crypto_verify(crypto_alg alg, const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len) {
    if (!pub || !msg || !sig)
        return -1;
    if (alg != pub->alg)
        return -1;
    unsigned char hash[48];
    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_rsa_context *rsa = pub->key;
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                       msg, msg_len, hash) != 0 ||
            mbedtls_rsa_pkcs1_verify(rsa, MBEDTLS_MD_SHA384, 0,
                                     hash, sig) != 0)
            return -1;
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
        lms_pair *pair = pub->key;
        if (mbedtls_lms_verify(&pair->pub, msg, msg_len, sig, sig_len) != 0)
            return -1;
        return 0;
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len,
                                                     msg, msg_len,
                                                     pub->key) != 0)
            return -1;
        return 0;
    }
    return -1;
}

int crypto_encrypt_aes256cbc(const uint8_t key[32], const uint8_t iv[16],
                             const uint8_t *in, size_t len, uint8_t *out) {
    if (!key || !iv || !in || !out)
        return -1;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 256) != 0)
        return -1;
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv_copy, in, out) != 0)
        return -1;
    mbedtls_aes_free(&aes);
    return 0;
}

int crypto_decrypt_aes256cbc(const uint8_t key[32], const uint8_t iv[16],
                             const uint8_t *in, size_t len, uint8_t *out) {
    if (!key || !iv || !in || !out)
        return -1;
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_dec(&aes, key, 256) != 0)
        return -1;
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv_copy, in, out) != 0)
        return -1;
    mbedtls_aes_free(&aes);
    return 0;
}

void crypto_free_key(crypto_key *key) {
    if (!key || !key->key) return;
    if (key->alg == CRYPTO_ALG_RSA4096) {
        mbedtls_rsa_free((mbedtls_rsa_context *)key->key);
        free(key->key);
    } else if (key->alg == CRYPTO_ALG_LMS) {
        lms_pair *pair = key->key;
        mbedtls_lms_private_free(&pair->priv);
        mbedtls_lms_public_free(&pair->pub);
        free(pair);
    } else if (key->alg == CRYPTO_ALG_MLDSA87) {
        free(key->key);
    }
    key->key = NULL;
    key->key_len = 0;
}
