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
        mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);
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
        mbedtls_lms_context *lms = calloc(1, sizeof(*lms));
        if (!lms) return -1;
        mbedtls_lms_init(lms);
        if (mbedtls_lms_generate_keys(lms, rng_callback, &drbg) != 0) {
            mbedtls_lms_free(lms);
            free(lms);
            return -1;
        }
        out_priv->alg = out_pub->alg = CRYPTO_ALG_LMS;
        out_priv->key = lms;
        out_pub->key = lms; /* same context contains priv/pub */
        out_priv->key_len = out_pub->key_len = sizeof(*lms);
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
    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_rsa_context *rsa = priv->key;
        if (mbedtls_rsa_pkcs1_sign(rsa, rng_callback, NULL,
                                   MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA384,
                                   0, msg, sig) != 0)
            return -1;
        *sig_len = mbedtls_rsa_get_len(rsa);
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
        mbedtls_lms_context *lms = priv->key;
        size_t olen = 0;
        if (mbedtls_lms_sign(lms, msg, msg_len, sig, *sig_len, &olen,
                              rng_callback, NULL) != 0)
            return -1;
        *sig_len = olen;
        return 0;
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, sig_len,
                                                         msg, msg_len,
                                                         priv->key) != 0)
            return -1;
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
    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_rsa_context *rsa = pub->key;
        if (mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL,
                                     MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA384,
                                     0, msg, sig) != 0)
            return -1;
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
        if (mbedtls_lms_verify(pub->key, msg, msg_len, sig, sig_len) != 0)
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
        mbedtls_lms_free((mbedtls_lms_context *)key->key);
        free(key->key);
    } else if (key->alg == CRYPTO_ALG_MLDSA87) {
        free(key->key);
    }
    key->key = NULL;
    key->key_len = 0;
}
