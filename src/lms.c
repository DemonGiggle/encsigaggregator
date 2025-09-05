#include "lms.h"
#include <stdlib.h>
#include <string.h>
#include <mbedtls/entropy.h>
#include <mbedtls/lms.h>

typedef struct {
    mbedtls_lms_private_t priv;
    mbedtls_lms_public_t pub;
} lms_pair;

static int rng_callback(void *ctx, unsigned char *out, size_t len) {
    return mbedtls_ctr_drbg_random((mbedtls_ctr_drbg_context *)ctx, out, len);
}

int lms_keygen(mbedtls_ctr_drbg_context *drbg,
               crypto_key *out_priv, crypto_key *out_pub) {
    if (!drbg || !out_priv || !out_pub) {
        return -1;
    }
    lms_pair *pair = calloc(1, sizeof(*pair));
    if (!pair) {
        return -1;
    }
    mbedtls_lms_private_init(&pair->priv);
    mbedtls_lms_public_init(&pair->pub);
    unsigned char seed[CRYPTO_LMS_SEED_SIZE];
    if (mbedtls_ctr_drbg_random(drbg, seed, sizeof(seed)) != 0 ||
        mbedtls_lms_generate_private_key(&pair->priv,
                                         MBEDTLS_LMS_SHA256_M32_H10,
                                         MBEDTLS_LMOTS_SHA256_N32_W8,
                                         rng_callback, drbg,
                                         seed, sizeof(seed)) != 0 ||
        mbedtls_lms_calculate_public_key(&pair->pub, &pair->priv) != 0) {
        mbedtls_lms_private_free(&pair->priv);
        mbedtls_lms_public_free(&pair->pub);
        free(pair);
        return -1;
    }
    out_priv->alg     = CRYPTO_ALG_LMS;
    out_pub->alg      = CRYPTO_ALG_LMS;
    out_priv->key     = pair;
    out_pub->key      = pair;
    out_priv->key_len = sizeof(*pair);
    out_pub->key_len  = sizeof(*pair);
    return 0;
}

int lms_load_keypair(const char *priv_path, const char *pub_path,
                     crypto_key *out_priv, crypto_key *out_pub) {
    (void)priv_path;
    (void)pub_path;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        return -1;
    }
    int ret = lms_keygen(&drbg, out_priv, out_pub);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int lms_sign(mbedtls_ctr_drbg_context *drbg, const crypto_key *priv,
             const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len) {
    if (!drbg || !priv || !msg || !sig || !sig_len ||
        priv->alg != CRYPTO_ALG_LMS) {
        return -1;
    }
    lms_pair *pair = priv->key;
    size_t olen = 0;
    if (mbedtls_lms_sign(&pair->priv, rng_callback, drbg,
                          msg, msg_len, sig, *sig_len, &olen) != 0) {
        return -1;
    }
    *sig_len = olen;
    return 0;
}

int lms_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len) {
    if (!pub || !msg || !sig || pub->alg != CRYPTO_ALG_LMS) {
        return -1;
    }
    lms_pair *pair = pub->key;
    if (mbedtls_lms_verify(&pair->pub, msg, msg_len, sig, sig_len) != 0) {
        return -1;
    }
    return 0;
}

int lms_export_keypair(const crypto_key *priv, const crypto_key *pub,
                       crypto_key *out_priv, crypto_key *out_pub) {
    if (!priv || !pub || !out_priv || !out_pub) {
        return -1;
    }
    const lms_pair *pair = priv->key;
    const mbedtls_lms_private_t *pr = &pair->priv;
    size_t count = 1u << MBEDTLS_LMS_H_TREE_HEIGHT(
        pr->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type));
    size_t priv_size =
        sizeof(pr->MBEDTLS_PRIVATE(params)) +
        sizeof(pr->MBEDTLS_PRIVATE(q_next_usable_key)) +
        count * sizeof(mbedtls_lmots_private_t) +
        count * sizeof(mbedtls_lmots_public_t) +
        sizeof(pr->MBEDTLS_PRIVATE(have_private_key));
    unsigned char *pbuf = malloc(priv_size);
    if (!pbuf) {
        return -1;
    }
    unsigned char *p = pbuf;
    memcpy(p, &pr->MBEDTLS_PRIVATE(params),
           sizeof(pr->MBEDTLS_PRIVATE(params)));
    p += sizeof(pr->MBEDTLS_PRIVATE(params));
    memcpy(p, &pr->MBEDTLS_PRIVATE(q_next_usable_key),
           sizeof(pr->MBEDTLS_PRIVATE(q_next_usable_key)));
    p += sizeof(pr->MBEDTLS_PRIVATE(q_next_usable_key));
    memcpy(p, pr->MBEDTLS_PRIVATE(ots_private_keys),
           count * sizeof(mbedtls_lmots_private_t));
    p += count * sizeof(mbedtls_lmots_private_t);
    memcpy(p, pr->MBEDTLS_PRIVATE(ots_public_keys),
           count * sizeof(mbedtls_lmots_public_t));
    p += count * sizeof(mbedtls_lmots_public_t);
    memcpy(p, &pr->MBEDTLS_PRIVATE(have_private_key),
           sizeof(pr->MBEDTLS_PRIVATE(have_private_key)));
    out_priv->key     = pbuf;
    out_priv->key_len = priv_size;
    out_priv->alg     = CRYPTO_ALG_LMS;

    size_t pub_len = MBEDTLS_LMS_PUBLIC_KEY_LEN(
        pr->MBEDTLS_PRIVATE(params).MBEDTLS_PRIVATE(type));
    unsigned char *pub_buf = malloc(pub_len);
    if (!pub_buf) {
        free(pbuf);
        return -1;
    }
    size_t olen = 0;
    if (mbedtls_lms_export_public_key(&pair->pub, pub_buf, pub_len,
                                      &olen) != 0 || olen != pub_len) {
        free(pbuf);
        free(pub_buf);
        return -1;
    }
    out_pub->key     = pub_buf;
    out_pub->key_len = pub_len;
    out_pub->alg     = CRYPTO_ALG_LMS;
    return 0;
}

void lms_free_key(crypto_key *key) {
    if (!key || key->alg != CRYPTO_ALG_LMS || !key->key) {
        return;
    }
    lms_pair *pair = key->key;
    mbedtls_lms_private_free(&pair->priv);
    mbedtls_lms_public_free(&pair->pub);
    free(pair);
    key->key     = NULL;
    key->key_len = 0;
}
