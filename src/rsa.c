#include "rsa.h"
#include <stdlib.h>
#include <string.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include "util.h"

#define RSA_DER_MAX_LEN 4096

static int rng_callback(void *ctx, unsigned char *out, size_t len) {
    return mbedtls_ctr_drbg_random((mbedtls_ctr_drbg_context *)ctx, out, len);
}

int rsa_keygen(mbedtls_ctr_drbg_context *drbg, crypto_key *out_priv, crypto_key *out_pub) {
    if (!drbg || !out_priv || !out_pub) {
        return -1;
    }
    mbedtls_pk_context *pk = calloc(1, sizeof(*pk));
    if (!pk) {
        return -1;
    }
    mbedtls_pk_init(pk);
    if (mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        free(pk);
        return -1;
    }
    if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), rng_callback, drbg,
                            CRYPTO_RSA_BITS, CRYPTO_RSA_EXPONENT) != 0) {
        mbedtls_pk_free(pk);
        free(pk);
        return -1;
    }
    out_priv->alg     = CRYPTO_ALG_RSA4096;
    out_pub->alg      = CRYPTO_ALG_RSA4096;
    out_priv->key     = pk;
    out_pub->key      = pk;
    out_priv->key_len = sizeof(*pk);
    out_pub->key_len  = sizeof(*pk);
    return 0;
}

int rsa_load_keypair(const char *priv_path, const char *pub_path,
                     crypto_key *out_priv, crypto_key *out_pub) {
    unsigned char *priv_buf = NULL;
    unsigned char *pub_buf  = NULL;
    size_t priv_len = 0;
    size_t pub_len  = 0;
    if (read_file(priv_path, &priv_buf, &priv_len) != 0 ||
        read_file(pub_path, &pub_buf, &pub_len) != 0) {
        free(priv_buf);
        free(pub_buf);
        return -1;
    }
    mbedtls_pk_context *pk = calloc(1, sizeof(*pk));
    if (!pk) {
        free(priv_buf);
        free(pub_buf);
        return -1;
    }
    mbedtls_pk_init(pk);
    if (mbedtls_pk_parse_key(pk, priv_buf, priv_len, NULL, 0, NULL, NULL) != 0 ||
        mbedtls_pk_parse_public_key(pk, pub_buf, pub_len) != 0) {
        mbedtls_pk_free(pk);
        free(pk);
        free(priv_buf);
        free(pub_buf);
        return -1;
    }
    free(priv_buf);
    free(pub_buf);
    out_priv->alg     = CRYPTO_ALG_RSA4096;
    out_pub->alg      = CRYPTO_ALG_RSA4096;
    out_priv->key     = pk;
    out_pub->key      = pk;
    out_priv->key_len = sizeof(*pk);
    out_pub->key_len  = sizeof(*pk);
    return 0;
}

int rsa_sign(mbedtls_ctr_drbg_context *drbg, const crypto_key *priv,
             const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len) {
    if (!drbg || !priv || !msg || !sig || !sig_len ||
        priv->alg != CRYPTO_ALG_RSA4096) {
        return -1;
    }
    mbedtls_pk_context *pk = priv->key;
    unsigned char hash[CRYPTO_SHA384_DIGEST_SIZE];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                   msg, msg_len, hash) != 0) {
        return -1;
    }
    size_t sig_size = mbedtls_pk_get_len(pk);
    if (mbedtls_pk_sign(pk, MBEDTLS_MD_SHA384, hash, sizeof(hash),
                        sig, sig_size, sig_len, rng_callback, drbg) != 0) {
        return -1;
    }
    return 0;
}

int rsa_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len) {
    if (!pub || !msg || !sig || pub->alg != CRYPTO_ALG_RSA4096) {
        return -1;
    }
    mbedtls_pk_context *pk = pub->key;
    unsigned char hash[CRYPTO_SHA384_DIGEST_SIZE];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                   msg, msg_len, hash) != 0 ||
        mbedtls_pk_verify(pk, MBEDTLS_MD_SHA384, hash, sizeof(hash),
                          sig, sig_len) != 0) {
        return -1;
    }
    return 0;
}

int rsa_export_keypair(const crypto_key *priv, const crypto_key *pub,
                       crypto_key *out_priv, crypto_key *out_pub) {
    if (!priv || !pub || !out_priv || !out_pub ||
        priv->alg != CRYPTO_ALG_RSA4096 || pub->alg != CRYPTO_ALG_RSA4096) {
        return -1;
    }
    mbedtls_pk_context *pk = priv->key;
    unsigned char buf[RSA_DER_MAX_LEN];
    int len = mbedtls_pk_write_key_der(pk, buf, sizeof(buf));
    if (len <= 0) {
        return -1;
    }
    out_priv->key = malloc(len);
    if (!out_priv->key) {
        return -1;
    }
    memcpy(out_priv->key, buf + sizeof(buf) - len, len);
    out_priv->key_len = len;
    out_priv->alg     = CRYPTO_ALG_RSA4096;

    len = mbedtls_pk_write_pubkey_der(pk, buf, sizeof(buf));
    if (len <= 0) {
        free(out_priv->key);
        return -1;
    }
    out_pub->key = malloc(len);
    if (!out_pub->key) {
        free(out_priv->key);
        return -1;
    }
    memcpy(out_pub->key, buf + sizeof(buf) - len, len);
    out_pub->key_len = len;
    out_pub->alg     = CRYPTO_ALG_RSA4096;
    return 0;
}

void rsa_free_key(crypto_key *key) {
    if (!key || key->alg != CRYPTO_ALG_RSA4096 || !key->key) {
        return;
    }
    mbedtls_pk_free((mbedtls_pk_context *)key->key);
    free(key->key);
    key->key     = NULL;
    key->key_len = 0;
}

