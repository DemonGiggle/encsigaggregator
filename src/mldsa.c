#include "mldsa.h"
#include <stdlib.h>
#include <string.h>
#include "util.h"

int mldsa_keygen(crypto_key *out_priv, crypto_key *out_pub) {
    if (!out_priv || !out_pub) {
        return -1;
    }
    unsigned char *pk = malloc(PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES);
    if (!pk || !sk) {
        free(pk);
        free(sk);
        return -1;
    }
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
        free(pk);
        free(sk);
        return -1;
    }
    out_pub->alg      = CRYPTO_ALG_MLDSA87;
    out_priv->alg     = CRYPTO_ALG_MLDSA87;
    out_pub->key      = pk;
    out_pub->key_len  = PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;
    out_priv->key     = sk;
    out_priv->key_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;
    return 0;
}

int mldsa_load_keypair(const char *priv_path, const char *pub_path,
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
    if (priv_len != PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES ||
        pub_len != PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        free(priv_buf);
        free(pub_buf);
        return -1;
    }
    out_priv->alg     = CRYPTO_ALG_MLDSA87;
    out_pub->alg      = CRYPTO_ALG_MLDSA87;
    out_priv->key     = priv_buf;
    out_priv->key_len = priv_len;
    out_pub->key      = pub_buf;
    out_pub->key_len  = pub_len;
    return 0;
}

int mldsa_sign(const crypto_key *priv, const uint8_t *msg, size_t msg_len,
               uint8_t *sig, size_t *sig_len) {
    if (!priv || !msg || !sig || !sig_len || priv->alg != CRYPTO_ALG_MLDSA87) {
        return -1;
    }
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, sig_len,
                                                     msg, msg_len,
                                                     priv->key) != 0) {
        return -1;
    }
    return 0;
}

int mldsa_verify(const crypto_key *pub, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len) {
    if (!pub || !msg || !sig || pub->alg != CRYPTO_ALG_MLDSA87) {
        return -1;
    }
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len,
                                                 msg, msg_len,
                                                 pub->key) != 0) {
        return -1;
    }
    return 0;
}

int mldsa_export_keypair(const crypto_key *priv, const crypto_key *pub,
                         crypto_key *out_priv, crypto_key *out_pub) {
    if (!priv || !pub || !out_priv || !out_pub ||
        priv->alg != CRYPTO_ALG_MLDSA87 || pub->alg != CRYPTO_ALG_MLDSA87) {
        return -1;
    }
    out_priv->key_len = priv->key_len;
    out_pub->key_len  = pub->key_len;
    out_priv->key = malloc(priv->key_len);
    out_pub->key  = malloc(pub->key_len);
    if (!out_priv->key || !out_pub->key) {
        free(out_priv->key);
        free(out_pub->key);
        out_priv->key = NULL;
        out_pub->key  = NULL;
        return -1;
    }
    memcpy(out_priv->key, priv->key, priv->key_len);
    memcpy(out_pub->key, pub->key, pub->key_len);
    out_priv->alg = CRYPTO_ALG_MLDSA87;
    out_pub->alg  = CRYPTO_ALG_MLDSA87;
    return 0;
}

void mldsa_free_key(crypto_key *key) {
    if (!key || key->alg != CRYPTO_ALG_MLDSA87 || !key->key) {
        return;
    }
    free(key->key);
    key->key     = NULL;
    key->key_len = 0;
}

