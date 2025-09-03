#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "util.h"

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/lms.h>

#include "api.h" /* PQClean ml-dsa-87 */

typedef struct {
    mbedtls_lms_private_t priv;
    mbedtls_lms_public_t pub;
} lms_pair;

typedef struct {
    crypto_key first_priv;
    crypto_key first_pub;
    crypto_key second_priv;
    crypto_key second_pub;
} hybrid_pair;

#define LMS_SIG_LEN \
    MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10, MBEDTLS_LMOTS_SHA256_N32_W8)

#define CRYPTO_RSA_DER_MAX_LEN 4096


static int rng_callback(void *ctx, unsigned char *out, size_t len) {
    return mbedtls_ctr_drbg_random((mbedtls_ctr_drbg_context *)ctx, out, len);
}

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

    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_pk_context *pk = calloc(1, sizeof(*pk));
        if (!pk) {
            return -1;
        }
        mbedtls_pk_init(pk);
        if (mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
            free(pk);
            return -1;
        }
        if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), rng_callback, &drbg,
                                CRYPTO_RSA_BITS, CRYPTO_RSA_EXPONENT) != 0) {
            mbedtls_pk_free(pk);
            free(pk);
            return -1;
        }
        out_priv->alg     = CRYPTO_ALG_RSA4096;
        out_pub->alg      = CRYPTO_ALG_RSA4096;
        out_priv->key     = pk;
        out_pub->key      = pk; /* share context */
        out_priv->key_len = sizeof(*pk);
        out_pub->key_len  = sizeof(*pk);
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
        lms_pair *pair = calloc(1, sizeof(*pair));
        if (!pair) {
            return -1;
        }
        mbedtls_lms_private_init(&pair->priv);
        mbedtls_lms_public_init(&pair->pub);
        unsigned char seed[CRYPTO_LMS_SEED_SIZE];
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
        out_priv->alg     = CRYPTO_ALG_LMS;
        out_pub->alg      = CRYPTO_ALG_LMS;
        out_priv->key     = pair;
        out_pub->key      = pair; /* same struct contains priv/pub */
        out_priv->key_len = sizeof(*pair);
        out_pub->key_len  = sizeof(*pair);
        return 0;
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        unsigned char *pk = NULL;
        unsigned char *sk = NULL;
        pk = malloc(PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES);
        sk = malloc(PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES);
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
    } else if (alg == CRYPTO_ALG_RSA4096_LMS ||
               alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
               alg == CRYPTO_ALG_LMS_MLDSA87) {
        hybrid_pair *pair = calloc(1, sizeof(*pair));
        if (!pair) {
            return -1;
        }
        crypto_alg first, second;
        if (alg == CRYPTO_ALG_RSA4096_LMS) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_LMS;
        } else if (alg == CRYPTO_ALG_RSA4096_MLDSA87) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_MLDSA87;
        } else {
            first  = CRYPTO_ALG_LMS;
            second = CRYPTO_ALG_MLDSA87;
        }
        if (crypto_keygen(first, &pair->first_priv, &pair->first_pub) != 0 ||
            crypto_keygen(second, &pair->second_priv, &pair->second_pub) != 0) {
            crypto_free_key(&pair->first_priv);
            pair->first_pub.key = NULL;
            crypto_free_key(&pair->first_pub);
            crypto_free_key(&pair->second_priv);
            pair->second_pub.key = NULL;
            crypto_free_key(&pair->second_pub);
            free(pair);
            return -1;
        }
        out_priv->alg     = alg;
        out_pub->alg      = alg;
        out_priv->key     = pair;
        out_pub->key      = pair;
        out_priv->key_len = sizeof(*pair);
        out_pub->key_len  = sizeof(*pair);
        return 0;
    }
    return -1;
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

    if (alg == CRYPTO_ALG_RSA4096_LMS ||
        alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
        alg == CRYPTO_ALG_LMS_MLDSA87) {
        return crypto_keygen(alg, out_priv, out_pub);
    }

    unsigned char *priv_buf = NULL;
    unsigned char *pub_buf  = NULL;

    size_t priv_len = 0;
    size_t pub_len  = 0;
    if (read_file(priv_path, &priv_buf, &priv_len) != 0 ||
        read_file(pub_path, &pub_buf, &pub_len) != 0) {
        free(priv_buf);
        free(pub_buf);
        return crypto_keygen(alg, out_priv, out_pub);
    }

    if (alg == CRYPTO_ALG_RSA4096) {
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
            return crypto_keygen(alg, out_priv, out_pub);
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
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        if (priv_len != PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES ||
            pub_len != PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES) {
            free(priv_buf);
            free(pub_buf);
            return crypto_keygen(alg, out_priv, out_pub);
        }
        out_priv->alg     = CRYPTO_ALG_MLDSA87;
        out_pub->alg      = CRYPTO_ALG_MLDSA87;
        out_priv->key     = priv_buf;
        out_priv->key_len = priv_len;
        out_pub->key      = pub_buf;
        out_pub->key_len  = pub_len;
        return 0;
    } else {
        /* LMS import of private keys is not supported in Mbed TLS */
        free(priv_buf);
        free(pub_buf);
        return crypto_keygen(alg, out_priv, out_pub);
    }
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
    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_pk_context *pk = priv->key;
        unsigned char hash[CRYPTO_SHA384_DIGEST_SIZE];
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                       msg, msg_len, hash) != 0) {
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            return -1;
        }
        size_t sig_size = mbedtls_pk_get_len(pk);
        if (mbedtls_pk_sign(pk, MBEDTLS_MD_SHA384, hash, sizeof(hash),
                            sig, sig_size, sig_len, rng_callback, &drbg) != 0) {
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            return -1;
        }
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
    } else if (alg == CRYPTO_ALG_RSA4096_LMS ||
               alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
               alg == CRYPTO_ALG_LMS_MLDSA87) {
        hybrid_pair *pair = priv->key;
        size_t len1 = 0;
        size_t len2 = 0;
        crypto_alg first, second;
        if (alg == CRYPTO_ALG_RSA4096_LMS) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_LMS;
            len1   = CRYPTO_RSA_SIG_SIZE;
            len2   = LMS_SIG_LEN;
        } else if (alg == CRYPTO_ALG_RSA4096_MLDSA87) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_MLDSA87;
            len1   = CRYPTO_RSA_SIG_SIZE;
            len2   = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        } else {
            first  = CRYPTO_ALG_LMS;
            second = CRYPTO_ALG_MLDSA87;
            len1   = LMS_SIG_LEN;
            len2   = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        }
        size_t tmp = len1;
        if (crypto_sign(first, &pair->first_priv, msg, msg_len, sig, &tmp) != 0 ||
            tmp != len1) {
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            return -1;
        }
        tmp = len2;
        if (crypto_sign(second, &pair->second_priv, msg, msg_len, sig + len1, &tmp) != 0 ||
            tmp != len2) {
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            return -1;
        }
        *sig_len = len1 + len2;
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        return 0;
    }
    return -1;
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
    unsigned char hash[CRYPTO_SHA384_DIGEST_SIZE];
    if (alg == CRYPTO_ALG_RSA4096) {
        mbedtls_pk_context *pk = pub->key;
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
                       msg, msg_len, hash) != 0 ||
            mbedtls_pk_verify(pk, MBEDTLS_MD_SHA384, hash, sizeof(hash), sig, sig_len) != 0) {
            return -1;
        }
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
        lms_pair *pair = pub->key;
        if (mbedtls_lms_verify(&pair->pub, msg, msg_len, sig, sig_len) != 0) {
            return -1;
        }
        return 0;
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len,
                                                     msg, msg_len,
                                                     pub->key) != 0) {
            return -1;
        }
        return 0;
    } else if (alg == CRYPTO_ALG_RSA4096_LMS ||
               alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
               alg == CRYPTO_ALG_LMS_MLDSA87) {
        hybrid_pair *pair = pub->key;
        size_t len1 = 0;
        size_t len2 = 0;
        crypto_alg first, second;
        if (alg == CRYPTO_ALG_RSA4096_LMS) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_LMS;
            len1   = CRYPTO_RSA_SIG_SIZE;
            len2   = LMS_SIG_LEN;
        } else if (alg == CRYPTO_ALG_RSA4096_MLDSA87) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_MLDSA87;
            len1   = CRYPTO_RSA_SIG_SIZE;
            len2   = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        } else {
            first  = CRYPTO_ALG_LMS;
            second = CRYPTO_ALG_MLDSA87;
            len1   = LMS_SIG_LEN;
            len2   = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
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
        mbedtls_pk_context *pk = priv->key;
        unsigned char buf[CRYPTO_RSA_DER_MAX_LEN];
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
        out_priv->alg     = alg;

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
        out_pub->alg     = alg;
        return 0;
    } else if (alg == CRYPTO_ALG_LMS) {
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
        /* mbed TLS exposes no official serialization API for
         * mbedtls_lms_private_t. We copy internal fields accessed via
         * MBEDTLS_PRIVATE to flatten the structure, which is inherently
         * fragile and may break with future library changes. */
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
        out_priv->alg     = alg;

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
        out_pub->alg     = alg;
        return 0;
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        out_priv->key = malloc(priv->key_len);
        out_pub->key  = malloc(pub->key_len);
        if (!out_priv->key || !out_pub->key) {
            free(out_priv->key);
            free(out_pub->key);
            return -1;
        }
        memcpy(out_priv->key, priv->key, priv->key_len);
        memcpy(out_pub->key, pub->key, pub->key_len);
        out_priv->key_len = priv->key_len;
        out_pub->key_len  = pub->key_len;
        out_priv->alg     = alg;
        out_pub->alg      = alg;
        return 0;
    }
    return -1;
}

int crypto_export_keypair_components(crypto_alg alg, const crypto_key *priv,
                                     const crypto_key *pub,
                                     crypto_key out_priv[2],
                                     crypto_key out_pub[2])
{
    if (!priv || !pub || !out_priv || !out_pub) {
        return -1;
    }
    memset(out_priv, 0, sizeof(crypto_key) * 2);
    memset(out_pub, 0, sizeof(crypto_key) * 2);
    if (alg == CRYPTO_ALG_RSA4096 ||
        alg == CRYPTO_ALG_LMS ||
        alg == CRYPTO_ALG_MLDSA87) {
        return export_simple(alg, priv, pub, &out_priv[0], &out_pub[0]);
    }
    if (alg == CRYPTO_ALG_RSA4096_LMS ||
        alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
        alg == CRYPTO_ALG_LMS_MLDSA87) {
        const hybrid_pair *pair = priv->key;
        crypto_alg first, second;
        if (alg == CRYPTO_ALG_RSA4096_LMS) {
            first = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_LMS;
        } else if (alg == CRYPTO_ALG_RSA4096_MLDSA87) {
            first = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_MLDSA87;
        } else {
            first = CRYPTO_ALG_LMS;
            second = CRYPTO_ALG_MLDSA87;
        }
        if (export_simple(first, &pair->first_priv, &pair->first_pub,
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
    return -1;
}

int crypto_export_keypair(crypto_alg alg, const crypto_key *priv,
                          const crypto_key *pub, crypto_key *out_priv,
                          crypto_key *out_pub)
{
    if (!priv || !pub || !out_priv || !out_pub) {
        return -1;
    }
    if (alg == CRYPTO_ALG_RSA4096_LMS ||
        alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
        alg == CRYPTO_ALG_LMS_MLDSA87) {
        const hybrid_pair *pair = priv->key;
        crypto_key first_priv = {0}, first_pub = {0};
        crypto_key second_priv = {0}, second_pub = {0};
        crypto_alg first, second;
        if (alg == CRYPTO_ALG_RSA4096_LMS) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_LMS;
        } else if (alg == CRYPTO_ALG_RSA4096_MLDSA87) {
            first  = CRYPTO_ALG_RSA4096;
            second = CRYPTO_ALG_MLDSA87;
        } else {
            first  = CRYPTO_ALG_LMS;
            second = CRYPTO_ALG_MLDSA87;
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
        mbedtls_pk_free((mbedtls_pk_context *)key->key);
        free(key->key);
    } else if (key->alg == CRYPTO_ALG_LMS) {
        lms_pair *pair = key->key;
        mbedtls_lms_private_free(&pair->priv);
        mbedtls_lms_public_free(&pair->pub);
        free(pair);
    } else if (key->alg == CRYPTO_ALG_MLDSA87) {
        free(key->key);
    } else if (key->alg == CRYPTO_ALG_RSA4096_LMS ||
               key->alg == CRYPTO_ALG_RSA4096_MLDSA87 ||
               key->alg == CRYPTO_ALG_LMS_MLDSA87) {
        hybrid_pair *pair = key->key;
        crypto_free_key(&pair->first_priv);
        pair->first_pub.key = NULL;
        crypto_free_key(&pair->first_pub);
        crypto_free_key(&pair->second_priv);
        pair->second_pub.key = NULL;
        crypto_free_key(&pair->second_pub);
        free(pair);
    }
    key->key     = NULL;
    key->key_len = 0;
}
