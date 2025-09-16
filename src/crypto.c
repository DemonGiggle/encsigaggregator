#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "hybrid_crypto.h"
#include "lms.h"
#include "rsa.h"
#include "mldsa.h"

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/lms.h>


const char *crypto_alg_name(int alg)
{
    switch (alg) {
    case CRYPTO_ALG_RSA4096:
        return "rsa";
    case CRYPTO_ALG_LMS:
        return "lms";
    case CRYPTO_ALG_MLDSA87:
        return "mldsa87";
    case CRYPTO_ALG_RSA4096_LMS:
        return "rsa-lms";
    case CRYPTO_ALG_RSA4096_MLDSA87:
        return "rsa-mldsa87";
    case CRYPTO_ALG_LMS_MLDSA87:
        return "lms-mldsa87";
    default:
        return "unknown";
    }
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

    int ret = -1;
    if (alg == CRYPTO_ALG_RSA4096) {
        ret = rsa_keygen(&drbg, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_LMS) {
        ret = lms_keygen(&drbg, out_priv, out_pub);
    } else if (alg == CRYPTO_ALG_MLDSA87) {
        ret = mldsa_keygen(out_priv, out_pub);
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

int crypto_load_keypair(crypto_alg alg, const char *priv_path, const char *pub_path,
                        crypto_key *out_priv, crypto_key *out_pub)
{
    if (!out_priv || !out_pub) {
        return -1;
    }
    if (!priv_path || !pub_path) {
        return crypto_keygen(alg, out_priv, out_pub);
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


int crypto_export_keypair(crypto_alg alg, const crypto_key *priv,
                          const crypto_key *pub, crypto_key *out_priv,
                          crypto_key *out_pub)
{
    if (!priv || !pub || !out_priv || !out_pub) {
        return -1;
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
    } else {
        key->key = NULL;
        key->key_len = 0;
        return;
    }
    key->key     = NULL;
    key->key_len = 0;
}
