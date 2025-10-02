#define _POSIX_C_SOURCE 200809L /* for mkstemp and related functions */
#include "crypto.h"
#include "hybrid_crypto.h"
#include "rsa.h"
#include "lms.h"
#include "mldsa.h"
#include "util.h"
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <mbedtls/lms.h>
#include <mbedtls/private_access.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <stdio.h>
#include <unistd.h>
#include "api.h"

/* Write key material to a temporary file in place */
static void write_key_to_temp_file(const crypto_key *key, char path[]) {
    int fd = mkstemp(path);
    assert_true(fd != -1);
    FILE *f = fdopen(fd, "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(key->key, 1, key->key_len, f), key->key_len);
    fclose(f);
}

/* Compute SHA-384 of 'abc' and compare against known vector */
static void test_sha384(void **state) {
    (void)state;
    uint8_t out[CRYPTO_SHA384_DIGEST_SIZE];
    assert_int_equal(crypto_sha384((const uint8_t *)"abc", 3, out), 0);
    const uint8_t expected[CRYPTO_SHA384_DIGEST_SIZE] = {
        0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,
        0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
        0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,
        0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
        0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,
        0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
    };
    assert_memory_equal(out, expected, CRYPTO_SHA384_DIGEST_SIZE);
}

/* Encrypt and decrypt a block-aligned payload with AES-CBC */
static void test_aes_cbc(void **state) {
    (void)state;
    uint8_t key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_256, NULL, NULL, key, iv), 0);

    const uint8_t plaintext[32] =
        "0123456789abcdef0123456789abcdef";
    uint8_t enc[48];
    size_t enc_len = 0;
    uint8_t dec[32];
    size_t dec_len = 0;
    assert_int_equal(crypto_encrypt_aescbc(key, CRYPTO_AES_KEY_BITS_256, iv,
                                          plaintext, 32, enc, &enc_len), 0);
    assert_int_equal(enc_len, 48);
    assert_int_equal(crypto_decrypt_aescbc(key, CRYPTO_AES_KEY_BITS_256, iv,
                                          enc, enc_len, dec, &dec_len), 0);
    assert_int_equal(dec_len, 32);
    assert_memory_equal(dec, plaintext, 32);
}

/* Encrypt and decrypt data whose length is not a multiple of the block size */
static void test_aes_cbc_unaligned(void **state) {
    (void)state;
    uint8_t key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_256, NULL, NULL, key, iv), 0);

    const uint8_t plaintext[] = "unaligned payload";
    uint8_t enc[32];
    size_t enc_len = 0;
    uint8_t dec[32];
    size_t dec_len = 0;
    assert_int_equal(crypto_encrypt_aescbc(key, CRYPTO_AES_KEY_BITS_256, iv,
                                          plaintext, sizeof(plaintext) - 1,
                                          enc, &enc_len), 0);
    assert_int_equal(enc_len, 32);
    assert_int_equal(crypto_decrypt_aescbc(key, CRYPTO_AES_KEY_BITS_256, iv,
                                          enc, enc_len, dec, &dec_len), 0);
    assert_int_equal(dec_len, sizeof(plaintext) - 1);
    assert_memory_equal(dec, plaintext, sizeof(plaintext) - 1);
}

/* Handle AES-CBC operations on an empty plaintext */
static void test_aes_cbc_empty(void **state) {
    (void)state;
    uint8_t key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_256, NULL, NULL, key, iv), 0);

    const uint8_t *plaintext = (const uint8_t *)"";
    uint8_t enc[CRYPTO_AES_IV_SIZE];
    size_t enc_len = 0;
    uint8_t dec[CRYPTO_AES_IV_SIZE];
    size_t dec_len = 0;
    assert_int_equal(crypto_encrypt_aescbc(key, CRYPTO_AES_KEY_BITS_256, iv,
                                          plaintext, 0, enc, &enc_len), 0);
    assert_int_equal(enc_len, CRYPTO_AES_IV_SIZE);
    assert_int_equal(crypto_decrypt_aescbc(key, CRYPTO_AES_KEY_BITS_256, iv,
                                          enc, enc_len, dec, &dec_len), 0);
    assert_int_equal(dec_len, 0);
}

#include <stdio.h>
#include <unistd.h>

/* Temporary file paths for AES key/IV used in tests */
struct aes_paths {
    char key_path[sizeof("/tmp/keyXXXXXX")];
    char iv_path[sizeof("/tmp/ivXXXXXX")];
};

static int aes_setup(void **state) {
    struct aes_paths *p = malloc(sizeof(*p));
    if (!p)
        return -1;
    strcpy(p->key_path, "/tmp/keyXXXXXX");
    int kfd = mkstemp(p->key_path);
    if (kfd == -1) {
        free(p);
        return -1;
    }
    close(kfd);
    strcpy(p->iv_path, "/tmp/ivXXXXXX");
    int ifd = mkstemp(p->iv_path);
    if (ifd == -1) {
        unlink(p->key_path);
        free(p);
        return -1;
    }
    close(ifd);
    *state = p;
    return 0;
}

static int aes_teardown(void **state) {
    struct aes_paths *p = *state;
    unlink(p->key_path);
    unlink(p->iv_path);
    free(p);
    return 0;
}

static void aes_roundtrip(size_t bits, const struct aes_paths *p) {
    uint8_t key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(bits, NULL, NULL, key, iv), 0);

    FILE *f = fopen(p->key_path, "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(key, 1, bits / 8, f), bits / 8);
    fclose(f);
    f = fopen(p->iv_path, "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(iv, 1, CRYPTO_AES_IV_SIZE, f), CRYPTO_AES_IV_SIZE);
    fclose(f);

    uint8_t key2[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv2[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(bits, p->key_path, p->iv_path, key2, iv2), 0);
    assert_memory_equal(key, key2, bits / 8);
    assert_memory_equal(iv, iv2, CRYPTO_AES_IV_SIZE);
}

static void test_aes_serialize_128(void **state) {
    aes_roundtrip(CRYPTO_AES_KEY_BITS_128, (const struct aes_paths *)*state);
}

static void test_aes_serialize_192(void **state) {
    aes_roundtrip(CRYPTO_AES_KEY_BITS_192, (const struct aes_paths *)*state);
}

static void test_aes_serialize_256(void **state) {
    aes_roundtrip(CRYPTO_AES_KEY_BITS_256, (const struct aes_paths *)*state);
}

/* Generate RSA key pair and verify signing round-trip */
static void test_rsa_sign_verify(void **state) {
    (void)state;
    crypto_key priv = {0}, pub = {0};
    assert_int_equal(crypto_keygen(CRYPTO_ALG_RSA4096, &priv, &pub), 0);
    const uint8_t msg[] = "test message";
    /* large enough to hold the RSA signature */
    uint8_t sig[CRYPTO_MAX_SIG_SIZE];
    size_t sig_len = 0; /* crypto_sign should update this */
    assert_int_equal(crypto_sign(CRYPTO_ALG_RSA4096, &priv,
                                 msg, sizeof(msg) - 1,
                                 sig, &sig_len), 0);
    assert_int_equal(sig_len, CRYPTO_RSA_SIG_SIZE);
    assert_true(sig_len < sizeof(sig));
    assert_int_equal(crypto_verify(CRYPTO_ALG_RSA4096, &pub,
                                   msg, sizeof(msg) - 1,
                                   sig, sig_len), 0);
    crypto_free_key(&priv);
    crypto_free_key(&pub);
}

/* Generate LMS key pair and verify signing round-trip */
static void test_lms_sign_verify(void **state) {
    (void)state;
    crypto_key priv = {0}, pub = {0};
    assert_int_equal(crypto_keygen(CRYPTO_ALG_LMS, &priv, &pub), 0);
    const uint8_t msg[] = "test message";
    uint8_t sig[MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10,
                                    MBEDTLS_LMOTS_SHA256_N32_W8) + 32];
    size_t sig_len = sizeof(sig);
    assert_int_equal(crypto_sign(CRYPTO_ALG_LMS, &priv,
                                 msg, sizeof(msg) - 1,
                                 sig, &sig_len), 0);
    assert_int_equal(sig_len,
                     MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10,
                                        MBEDTLS_LMOTS_SHA256_N32_W8));
    assert_true(sig_len < sizeof(sig));
    assert_int_equal(crypto_verify(CRYPTO_ALG_LMS, &pub,
                                   msg, sizeof(msg) - 1,
                                   sig, sig_len), 0);
    crypto_free_key(&priv);
    crypto_free_key(&pub);
}

/* Ensure LMS q_next_usable_key is preserved across serialization */
static void test_lms_q_next_usable_key(void **state) {
    (void)state;
    crypto_key priv = {0}, pub = {0};
    assert_int_equal(crypto_keygen(CRYPTO_ALG_LMS, &priv, &pub), 0);

    mbedtls_lms_private_t *pr = priv.key;
    uint32_t before = pr->MBEDTLS_PRIVATE(q_next_usable_key);

    const uint8_t msg[] = "test message";
    uint8_t sig[MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10,
                                    MBEDTLS_LMOTS_SHA256_N32_W8) + 32];
    size_t sig_len = sizeof(sig);
    assert_int_equal(crypto_sign(CRYPTO_ALG_LMS, &priv,
                                 msg, sizeof(msg) - 1,
                                 sig, &sig_len), 0);

    uint32_t after = pr->MBEDTLS_PRIVATE(q_next_usable_key);
    assert_int_equal(after, before + 1);

    crypto_key priv_blob = {0}, pub_blob = {0};
    assert_int_equal(crypto_export_keypair(CRYPTO_ALG_LMS, &priv, &pub,
                                          &priv_blob, &pub_blob), 0);

    char path[] = "/tmp/lmsprivXXXXXX";
    int fd = mkstemp(path);
    assert_true(fd != -1);
    assert_int_equal(write(fd, priv_blob.key, priv_blob.key_len),
                     (ssize_t)priv_blob.key_len);
    close(fd);

    uint8_t *buf = NULL;
    size_t len = 0;
    assert_int_equal(read_file(path, &buf, &len), 0);
    assert_int_equal(len, priv_blob.key_len);

    size_t params_size = sizeof(pr->MBEDTLS_PRIVATE(params));
    uint32_t q_loaded = 0;
    memcpy(&q_loaded, buf + params_size, sizeof(q_loaded));
    assert_int_equal(q_loaded, after);

    free(buf);
    unlink(path);
    free(priv_blob.key);
    free(pub_blob.key);
    crypto_free_key(&priv);
    crypto_free_key(&pub);
}

/* Generate ML-DSA key pair and verify signing round-trip */
static void test_mldsa_sign_verify(void **state) {
    (void)state;
    crypto_key priv = {0}, pub = {0};
    assert_int_equal(crypto_keygen(CRYPTO_ALG_MLDSA87, &priv, &pub), 0);
    const uint8_t msg[] = "test message";
    uint8_t sig[PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES + 32];
    size_t sig_len = 0; /* crypto_sign should update this */
    assert_int_equal(crypto_sign(CRYPTO_ALG_MLDSA87, &priv,
                                 msg, sizeof(msg) - 1,
                                 sig, &sig_len), 0);
    assert_int_equal(sig_len, PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES);
    assert_true(sig_len < sizeof(sig));
    assert_int_equal(crypto_verify(CRYPTO_ALG_MLDSA87, &pub,
                                   msg, sizeof(msg) - 1,
                                   sig, sig_len), 0);
    crypto_free_key(&priv);
    crypto_free_key(&pub);
}

/* Verify combined RSA+LMS hybrid signature workflow */
static void test_rsa_lms_sign_verify(void **state) {
    (void)state;
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};
    assert_int_equal(hybrid_crypto_keygen(CRYPTO_ALG_RSA4096_LMS, privs, pubs), 0);
    const uint8_t msg[] = "test message";
    uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE];
    size_t sig_lens[2] = {0};
    assert_int_equal(hybrid_crypto_sign(CRYPTO_ALG_RSA4096_LMS, privs,
                                        msg, sizeof(msg) - 1,
                                        sigs, sig_lens), 0);
    size_t len1 = 0;
    size_t len2 = 0;
    crypto_alg first = 0;
    crypto_alg second = 0;
    assert_int_equal(crypto_hybrid_get_algs(CRYPTO_ALG_RSA4096_LMS,
                                            &first, &second), 0);
    assert_int_equal(first, CRYPTO_ALG_RSA4096);
    assert_int_equal(second, CRYPTO_ALG_LMS);
    assert_int_equal(crypto_hybrid_get_sig_lens(CRYPTO_ALG_RSA4096_LMS,
                                                &len1, &len2), 0);
    assert_int_equal(sig_lens[0], len1);
    assert_int_equal(sig_lens[1], len2);
    assert_int_equal(hybrid_crypto_verify(CRYPTO_ALG_RSA4096_LMS, pubs,
                                          msg, sizeof(msg) - 1,
                                          sigs, sig_lens), 0);
    crypto_free_key(&privs[0]);
    crypto_free_key(&privs[1]);
    crypto_free_key(&pubs[0]);
    crypto_free_key(&pubs[1]);
}

/* Verify combined RSA+ML-DSA hybrid signature workflow */
static void test_rsa_mldsa_sign_verify(void **state) {
    (void)state;
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};
    assert_int_equal(hybrid_crypto_keygen(CRYPTO_ALG_RSA4096_MLDSA87, privs, pubs), 0);
    const uint8_t msg[] = "test message";
    uint8_t sigs2[2][CRYPTO_MAX_SIG_SIZE];
    size_t sig_lens2[2] = {0};
    assert_int_equal(hybrid_crypto_sign(CRYPTO_ALG_RSA4096_MLDSA87, privs,
                                        msg, sizeof(msg) - 1,
                                        sigs2, sig_lens2), 0);
    size_t len1b = 0;
    size_t len2b = 0;
    crypto_alg firstb = 0;
    crypto_alg secondb = 0;
    assert_int_equal(crypto_hybrid_get_algs(CRYPTO_ALG_RSA4096_MLDSA87,
                                            &firstb, &secondb), 0);
    assert_int_equal(firstb, CRYPTO_ALG_RSA4096);
    assert_int_equal(secondb, CRYPTO_ALG_MLDSA87);
    assert_int_equal(crypto_hybrid_get_sig_lens(CRYPTO_ALG_RSA4096_MLDSA87,
                                                &len1b, &len2b), 0);
    assert_int_equal(sig_lens2[0], len1b);
    assert_int_equal(sig_lens2[1], len2b);
    assert_int_equal(hybrid_crypto_verify(CRYPTO_ALG_RSA4096_MLDSA87, pubs,
                                          msg, sizeof(msg) - 1,
                                          sigs2, sig_lens2), 0);
    crypto_free_key(&privs[0]);
    crypto_free_key(&privs[1]);
    crypto_free_key(&pubs[0]);
    crypto_free_key(&pubs[1]);
}

/* Verify combined LMS+ML-DSA hybrid signature workflow */
static void test_lms_mldsa_sign_verify(void **state) {
    (void)state;
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};
    assert_int_equal(hybrid_crypto_keygen(CRYPTO_ALG_LMS_MLDSA87, privs, pubs), 0);
    const uint8_t msg[] = "test message";
    uint8_t sigs3[2][CRYPTO_MAX_SIG_SIZE];
    size_t sig_lens3[2] = {0};
    assert_int_equal(hybrid_crypto_sign(CRYPTO_ALG_LMS_MLDSA87, privs,
                                        msg, sizeof(msg) - 1,
                                        sigs3, sig_lens3), 0);
    size_t len1c = 0;
    size_t len2c = 0;
    crypto_alg firstc = 0;
    crypto_alg secondc = 0;
    assert_int_equal(crypto_hybrid_get_algs(CRYPTO_ALG_LMS_MLDSA87,
                                            &firstc, &secondc), 0);
    assert_int_equal(firstc, CRYPTO_ALG_LMS);
    assert_int_equal(secondc, CRYPTO_ALG_MLDSA87);
    assert_int_equal(crypto_hybrid_get_sig_lens(CRYPTO_ALG_LMS_MLDSA87,
                                                &len1c, &len2c), 0);
    assert_int_equal(sig_lens3[0], len1c);
    assert_int_equal(sig_lens3[1], len2c);
    assert_int_equal(hybrid_crypto_verify(CRYPTO_ALG_LMS_MLDSA87, pubs,
                                          msg, sizeof(msg) - 1,
                                          sigs3, sig_lens3), 0);
    crypto_free_key(&privs[0]);
    crypto_free_key(&privs[1]);
    crypto_free_key(&pubs[0]);
    crypto_free_key(&pubs[1]);
}

/* Export raw public keys for a hybrid algorithm */
static void test_hybrid_export_raw_pk(void **state) {
    (void)state;
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};
    assert_int_equal(hybrid_crypto_keygen(CRYPTO_ALG_RSA4096_MLDSA87, privs, pubs), 0);

    uint8_t *out_pks[2] = {NULL, NULL};
    size_t out_lens[2] = {0, 0};
    assert_int_equal(hybrid_crypto_export_pk(CRYPTO_ALG_RSA4096_MLDSA87, pubs,
                                             out_pks, out_lens), 0);
    assert_non_null(out_pks[0]);
    assert_non_null(out_pks[1]);
    assert_int_equal(out_lens[0], CRYPTO_RSA_BITS / 8);
    assert_int_equal(out_lens[1], PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES);

    uint8_t *rsa_raw = NULL;
    size_t rsa_raw_len = 0;
    assert_int_equal(crypto_export_raw_pk(CRYPTO_ALG_RSA4096, &pubs[0],
                                          &rsa_raw, &rsa_raw_len), 0);
    assert_int_equal(rsa_raw_len, out_lens[0]);
    assert_memory_equal(rsa_raw, out_pks[0], out_lens[0]);

    uint8_t *mldsa_raw = NULL;
    size_t mldsa_raw_len = 0;
    assert_int_equal(crypto_export_raw_pk(CRYPTO_ALG_MLDSA87, &pubs[1],
                                          &mldsa_raw, &mldsa_raw_len), 0);
    assert_int_equal(mldsa_raw_len, out_lens[1]);
    assert_memory_equal(mldsa_raw, out_pks[1], out_lens[1]);

    free(rsa_raw);
    free(mldsa_raw);
    free(out_pks[0]);
    free(out_pks[1]);
    crypto_free_key(&privs[0]);
    crypto_free_key(&privs[1]);
    crypto_free_key(&pubs[0]);
    crypto_free_key(&pubs[1]);
}

/* Helper to validate serialization roundtrip for single algorithms */
static void test_single_alg_load_keypair_roundtrip(void **state, crypto_alg alg) {
    (void)state;
    crypto_key priv = {0}, pub = {0};
    assert_int_equal(crypto_keygen(alg, &priv, &pub), 0);
    crypto_key priv_blob = {0}, pub_blob = {0};
    assert_int_equal(crypto_export_keypair(alg, &priv, &pub,
                                          &priv_blob, &pub_blob), 0);
    char priv_path[] = "/tmp/privXXXXXX";
    write_key_to_temp_file(&priv_blob, priv_path);
    char pub_path[] = "/tmp/pubXXXXXX";
    write_key_to_temp_file(&pub_blob, pub_path);
    crypto_key priv2 = {0}, pub2 = {0};
    assert_int_equal(crypto_load_keypair(alg, priv_path, pub_path,
                                        &priv2, &pub2), 0);
    crypto_key priv_blob2 = {0}, pub_blob2 = {0};
    assert_int_equal(crypto_export_keypair(alg, &priv2, &pub2,
                                          &priv_blob2, &pub_blob2), 0);
    assert_int_equal(priv_blob2.key_len, priv_blob.key_len);
    assert_memory_equal(priv_blob2.key, priv_blob.key, priv_blob.key_len);
    assert_int_equal(pub_blob2.key_len, pub_blob.key_len);
    assert_memory_equal(pub_blob2.key, pub_blob.key, pub_blob.key_len);
    const uint8_t msg[] = "reload";
    uint8_t sig[CRYPTO_MAX_SIG_SIZE];
    size_t sig_len = sizeof(sig);
    assert_int_equal(crypto_sign(alg, &priv2, msg,
                                 sizeof(msg) - 1, sig, &sig_len), 0);
    switch (alg) {
    case CRYPTO_ALG_RSA4096:
        assert_int_equal(sig_len, CRYPTO_RSA_SIG_SIZE);
        break;
    case CRYPTO_ALG_LMS:
        assert_int_equal(sig_len,
                         MBEDTLS_LMS_SIG_LEN(MBEDTLS_LMS_SHA256_M32_H10,
                                             MBEDTLS_LMOTS_SHA256_N32_W8));
        break;
    case CRYPTO_ALG_MLDSA87:
        assert_int_equal(sig_len, PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES);
        break;
    default:
        break;
    }
    assert_int_equal(crypto_verify(alg, &pub2, msg,
                                   sizeof(msg) - 1, sig, sig_len), 0);
    unlink(priv_path);
    unlink(pub_path);
    crypto_free_key(&priv);
    crypto_free_key(&pub);
    crypto_free_key(&priv2);
    crypto_free_key(&pub2);
    free(priv_blob.key);
    free(pub_blob.key);
    free(priv_blob2.key);
    free(pub_blob2.key);
}

/* Helper to validate serialization roundtrip for hybrid algorithms */
static void test_hybrid_alg_load_keypair_roundtrip(void **state, hybrid_alg alg) {
    (void)state;
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};
    assert_int_equal(hybrid_crypto_keygen(alg, privs, pubs), 0);
    crypto_key priv_parts[2] = {{0}};
    crypto_key pub_parts[2] = {{0}};
    assert_int_equal(hybrid_crypto_export_keypairs(alg, privs, pubs,
                                                  priv_parts, pub_parts), 0);
    char priv0_path[] = "/tmp/priv0XXXXXX";
    write_key_to_temp_file(&priv_parts[0], priv0_path);
    char priv1_path[] = "/tmp/priv1XXXXXX";
    write_key_to_temp_file(&priv_parts[1], priv1_path);
    char pub0_path[] = "/tmp/pub0XXXXXX";
    write_key_to_temp_file(&pub_parts[0], pub0_path);
    char pub1_path[] = "/tmp/pub1XXXXXX";
    write_key_to_temp_file(&pub_parts[1], pub1_path);
    char priv_paths[2 * PATH_MAX];
    char pub_paths[2 * PATH_MAX];
    snprintf(priv_paths, sizeof(priv_paths), "%s,%s", priv0_path, priv1_path);
    snprintf(pub_paths, sizeof(pub_paths), "%s,%s", pub0_path, pub1_path);
    crypto_key privs2[2] = {{0}};
    crypto_key pubs2[2] = {{0}};
    assert_int_equal(hybrid_crypto_load_keypair(alg, priv_paths, pub_paths,
                                                privs2, pubs2), 0);
    crypto_key priv_parts2[2] = {{0}};
    crypto_key pub_parts2[2] = {{0}};
    assert_int_equal(hybrid_crypto_export_keypairs(alg, privs2, pubs2,
                                                  priv_parts2, pub_parts2), 0);
    for (int i = 0; i < 2; i++) {
        assert_int_equal(priv_parts2[i].key_len, priv_parts[i].key_len);
        assert_memory_equal(priv_parts2[i].key, priv_parts[i].key,
                            priv_parts[i].key_len);
        assert_int_equal(pub_parts2[i].key_len, pub_parts[i].key_len);
        assert_memory_equal(pub_parts2[i].key, pub_parts[i].key,
                            pub_parts[i].key_len);
    }
    const uint8_t msg[] = "roundtrip";
    uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE];
    size_t sig_lens[2] = {0};
    assert_int_equal(hybrid_crypto_sign(alg, privs2,
                                        msg, sizeof(msg) - 1,
                                        sigs, sig_lens), 0);
    assert_int_equal(hybrid_crypto_verify(alg, pubs2,
                                          msg, sizeof(msg) - 1,
                                          sigs, sig_lens), 0);
    unlink(priv0_path);
    unlink(priv1_path);
    unlink(pub0_path);
    unlink(pub1_path);
    for (int i = 0; i < 2; i++) {
        crypto_free_key(&privs[i]);
        crypto_free_key(&pubs[i]);
        crypto_free_key(&privs2[i]);
        crypto_free_key(&pubs2[i]);
        free(priv_parts[i].key);
        free(pub_parts[i].key);
        free(priv_parts2[i].key);
        free(pub_parts2[i].key);
    }
}

static void test_hybrid_load_keypair(void **state) {
    test_hybrid_alg_load_keypair_roundtrip(state, CRYPTO_ALG_RSA4096_MLDSA87);
}

static void test_rsa_load_keypair(void **state) {
    test_single_alg_load_keypair_roundtrip(state, CRYPTO_ALG_RSA4096);
}

static void test_lms_load_keypair(void **state) {
    test_single_alg_load_keypair_roundtrip(state, CRYPTO_ALG_LMS);
}

static void test_mldsa_load_keypair(void **state) {
    test_single_alg_load_keypair_roundtrip(state, CRYPTO_ALG_MLDSA87);
}

static void test_hybrid_load_keypair_rsa_lms(void **state) {
    test_hybrid_alg_load_keypair_roundtrip(state, CRYPTO_ALG_RSA4096_LMS);
}

static void test_hybrid_load_keypair_lms_mldsa(void **state) {
    test_hybrid_alg_load_keypair_roundtrip(state, CRYPTO_ALG_LMS_MLDSA87);
}


static void outputs_roundtrip(int alg) {
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};
    if (crypto_is_hybrid_alg(alg)) {
        assert_int_equal(hybrid_crypto_keygen((hybrid_alg)alg, privs, pubs), 0);
    } else {
        assert_int_equal(crypto_keygen((crypto_alg)alg, &privs[0], &pubs[0]), 0);
    }

    uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_128, NULL, NULL,
                                     aes_key, iv), 0);

    const uint8_t msg[] = "serialize test";
    uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE];
    size_t sig_lens[2] = {0};
    if (crypto_is_hybrid_alg(alg)) {
        assert_int_equal(hybrid_crypto_sign((hybrid_alg)alg, privs, msg,
                                           sizeof(msg) - 1, sigs, sig_lens), 0);
    } else {
        sig_lens[0] = CRYPTO_MAX_SIG_SIZE;
        assert_int_equal(crypto_sign((crypto_alg)alg, &privs[0], msg,
                                     sizeof(msg) - 1, sigs[0], &sig_lens[0]), 0);
    }

    size_t enc_len = sizeof(msg) - 1;
    size_t rem = enc_len % CRYPTO_AES_IV_SIZE;
    enc_len += CRYPTO_AES_IV_SIZE - rem;
    uint8_t *enc = malloc(enc_len);
    assert_non_null(enc);
    assert_int_equal(crypto_encrypt_aescbc(aes_key, CRYPTO_AES_KEY_BITS_128,
                                          iv, msg, sizeof(msg) - 1,
                                          enc, &enc_len), 0);

    char out_path[] = "/tmp/outXXXXXX";
    int fd = mkstemp(out_path);
    assert_true(fd != -1);
    close(fd);

    assert_int_equal(write_outputs(out_path, 1, alg, privs, pubs,
                                   aes_key, CRYPTO_AES_KEY_BITS_128 / 8,
                                   iv, sigs, sig_lens, enc, enc_len), 0);

    uint8_t *tmp = NULL;
    size_t len = 0;
    assert_int_equal(read_file(out_path, &tmp, &len), 0);
    assert_int_equal(len, enc_len);
    assert_memory_equal(tmp, enc, enc_len);
    free(tmp);

    char path[64];
    crypto_key priv_parts[2] = {{0}};
    crypto_key pub_parts[2] = {{0}};
    size_t key_count = 1;
    if (crypto_is_hybrid_alg(alg)) {
        assert_int_equal(hybrid_crypto_export_keypairs((hybrid_alg)alg, privs,
                                                      pubs, priv_parts,
                                                      pub_parts), 0);
        key_count = 2;
    } else {
        assert_int_equal(crypto_export_keypair((crypto_alg)alg, &privs[0], &pubs[0],
                                              &priv_parts[0], &pub_parts[0]), 0);
    }

    struct { char name[8]; const uint8_t *data; size_t len; } comps[9];
    size_t comp_idx = 0;
    strcpy(comps[comp_idx].name, "aes_iv");
    comps[comp_idx].data = iv;
    comps[comp_idx].len  = CRYPTO_AES_IV_SIZE;
    comp_idx++;
    strcpy(comps[comp_idx].name, "aes");
    comps[comp_idx].data = aes_key;
    comps[comp_idx].len  = CRYPTO_AES_KEY_BITS_128 / 8;
    comp_idx++;
    for (size_t i = 0; i < key_count; i++) {
        sprintf(comps[comp_idx].name, "sk%zu", i);
        comps[comp_idx].data = priv_parts[i].key;
        comps[comp_idx].len  = priv_parts[i].key_len;
        comp_idx++;
    }
    for (size_t i = 0; i < key_count; i++) {
        sprintf(comps[comp_idx].name, "pk%zu", i);
        comps[comp_idx].data = pub_parts[i].key;
        comps[comp_idx].len  = pub_parts[i].key_len;
        comp_idx++;
    }
    if (key_count == 2) {
        sprintf(comps[comp_idx].name, "sig0");
        comps[comp_idx].data = sigs[0];
        comps[comp_idx].len  = sig_lens[0];
        comp_idx++;
        sprintf(comps[comp_idx].name, "sig1");
        comps[comp_idx].data = sigs[1];
        comps[comp_idx].len  = sig_lens[1];
        comp_idx++;
    } else {
        strcpy(comps[comp_idx].name, "sig0");
        comps[comp_idx].data = sigs[0];
        comps[comp_idx].len  = sig_lens[0];
        comp_idx++;
    }

    for (size_t i = 0; i < comp_idx; i++) {
        sprintf(path, "%s.bin", comps[i].name);
        tmp = NULL;
        len = 0;
        assert_int_equal(read_file(path, &tmp, &len), 0);
        assert_int_equal(len, comps[i].len);
        assert_memory_equal(tmp, comps[i].data, comps[i].len);
        free(tmp);
        unlink(path);
        sprintf(path, "%s.hex", comps[i].name);
        unlink(path);
    }

    char *hex_path = malloc(strlen(out_path) + 5);
    assert_non_null(hex_path);
    sprintf(hex_path, "%s.hex", out_path);
    unlink(out_path);
    unlink(hex_path);
    free(hex_path);

    /* sigs allocated on stack */
    free(enc);
    for (size_t i = 0; i < key_count; i++) {
        free(priv_parts[i].key);
        free(pub_parts[i].key);
    }
    crypto_free_key(&privs[0]);
    crypto_free_key(&privs[1]);
    crypto_free_key(&pubs[0]);
    crypto_free_key(&pubs[1]);
}

static void test_rsa_outputs(void **state) {
    (void)state;
    outputs_roundtrip(CRYPTO_ALG_RSA4096);
}

static void test_lms_outputs(void **state) {
    (void)state;
    outputs_roundtrip(CRYPTO_ALG_LMS);
}

static void test_mldsa_outputs(void **state) {
    (void)state;
    outputs_roundtrip(CRYPTO_ALG_MLDSA87);
}

static void test_rsa_lms_outputs(void **state) {
    (void)state;
    outputs_roundtrip(CRYPTO_ALG_RSA4096_LMS);
}

static void test_rsa_mldsa_outputs(void **state) {
    (void)state;
    outputs_roundtrip(CRYPTO_ALG_RSA4096_MLDSA87);
}

static void test_lms_mldsa_outputs(void **state) {
    (void)state;
    outputs_roundtrip(CRYPTO_ALG_LMS_MLDSA87);
}

/* When keys are provided, only the signature should be output */
static void test_outputs_signature_only(void **state) {
    (void)state;
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};
    assert_int_equal(crypto_keygen(CRYPTO_ALG_RSA4096, &privs[0], &pubs[0]), 0);

    uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_128, NULL, NULL,
                                     aes_key, iv), 0);

    const uint8_t msg[] = "sig only";
    uint8_t sigs[2][CRYPTO_MAX_SIG_SIZE];
    size_t sig_lens[2] = {0};
    sig_lens[0] = CRYPTO_MAX_SIG_SIZE;
    assert_int_equal(crypto_sign(CRYPTO_ALG_RSA4096, &privs[0],
                                 msg, sizeof(msg) - 1,
                                 sigs[0], &sig_lens[0]), 0);

    size_t enc_len = sizeof(msg) - 1;
    size_t rem = enc_len % CRYPTO_AES_IV_SIZE;
    enc_len += CRYPTO_AES_IV_SIZE - rem;
    uint8_t *enc = malloc(enc_len);
    assert_non_null(enc);
    assert_int_equal(crypto_encrypt_aescbc(aes_key, CRYPTO_AES_KEY_BITS_128,
                                          iv, msg, sizeof(msg) - 1,
                                          enc, &enc_len), 0);

    char out_path[] = "/tmp/outXXXXXX";
    int fd = mkstemp(out_path);
    assert_true(fd != -1);
    close(fd);

    assert_int_equal(write_outputs(out_path, 0, CRYPTO_ALG_RSA4096, privs, pubs,
                                   aes_key, CRYPTO_AES_KEY_BITS_128 / 8,
                                   iv, sigs, sig_lens, enc, enc_len), 0);

    uint8_t *tmp = NULL;
    size_t len = 0;
    assert_int_equal(read_file("sig0.bin", &tmp, &len), 0);
    assert_int_equal(len, sig_lens[0]);
    assert_memory_equal(tmp, sigs[0], sig_lens[0]);
    free(tmp);

    assert_int_equal(access("aes.bin", F_OK), -1);
    assert_int_equal(access("aes_iv.bin", F_OK), -1);
    assert_int_equal(access("sk0.bin", F_OK), -1);
    assert_int_equal(access("pk0.bin", F_OK), -1);

    unlink("sig0.bin");
    unlink("sig0.hex");
    char *hex_path = malloc(strlen(out_path) + 5);
    assert_non_null(hex_path);
    sprintf(hex_path, "%s.hex", out_path);
    unlink(out_path);
    unlink(hex_path);
    free(hex_path);
    free(enc);
    crypto_free_key(&privs[0]);
    crypto_free_key(&pubs[0]);
}

/* Reject invalid parameters to AES initialisation routine */
static void test_crypto_init_aes_invalid(void **state) {
    (void)state;
    uint8_t key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(100, NULL, NULL, key, iv), -1);
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_128, NULL, NULL, NULL, iv), -1);
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_128, NULL, NULL, key, NULL), -1);
}

/* Reject invalid arguments to SHA-384 helper */
static void test_crypto_sha384_invalid(void **state) {
    (void)state;
    uint8_t out[CRYPTO_SHA384_DIGEST_SIZE];
    assert_int_equal(crypto_sha384(NULL, 0, out), -1);
    assert_int_equal(crypto_sha384((const uint8_t *)"a", 1, NULL), -1);
}

/* Reject invalid parameters to AES-CBC encryption */
static void test_crypto_encrypt_invalid(void **state) {
    (void)state;
    uint8_t key[CRYPTO_AES_IV_SIZE] = {0};
    uint8_t iv[CRYPTO_AES_IV_SIZE] = {0};
    uint8_t in[CRYPTO_AES_IV_SIZE] = {0};
    uint8_t out[CRYPTO_AES_IV_SIZE];
    size_t out_len = 0;
    assert_int_equal(crypto_encrypt_aescbc(NULL, CRYPTO_AES_KEY_BITS_128, iv,
                                           in, CRYPTO_AES_IV_SIZE, out,
                                           &out_len), -1);
    assert_int_equal(crypto_encrypt_aescbc(key, CRYPTO_AES_KEY_BITS_128, NULL,
                                           in, CRYPTO_AES_IV_SIZE, out,
                                           &out_len), -1);
    assert_int_equal(crypto_encrypt_aescbc(key, CRYPTO_AES_KEY_BITS_128, iv,
                                           NULL, CRYPTO_AES_IV_SIZE, out,
                                           &out_len), -1);
    assert_int_equal(crypto_encrypt_aescbc(key, CRYPTO_AES_KEY_BITS_128, iv,
                                           in, CRYPTO_AES_IV_SIZE, NULL,
                                           &out_len), -1);
    assert_int_equal(crypto_encrypt_aescbc(key, CRYPTO_AES_KEY_BITS_128, iv,
                                           in, CRYPTO_AES_IV_SIZE, out,
                                           NULL), -1);
}

/* Reject improper arguments to signing function */
static void test_crypto_sign_invalid(void **state) {
    (void)state;
    crypto_key priv = {0};
    uint8_t sig[16];
    size_t sig_len = sizeof(sig);
    assert_int_equal(crypto_sign(CRYPTO_ALG_RSA4096, NULL, (uint8_t *)"a", 1, sig, &sig_len), -1);
    assert_int_equal(crypto_sign(CRYPTO_ALG_RSA4096, &priv, NULL, 1, sig, &sig_len), -1);
    assert_int_equal(crypto_sign(CRYPTO_ALG_RSA4096, &priv, (uint8_t *)"a", 1, NULL, &sig_len), -1);
    assert_int_equal(crypto_sign(CRYPTO_ALG_RSA4096, &priv, (uint8_t *)"a", 1, sig, NULL), -1);
}

/* Reject improper arguments to signature verification function */
static void test_crypto_verify_invalid(void **state) {
    (void)state;
    crypto_key pub = {0};
    uint8_t sig[16];
    assert_int_equal(crypto_verify(CRYPTO_ALG_RSA4096, NULL, (uint8_t *)"a", 1, sig, 16), -1);
    assert_int_equal(crypto_verify(CRYPTO_ALG_RSA4096, &pub, NULL, 1, sig, 16), -1);
    assert_int_equal(crypto_verify(CRYPTO_ALG_RSA4096, &pub, (uint8_t *)"a", 1, NULL, 16), -1);
}

const struct CMUnitTest crypto_tests[] = {
    cmocka_unit_test(test_sha384),
    cmocka_unit_test(test_aes_cbc_empty),
    cmocka_unit_test(test_aes_cbc),
    cmocka_unit_test(test_aes_cbc_unaligned),
    cmocka_unit_test_setup_teardown(test_aes_serialize_128, aes_setup, aes_teardown),
    cmocka_unit_test_setup_teardown(test_aes_serialize_192, aes_setup, aes_teardown),
    cmocka_unit_test_setup_teardown(test_aes_serialize_256, aes_setup, aes_teardown),
    cmocka_unit_test(test_rsa_sign_verify),
    cmocka_unit_test(test_lms_sign_verify),
    cmocka_unit_test(test_lms_q_next_usable_key),
    cmocka_unit_test(test_mldsa_sign_verify),
    cmocka_unit_test(test_rsa_lms_sign_verify),
    cmocka_unit_test(test_rsa_mldsa_sign_verify),
    cmocka_unit_test(test_lms_mldsa_sign_verify),
    cmocka_unit_test(test_hybrid_export_raw_pk),
    cmocka_unit_test(test_rsa_load_keypair),
    cmocka_unit_test(test_lms_load_keypair),
    cmocka_unit_test(test_mldsa_load_keypair),
    cmocka_unit_test(test_hybrid_load_keypair),
    cmocka_unit_test(test_hybrid_load_keypair_rsa_lms),
    cmocka_unit_test(test_hybrid_load_keypair_lms_mldsa),
    cmocka_unit_test(test_rsa_outputs),
    cmocka_unit_test(test_lms_outputs),
    cmocka_unit_test(test_mldsa_outputs),
    cmocka_unit_test(test_rsa_lms_outputs),
    cmocka_unit_test(test_rsa_mldsa_outputs),
    cmocka_unit_test(test_lms_mldsa_outputs),
    cmocka_unit_test(test_outputs_signature_only),
    cmocka_unit_test(test_crypto_init_aes_invalid),
    cmocka_unit_test(test_crypto_sha384_invalid),
    cmocka_unit_test(test_crypto_encrypt_invalid),
    cmocka_unit_test(test_crypto_sign_invalid),
    cmocka_unit_test(test_crypto_verify_invalid),
};

const size_t crypto_tests_count =
    sizeof(crypto_tests) / sizeof(crypto_tests[0]);
