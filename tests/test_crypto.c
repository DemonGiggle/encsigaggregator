#include "crypto.h"
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <mbedtls/lms.h>
#include "api.h"

static void test_sha384(void **state) {
    (void)state;
    uint8_t out[48];
    assert_int_equal(crypto_sha384((const uint8_t *)"abc", 3, out), 0);
    const uint8_t expected[48] = {
        0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,
        0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
        0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,
        0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
        0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,
        0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
    };
    assert_memory_equal(out, expected, 48);
}

static void test_aes_cbc(void **state) {
    (void)state;
    uint8_t key[32];
    uint8_t iv[16];
    assert_int_equal(crypto_init_aes(256, NULL, NULL, key, iv), 0);

    const uint8_t plaintext[32] =
        "0123456789abcdef0123456789abcdef";
    uint8_t enc[32];
    uint8_t dec[32];
    assert_int_equal(crypto_encrypt_aescbc(key, 256, iv, plaintext, 32, enc), 0);
    assert_int_equal(crypto_decrypt_aescbc(key, 256, iv, enc, 32, dec), 0);
    assert_memory_equal(dec, plaintext, 32);
}

static void test_rsa_sign_verify(void **state) {
    (void)state;
    crypto_key priv = {0}, pub = {0};
    assert_int_equal(crypto_keygen(CRYPTO_ALG_RSA4096, &priv, &pub), 0);
    const uint8_t msg[] = "test message";
    uint8_t sig[1024];
    size_t sig_len = 0; /* crypto_sign should update this */
    assert_int_equal(crypto_sign(CRYPTO_ALG_RSA4096, &priv,
                                 msg, sizeof(msg) - 1,
                                 sig, &sig_len), 0);
    assert_int_equal(sig_len, 512);
    assert_true(sig_len < sizeof(sig));
    assert_int_equal(crypto_verify(CRYPTO_ALG_RSA4096, &pub,
                                   msg, sizeof(msg) - 1,
                                   sig, sig_len), 0);
    crypto_free_key(&priv);
    pub.key = NULL;
    crypto_free_key(&pub);
}

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
    pub.key = NULL;
    crypto_free_key(&pub);
}

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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sha384),
        cmocka_unit_test(test_aes_cbc),
        cmocka_unit_test(test_rsa_sign_verify),
        cmocka_unit_test(test_lms_sign_verify),
        cmocka_unit_test(test_mldsa_sign_verify),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
