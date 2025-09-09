#define _POSIX_C_SOURCE 200809L
#include "cliopts.h"
#include "crypto.h"
#include "util.h"
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <limits.h>

static void cleanup_tool_outputs(void) {
    const char *paths[] = {
        "sk0.bin", "sk0.hex", "pk0.bin", "pk0.hex",
        "aes.bin", "aes.hex", "aes_iv.bin", "aes_iv.hex",
        "sig0.bin", "sig0.hex"
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        unlink(paths[i]);
}

/* Ensure parser rejects an unsupported algorithm argument. */
void test_cli_invalid_alg(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "foo", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(7, argv, &opts), -1);
}

/* Ensure parser rejects an unsupported AES key size. */
void test_cli_invalid_bits(void **state) {
    (void)state;
    char *argv[] = {"prog", "-b", "42", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(7, argv, &opts), -1);
}

/* Verify failure when required input file argument is missing. */
void test_cli_missing_infile(void **state) {
    (void)state;
    char *argv[] = {"prog", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(3, argv, &opts), -1);
}

/* Verify failure when required output file argument is missing. */
void test_cli_missing_outfile(void **state) {
    (void)state;
    char *argv[] = {"prog", "-i", "in", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(3, argv, &opts), -1);
}

/* Parse minimal valid invocation and verify default options. */
void test_cli_valid_minimal(void **state) {
    (void)state;
    char *argv[] = {"prog", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(5, argv, &opts), 0);
    assert_int_equal(opts.alg, CRYPTO_ALG_RSA4096);
    assert_int_equal(opts.aes_bits, CRYPTO_AES_KEY_BITS_256);
    assert_string_equal(opts.infile, "in");
    assert_string_equal(opts.outfile, "out");
}

/* Accept RSA+LMS algorithm selection. */
void test_cli_rsa_lms(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "rsa-lms", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(7, argv, &opts), 0);
    assert_int_equal(opts.alg, CRYPTO_ALG_RSA4096_LMS);
}

/* Accept RSA+ML-DSA algorithm selection. */
void test_cli_rsa_mldsa(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "rsa-mldsa87", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(7, argv, &opts), 0);
    assert_int_equal(opts.alg, CRYPTO_ALG_RSA4096_MLDSA87);
}

/* Accept LMS+ML-DSA algorithm selection. */
void test_cli_lms_mldsa(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "lms-mldsa87", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(7, argv, &opts), 0);
    assert_int_equal(opts.alg, CRYPTO_ALG_LMS_MLDSA87);
}

/* Generate key pair when only AES material is provided. */
void test_tool_gen_keypair_when_aes_provided(void **state) {
    (void)state;
    uint8_t key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    assert_int_equal(crypto_init_aes(CRYPTO_AES_KEY_BITS_256, NULL, NULL, key, iv), 0);

    char key_path[] = "/tmp/keyXXXXXX";
    int kfd = mkstemp(key_path);
    assert_true(kfd != -1);
    FILE *f = fdopen(kfd, "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(key, 1, CRYPTO_AES_KEY_BITS_256 / 8, f), CRYPTO_AES_KEY_BITS_256 / 8);
    fclose(f);

    char iv_path[] = "/tmp/ivXXXXXX";
    int ifd = mkstemp(iv_path);
    assert_true(ifd != -1);
    f = fdopen(ifd, "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(iv, 1, CRYPTO_AES_IV_SIZE, f), CRYPTO_AES_IV_SIZE);
    fclose(f);

    char in_path[] = "/tmp/inXXXXXX";
    int ifd2 = mkstemp(in_path);
    assert_true(ifd2 != -1);
    f = fdopen(ifd2, "wb");
    const char *msg = "data";
    assert_int_equal(fwrite(msg, 1, strlen(msg), f), (int)strlen(msg));
    fclose(f);

    char out_path[] = "/tmp/outXXXXXX";
    int ofd = mkstemp(out_path);
    assert_true(ofd != -1);
    close(ofd);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), "./encsigtool -i %s -o %s --aes-key-path %s --aes-iv %s",
             in_path, out_path, key_path, iv_path);
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    assert_int_equal(access("sk0.bin", F_OK), 0);
    assert_int_equal(access("pk0.bin", F_OK), 0);
    cleanup_tool_outputs();
    unlink(out_path);
    char hex_path[PATH_MAX];
    snprintf(hex_path, sizeof(hex_path), "%s.hex", out_path);
    unlink(hex_path);
    unlink(in_path);
    unlink(key_path);
    unlink(iv_path);
}

/* Generate AES material when only key pair is provided. */
void test_tool_gen_aes_when_keys_provided(void **state) {
    (void)state;
    crypto_key priv = {0}, pub = {0};
    assert_int_equal(crypto_keygen(CRYPTO_ALG_RSA4096, &priv, &pub), 0);
    crypto_key priv_blob = {0}, pub_blob = {0};
    assert_int_equal(crypto_export_keypair(CRYPTO_ALG_RSA4096, &priv, &pub, &priv_blob, &pub_blob), 0);

    char sk_path[] = "/tmp/skXXXXXX";
    int skfd = mkstemp(sk_path);
    assert_true(skfd != -1);
    FILE *f = fdopen(skfd, "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(priv_blob.key, 1, priv_blob.key_len, f), priv_blob.key_len);
    fclose(f);

    char pk_path[] = "/tmp/pkXXXXXX";
    int pkfd = mkstemp(pk_path);
    assert_true(pkfd != -1);
    f = fdopen(pkfd, "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(pub_blob.key, 1, pub_blob.key_len, f), pub_blob.key_len);
    fclose(f);

    char in_path[] = "/tmp/inXXXXXX";
    int ifd = mkstemp(in_path);
    assert_true(ifd != -1);
    f = fdopen(ifd, "wb");
    const char *msg = "data";
    assert_int_equal(fwrite(msg, 1, strlen(msg), f), (int)strlen(msg));
    fclose(f);

    char out_path[] = "/tmp/outXXXXXX";
    int ofd = mkstemp(out_path);
    assert_true(ofd != -1);
    close(ofd);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), "./encsigtool -i %s -o %s --pk-path %s --sk-path %s",
             in_path, out_path, pk_path, sk_path);
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    assert_int_equal(access("aes.bin", F_OK), 0);
    assert_int_equal(access("aes_iv.bin", F_OK), 0);
    cleanup_tool_outputs();
    unlink(out_path);
    char hex_path2[PATH_MAX];
    snprintf(hex_path2, sizeof(hex_path2), "%s.hex", out_path);
    unlink(hex_path2);
    unlink(in_path);
    unlink(pk_path);
    unlink(sk_path);
    free(priv_blob.key);
    free(pub_blob.key);
    crypto_free_key(&priv);
    crypto_free_key(&pub);
}


const struct CMUnitTest cli_tests[] = {
    cmocka_unit_test(test_cli_invalid_alg),
    cmocka_unit_test(test_cli_invalid_bits),
    cmocka_unit_test(test_cli_missing_infile),
    cmocka_unit_test(test_cli_missing_outfile),
    cmocka_unit_test(test_cli_valid_minimal),
    cmocka_unit_test(test_cli_rsa_lms),
    cmocka_unit_test(test_cli_rsa_mldsa),
    cmocka_unit_test(test_cli_lms_mldsa),
    cmocka_unit_test(test_tool_gen_keypair_when_aes_provided),
    cmocka_unit_test(test_tool_gen_aes_when_keys_provided),
};

const size_t cli_tests_count = sizeof(cli_tests) / sizeof(cli_tests[0]);


