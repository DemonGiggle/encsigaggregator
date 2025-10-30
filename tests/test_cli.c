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
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>

#ifndef TOOL_NAME
#error "TOOL_NAME must be defined"
#endif

#define TOOL_PATH "./" TOOL_NAME

static void cleanup_tool_outputs(void) {
    const char *paths[] = {
        "sk0.bin",  "sk0.hex",  "pk0.bin",  "pk0.hex",
        "sk1.bin",  "sk1.hex",  "pk1.bin",  "pk1.hex",
        "aes.bin",  "aes.hex",  "aes_iv.bin", "aes_iv.hex",
        "sig0.bin", "sig0.hex", "sig1.bin", "sig1.hex"
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

/* Verify failure when neither -o nor key-generation selectors are supplied. */
void test_cli_requires_outfile_or_keygen(void **state) {
    (void)state;
    char *argv[] = {"prog", "-i", "in", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(3, argv, &opts), -1);
}

/* Accept key-generation mode when only an algorithm is requested. */
void test_cli_keygen_rsa_only(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "rsa", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(3, argv, &opts), 0);
    assert_true(opts.keygen_mode);
    assert_int_equal(opts.alg, CRYPTO_ALG_RSA4096);
    assert_int_equal(opts.aes_bits, CRYPTO_AES_KEY_BITS_NONE);
}

/* Accept key-generation mode when only AES material is requested. */
void test_cli_keygen_aes_only(void **state) {
    (void)state;
    char *argv[] = {"prog", "-b", "256", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(3, argv, &opts), 0);
    assert_true(opts.keygen_mode);
    assert_int_equal(opts.alg, CRYPTO_ALG_NONE);
    assert_int_equal(opts.aes_bits, CRYPTO_AES_KEY_BITS_256);
}

/* Reject key-generation mode when existing paths are provided. */
void test_cli_keygen_reject_paths(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "rsa", "--pk-path", "pk0.bin", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(5, argv, &opts), -1);
}

/* Reject encryption mode when algorithm or AES bits are omitted. */
void test_cli_requires_selections_for_encrypt(void **state) {
    (void)state;
    char *argv[] = {"prog", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(5, argv, &opts), -1);
}

/* Parse verification options and ensure output path is optional. */
void test_cli_verify_parse(void **state) {
    (void)state;
    char *argv[] = {"prog", "--verify-sig", "--sig-path", "sig0.bin", "-a", "rsa", "-i", "in", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(8, argv, &opts), 0);
    assert_int_equal(opts.verify_sig, 1);
    assert_string_equal(opts.sig_path, "sig0.bin");
    assert_string_equal(opts.infile, "in");
    assert_null(opts.outfile);
}

/* Ensure signature verification requires an explicit algorithm. */
void test_cli_verify_sig_requires_alg(void **state) {
    (void)state;
    char *argv[] = {"prog", "--verify-sig", "--sig-path", "sig0.bin", "-i", "in", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(6, argv, &opts), -1);
}

/* Ensure decryption verification requires an explicit AES key size. */
void test_cli_verify_dec_requires_bits(void **state) {
    (void)state;
    char *argv[] = {"prog", "--verify-dec", "--expected-file", "exp", "--aes-key-path", "k", "--aes-iv", "iv", "-i", "in", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(10, argv, &opts), -1);
}

/* Accept RSA+LMS algorithm selection. */
void test_cli_rsa_lms(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "rsa-lms", "-b", "256", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(9, argv, &opts), 0);
    assert_int_equal(opts.alg, CRYPTO_ALG_RSA4096_LMS);
}

/* Accept RSA+ML-DSA algorithm selection. */
void test_cli_rsa_mldsa(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "rsa-mldsa87", "-b", "256", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(9, argv, &opts), 0);
    assert_int_equal(opts.alg, CRYPTO_ALG_RSA4096_MLDSA87);
}

/* Accept LMS+ML-DSA algorithm selection. */
void test_cli_lms_mldsa(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "lms-mldsa87", "-b", "256", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(9, argv, &opts), 0);
    assert_int_equal(opts.alg, CRYPTO_ALG_LMS_MLDSA87);
}

/* Generate signing keys through the CLI without producing ciphertext. */
void test_tool_keygen_rsa_outputs(void **state) {
    (void)state;
    cleanup_tool_outputs();

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa");
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    struct stat st;
    assert_int_equal(stat("sk0.bin", &st), 0);
    assert_true(st.st_size > 0);
    assert_int_equal(stat("pk0.bin", &st), 0);
    assert_true(st.st_size > 0);

    assert_int_equal(access("aes.bin", F_OK), -1);
    assert_int_equal(access("sig0.bin", F_OK), -1);

    cleanup_tool_outputs();
}

/* Generate AES material through the CLI without producing key pairs. */
void test_tool_keygen_aes_outputs(void **state) {
    (void)state;
    cleanup_tool_outputs();

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -b 192");
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    struct stat st;
    assert_int_equal(stat("aes.bin", &st), 0);
    assert_int_equal((size_t)st.st_size, CRYPTO_AES_KEY_BITS_192 / 8);
    assert_int_equal(stat("aes_iv.bin", &st), 0);
    assert_int_equal((size_t)st.st_size, CRYPTO_AES_IV_SIZE);

    assert_int_equal(access("sk0.bin", F_OK), -1);
    assert_int_equal(access("pk0.bin", F_OK), -1);

    cleanup_tool_outputs();
}

/* Refuse to overwrite ciphertext when the requested output path already exists. */
void test_tool_fails_when_ciphertext_exists(void **state) {
    (void)state;
    cleanup_tool_outputs();

    char in_path[] = "/tmp/inXXXXXX";
    int ifd = mkstemp(in_path);
    assert_true(ifd != -1);
    FILE *f = fdopen(ifd, "wb");
    assert_non_null(f);
    const char *msg = "data";
    assert_int_equal(fwrite(msg, 1, strlen(msg), f), (int)strlen(msg));
    fclose(f);

    char out_path[] = "/tmp/outXXXXXX";
    int ofd = mkstemp(out_path);
    assert_true(ofd != -1);
    close(ofd);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa -b 256 -i %s -o %s", in_path, out_path);
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 1);

    struct stat st;
    assert_int_equal(stat(out_path, &st), 0);
    assert_int_equal(st.st_size, 0);

    char hex_path[PATH_MAX];
    snprintf(hex_path, sizeof(hex_path), "%s.hex", out_path);
    assert_int_equal(access(hex_path, F_OK), -1);

    cleanup_tool_outputs();
    unlink(out_path);
    unlink(hex_path);
    unlink(in_path);
}

/* Refuse to overwrite an existing signature component before signing begins. */
void test_tool_fails_when_component_exists(void **state) {
    (void)state;
    cleanup_tool_outputs();

    char in_path[] = "/tmp/inXXXXXX";
    int ifd = mkstemp(in_path);
    assert_true(ifd != -1);
    FILE *f = fdopen(ifd, "wb");
    assert_non_null(f);
    const char *msg = "data";
    assert_int_equal(fwrite(msg, 1, strlen(msg), f), (int)strlen(msg));
    fclose(f);

    char out_path[] = "/tmp/outXXXXXX";
    int ofd = mkstemp(out_path);
    assert_true(ofd != -1);
    close(ofd);
    unlink(out_path);

    uint8_t existing[4] = {0xaa, 0xbb, 0xcc, 0xdd};
    f = fopen("sig0.bin", "wb");
    assert_non_null(f);
    assert_int_equal(fwrite(existing, 1, sizeof(existing), f), (int)sizeof(existing));
    fclose(f);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa -b 256 -i %s -o %s", in_path, out_path);
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 1);

    f = fopen("sig0.bin", "rb");
    assert_non_null(f);
    uint8_t buffer[sizeof(existing)] = {0};
    assert_int_equal(fread(buffer, 1, sizeof(buffer), f), (int)sizeof(buffer));
    fclose(f);
    assert_memory_equal(buffer, existing, sizeof(existing));

    assert_int_equal(access(out_path, F_OK), -1);
    char hex_path[PATH_MAX];
    snprintf(hex_path, sizeof(hex_path), "%s.hex", out_path);
    assert_int_equal(access(hex_path, F_OK), -1);
    assert_int_equal(access("sig0.hex", F_OK), -1);

    cleanup_tool_outputs();
    unlink(out_path);
    unlink(hex_path);
    unlink(in_path);
}

/* Generate key pair when only AES material is provided. */
void test_tool_gen_keypair_when_aes_provided(void **state) {
    (void)state;
    cleanup_tool_outputs();
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
    unlink(out_path);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa -b 256 -i %s -o %s --aes-key-path %s --aes-iv %s",
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
    cleanup_tool_outputs();
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
    unlink(out_path);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa -b 256 -i %s -o %s --pk-path %s --sk-path %s",
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

/* Run signing followed by verification through the CLI. */
void test_tool_verify_signature(void **state) {
    (void)state;
    cleanup_tool_outputs();

    char in_path[] = "/tmp/inXXXXXX";
    int ifd = mkstemp(in_path);
    assert_true(ifd != -1);
    FILE *f = fdopen(ifd, "wb");
    assert_non_null(f);
    const char *msg = "verify";
    assert_int_equal(fwrite(msg, 1, strlen(msg), f), (int)strlen(msg));
    fclose(f);

    char out_path[] = "/tmp/outXXXXXX";
    int ofd = mkstemp(out_path);
    assert_true(ofd != -1);
    close(ofd);
    unlink(out_path);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa -b 256 -i %s -o %s", in_path, out_path);
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    assert_int_equal(access("sig0.bin", F_OK), 0);
    assert_int_equal(access("pk0.bin", F_OK), 0);
    assert_int_equal(access("sk0.bin", F_OK), 0);

    char verify_cmd[PATH_MAX * 2];
    snprintf(verify_cmd, sizeof(verify_cmd),
             TOOL_PATH " --verify-sig --sig-path sig0.bin --pk-path pk0.bin --sk-path sk0.bin -a rsa -i %s",
             in_path);
    ret = system(verify_cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    cleanup_tool_outputs();
    unlink(out_path);
    char out_hex[PATH_MAX];
    snprintf(out_hex, sizeof(out_hex), "%s.hex", out_path);
    unlink(out_hex);
    unlink(in_path);
}


/* Run decryption verification through the CLI and confirm success. */
void test_tool_verify_decryption_success(void **state) {
    (void)state;
    cleanup_tool_outputs();

    char in_path[] = "/tmp/inXXXXXX";
    int ifd = mkstemp(in_path);
    assert_true(ifd != -1);
    FILE *f = fdopen(ifd, "wb");
    assert_non_null(f);
    const char *msg = "decrypt";
    assert_int_equal(fwrite(msg, 1, strlen(msg), f), (int)strlen(msg));
    fclose(f);

    char out_path[] = "/tmp/outXXXXXX";
    int ofd = mkstemp(out_path);
    assert_true(ofd != -1);
    close(ofd);
    unlink(out_path);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa -b 256 -i %s -o %s", in_path, out_path);
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    char dec_path[] = "/tmp/decXXXXXX";
    int dfd = mkstemp(dec_path);
    assert_true(dfd != -1);
    close(dfd);
    unlink(dec_path);

    char verify_cmd[PATH_MAX * 2];
    snprintf(verify_cmd, sizeof(verify_cmd),
             TOOL_PATH " --verify-dec --expected-file %s --aes-key-path aes.bin --aes-iv aes_iv.bin -b 256 -i %s -o %s",
             in_path, out_path, dec_path);
    ret = system(verify_cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    uint8_t *dec_buf = NULL;
    size_t dec_len = 0;
    assert_int_equal(read_file(dec_path, &dec_buf, &dec_len), 0);
    assert_int_equal(dec_len, strlen(msg));
    assert_memory_equal(dec_buf, msg, strlen(msg));
    free(dec_buf);

    cleanup_tool_outputs();
    unlink(out_path);
    char out_hex[PATH_MAX];
    snprintf(out_hex, sizeof(out_hex), "%s.hex", out_path);
    unlink(out_hex);
    unlink(dec_path);
    unlink(in_path);
}

/* Run decryption verification with mismatched plaintext and expect failure. */
void test_tool_verify_decryption_failure(void **state) {
    (void)state;
    cleanup_tool_outputs();

    char in_path[] = "/tmp/inXXXXXX";
    int ifd = mkstemp(in_path);
    assert_true(ifd != -1);
    FILE *f = fdopen(ifd, "wb");
    assert_non_null(f);
    const char *msg = "original";
    assert_int_equal(fwrite(msg, 1, strlen(msg), f), (int)strlen(msg));
    fclose(f);

    char out_path[] = "/tmp/outXXXXXX";
    int ofd = mkstemp(out_path);
    assert_true(ofd != -1);
    close(ofd);
    unlink(out_path);

    char cmd[PATH_MAX];
    snprintf(cmd, sizeof(cmd), TOOL_PATH " -a rsa -b 256 -i %s -o %s", in_path, out_path);
    int ret = system(cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 0);

    char wrong_path[] = "/tmp/wrongXXXXXX";
    int wfd = mkstemp(wrong_path);
    assert_true(wfd != -1);
    f = fdopen(wfd, "wb");
    assert_non_null(f);
    const char *wrong = "tampered";
    assert_int_equal(fwrite(wrong, 1, strlen(wrong), f), (int)strlen(wrong));
    fclose(f);

    char verify_cmd[PATH_MAX * 2];
    snprintf(verify_cmd, sizeof(verify_cmd),
             TOOL_PATH " --verify-dec --expected-file %s --aes-key-path aes.bin --aes-iv aes_iv.bin -b 256 -i %s",
             wrong_path, out_path);
    ret = system(verify_cmd);
    assert_true(ret != -1);
    assert_true(WIFEXITED(ret));
    assert_int_equal(WEXITSTATUS(ret), 1);

    cleanup_tool_outputs();
    unlink(out_path);
    char out_hex[PATH_MAX];
    snprintf(out_hex, sizeof(out_hex), "%s.hex", out_path);
    unlink(out_hex);
    unlink(in_path);
    unlink(wrong_path);
}


const struct CMUnitTest cli_tests[] = {
    cmocka_unit_test(test_cli_invalid_alg),
    cmocka_unit_test(test_cli_invalid_bits),
    cmocka_unit_test(test_cli_missing_infile),
    cmocka_unit_test(test_cli_requires_outfile_or_keygen),
    cmocka_unit_test(test_cli_keygen_rsa_only),
    cmocka_unit_test(test_cli_keygen_aes_only),
    cmocka_unit_test(test_cli_keygen_reject_paths),
    cmocka_unit_test(test_cli_requires_selections_for_encrypt),
    cmocka_unit_test(test_cli_verify_parse),
    cmocka_unit_test(test_cli_verify_sig_requires_alg),
    cmocka_unit_test(test_cli_verify_dec_requires_bits),
    cmocka_unit_test(test_cli_rsa_lms),
    cmocka_unit_test(test_cli_rsa_mldsa),
    cmocka_unit_test(test_cli_lms_mldsa),
    cmocka_unit_test(test_tool_keygen_rsa_outputs),
    cmocka_unit_test(test_tool_keygen_aes_outputs),
    cmocka_unit_test(test_tool_fails_when_ciphertext_exists),
    cmocka_unit_test(test_tool_fails_when_component_exists),
    cmocka_unit_test(test_tool_gen_keypair_when_aes_provided),
    cmocka_unit_test(test_tool_gen_aes_when_keys_provided),
    cmocka_unit_test(test_tool_verify_signature),
    cmocka_unit_test(test_tool_verify_decryption_success),
    cmocka_unit_test(test_tool_verify_decryption_failure),
};

const size_t cli_tests_count = sizeof(cli_tests) / sizeof(cli_tests[0]);


