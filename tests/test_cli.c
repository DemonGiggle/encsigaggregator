#include "cliopts.h"
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

void test_cli_invalid_alg(void **state) {
    (void)state;
    char *argv[] = {"prog", "-a", "foo", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(7, argv, &opts), -1);
}

void test_cli_invalid_bits(void **state) {
    (void)state;
    char *argv[] = {"prog", "-b", "42", "-i", "in", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(7, argv, &opts), -1);
}

void test_cli_missing_infile(void **state) {
    (void)state;
    char *argv[] = {"prog", "-o", "out", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(3, argv, &opts), -1);
}

void test_cli_missing_outfile(void **state) {
    (void)state;
    char *argv[] = {"prog", "-i", "in", NULL};
    cli_options opts;
    assert_int_equal(cli_parse_args(3, argv, &opts), -1);
}

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


const struct CMUnitTest cli_tests[] = {
    cmocka_unit_test(test_cli_invalid_alg),
    cmocka_unit_test(test_cli_invalid_bits),
    cmocka_unit_test(test_cli_missing_infile),
    cmocka_unit_test(test_cli_missing_outfile),
    cmocka_unit_test(test_cli_valid_minimal),
};

const size_t cli_tests_count = sizeof(cli_tests) / sizeof(cli_tests[0]);


