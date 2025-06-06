#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

extern const struct CMUnitTest crypto_tests[];
extern const size_t crypto_tests_count;
extern const struct CMUnitTest cli_tests[];
extern const size_t cli_tests_count;

int main(void) {
    size_t total = crypto_tests_count + cli_tests_count;
    struct CMUnitTest tests[total];
    memcpy(tests, crypto_tests, crypto_tests_count * sizeof(struct CMUnitTest));
    memcpy(tests + crypto_tests_count,
           cli_tests, cli_tests_count * sizeof(struct CMUnitTest));
    return cmocka_run_group_tests(tests, NULL, NULL);
}
