#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdlib.h>
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
    const char *filter      = getenv("CMOCKA_TEST_FILTER");
    if (filter != NULL && filter[0] != '\0') {
        cmocka_set_test_filter(filter);
    }
    const char *skip_filter = getenv("CMOCKA_SKIP_TEST_FILTER");
    if (skip_filter != NULL && skip_filter[0] != '\0') {
        cmocka_set_skip_filter(skip_filter);
    }
    return cmocka_run_group_tests(tests, NULL, NULL);
}
