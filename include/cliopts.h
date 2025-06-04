#ifndef CLIOPTS_H
#define CLIOPTS_H

#include "crypto.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    crypto_alg alg;
    size_t aes_bits;
    const char *infile;
    const char *outfile;
    const char *pk_path;
    const char *sk_path;
    const char *aes_key_path;
    const char *aes_iv_path;
} cli_options;

int cli_parse_args(int argc, char **argv, cli_options *opts);
void cli_usage(const char *prog);

#ifdef __cplusplus
}
#endif

#endif /* CLIOPTS_H */
