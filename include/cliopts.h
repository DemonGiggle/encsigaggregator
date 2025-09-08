#ifndef CLIOPTS_H
#define CLIOPTS_H

#include "crypto.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Parsed command-line parameters. */
typedef struct {
    crypto_alg alg;           /**< selected signing algorithm */
    size_t aes_bits;          /**< AES key size in bits */
    const char *infile;       /**< path to input file */
    const char *outfile;      /**< path to output file */
    const char *pk_path;      /**< public key file path */
    const char *sk_path;      /**< private key file path */
    const char *aes_key_path; /**< AES key file path */
    const char *aes_iv_path;  /**< AES IV file path */
} cli_options;

/**
 * @brief Parse argc/argv into opts.
 *
 * @return 0 on success, -1 on error.
 */
int cli_parse_args(int argc, char **argv, cli_options *opts);

/** @brief Print usage information for the program. */
void cli_usage(const char *prog);

#ifdef __cplusplus
}
#endif

#endif /* CLIOPTS_H */
