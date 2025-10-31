#ifndef CLIOPTS_H
#define CLIOPTS_H

#include "crypto.h"
#include "hybrid_crypto.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * struct cli_options - parsed command-line parameters
 * @alg:             selected signing algorithm
 * @aes_bits:        AES key size in bits
 * @infile:          path to input file
 * @outfile:         path to output file
 * @pk_path:         public key file path
 * @sk_path:         private key file path
 * @aes_key_path:    AES key file path
 * @aes_iv_path:     AES IV file path
 * @verify_sig:      non-zero to verify signatures instead of signing
 * @sig_path:        signature file path(s)
 * @verify_dec:      non-zero to verify AES decryption instead of signing
 * @expected_path:   expected plaintext file for decryption verification
 * @keygen_mode:     non-zero when the CLI should only generate keys
 */
typedef struct {
    int         alg;
    size_t      aes_bits;
    const char *infile;
    const char *outfile;
    const char *pk_path;
    const char *sk_path;
    const char *aes_key_path;
    const char *aes_iv_path;
    int         verify_sig;
    const char *sig_path;
    int         verify_dec;
    const char *expected_path;
    int         keygen_mode;
} cli_options;

/**
 * cli_parse_args - parse argc/argv into opts
 * @argc: argument count
 * @argv: argument vector
 * @opts: parsed options
 *
 * Return: 0 on success, -1 on error.
 */
int cli_parse_args(int argc, char **argv, cli_options *opts);

/**
 * cli_usage - print usage information for the program
 * @prog: program name
 */
void cli_usage(const char *prog);

void print_run_options(const cli_options *opts, int generate_pk, int generate_aes);

#ifdef __cplusplus
}
#endif

#endif /* CLIOPTS_H */
