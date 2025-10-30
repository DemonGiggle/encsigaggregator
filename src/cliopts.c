#include "cliopts.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cli_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-a alg] [-b bits] [--pk-path f --sk-path f --aes-key-path f --aes-iv f] -i in -o out\n",
            prog);
    fprintf(stderr,
            "       %s --verify-sig --sig-path f --pk-path f --sk-path f -i in\n",
            prog);
    fprintf(stderr,
            "       %s --verify-dec --expected-file f --aes-key-path f --aes-iv f -i in [-o out]\n",
            prog);
    fprintf(stderr,
            "       %s [-a alg] [-b bits] (omit -o to generate new keys)\n",
            prog);
    fprintf(stderr, "  -a <alg>            signing algorithm: rsa,lms,mldsa87,rsa-lms,rsa-mldsa87,lms-mldsa87\n");
    fprintf(stderr, "  -b <bits>           AES key bits: 128,192,256\n");
    fprintf(stderr,
            "  --pk-path <file[,file]>    public key file(s)\n");
    fprintf(stderr,
            "  --sk-path <file[,file]>    private key file(s)\n");
    fprintf(stderr, "  --aes-key-path <f>  AES key file (required with --verify-dec)\n");
    fprintf(stderr, "  --aes-iv <f>        AES IV file (required with --verify-dec)\n");
    fprintf(stderr, "  --verify-sig        verify signature(s) instead of generating output\n");
    fprintf(stderr, "  --verify-dec        verify AES decryption against an expected file\n");
    fprintf(stderr,
            "  --sig-path <file[,file]>  signature file(s) for verification\n");
    fprintf(stderr,
            "  --expected-file <file>  expected plaintext for decryption verification\n");
    fprintf(stderr, "  -i <file>           input file\n");
    fprintf(stderr, "  -o <file>           output file\n");
}

int cli_parse_args(int argc, char **argv, cli_options *o)
{
    if (!o) {
        return -1;
    }

    optind           = 1;
    o->alg           = CRYPTO_ALG_NONE;
    o->aes_bits      = CRYPTO_AES_KEY_BITS_NONE;
    o->infile        = NULL;
    o->outfile       = NULL;
    o->pk_path       = NULL;
    o->sk_path       = NULL;
    o->aes_key_path  = NULL;
    o->aes_iv_path   = NULL;
    o->verify_sig    = 0;
    o->sig_path      = NULL;
    o->verify_dec    = 0;
    o->expected_path = NULL;
    o->keygen_mode   = 0;

    static const struct option long_opts[] = {
        {"pk-path", required_argument, NULL, 1},
        {"sk-path", required_argument, NULL, 2},
        {"aes-key-path", required_argument, NULL, 3},
        {"aes-iv", required_argument, NULL, 4},
        {"verify-sig", no_argument, NULL, 5},
        {"sig-path", required_argument, NULL, 6},
        {"verify-dec", no_argument, NULL, 7},
        {"expected-file", required_argument, NULL, 8},
        {0, 0, 0, 0}
    };

    int          opt;
    int          invalid_alg      = 0;
    const char  *invalid_alg_name = NULL;
    int          invalid_aes_bits = 0;
    const char  *invalid_bits_arg = NULL;
    while ((opt = getopt_long(argc, argv, "a:b:i:o:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a':
            if (strcmp(optarg, "rsa") == 0) {
                o->alg = CRYPTO_ALG_RSA4096;
            } else if (strcmp(optarg, "lms") == 0) {
                o->alg = CRYPTO_ALG_LMS;
            } else if (strcmp(optarg, "mldsa87") == 0) {
                o->alg = CRYPTO_ALG_MLDSA87;
            } else if (strcmp(optarg, "rsa-lms") == 0) {
                o->alg = CRYPTO_ALG_RSA4096_LMS;
            } else if (strcmp(optarg, "rsa-mldsa87") == 0) {
                o->alg = CRYPTO_ALG_RSA4096_MLDSA87;
            } else if (strcmp(optarg, "lms-mldsa87") == 0) {
                o->alg = CRYPTO_ALG_LMS_MLDSA87;
            } else {
                invalid_alg      = 1;
                invalid_alg_name = optarg;
                o->alg           = CRYPTO_ALG_NONE;
            }
            break;
        case 'b': {
            char *endptr = NULL;
            long  bits   = strtol(optarg, &endptr, 10);
            if (!endptr || *endptr != '\0' || bits <= 0) {
                invalid_aes_bits = 1;
                invalid_bits_arg = optarg;
                o->aes_bits      = CRYPTO_AES_KEY_BITS_NONE;
                break;
            }
            o->aes_bits = (size_t)bits;
            if (o->aes_bits != CRYPTO_AES_KEY_BITS_128 &&
                o->aes_bits != CRYPTO_AES_KEY_BITS_192 &&
                o->aes_bits != CRYPTO_AES_KEY_BITS_256) {
                invalid_aes_bits = 1;
                invalid_bits_arg = optarg;
                o->aes_bits      = CRYPTO_AES_KEY_BITS_NONE;
            }
            break;
        }
        case 'i':
            o->infile = optarg;
            break;
        case 'o':
            o->outfile = optarg;
            break;
        case 1:
            o->pk_path = optarg;
            break;
        case 2:
            o->sk_path = optarg;
            break;
        case 3:
            o->aes_key_path = optarg;
            break;
        case 4:
            o->aes_iv_path = optarg;
            break;
        case 5:
            o->verify_sig = 1;
            break;
        case 6:
            o->sig_path = optarg;
            break;
        case 7:
            o->verify_dec = 1;
            break;
        case 8:
            o->expected_path = optarg;
            break;
        default:
            cli_usage(argv[0]);
            return -1;
        }
    }

    int keygen_mode = (!o->verify_sig && !o->verify_dec && o->outfile == NULL);
    o->keygen_mode  = keygen_mode;

    if (invalid_alg && !keygen_mode) {
        fprintf(stderr, "Unknown algorithm %s\n", invalid_alg_name);
        return -1;
    }

    if (invalid_aes_bits && !keygen_mode) {
        fprintf(stderr, "Invalid AES bits: %s\n", invalid_bits_arg ? invalid_bits_arg : "");
        return -1;
    }

    if (!o->infile && !keygen_mode) {
        cli_usage(argv[0]);
        return -1;
    }

    if (o->verify_sig && o->verify_dec) {
        fprintf(stderr, "Signature and decryption verification modes are mutually exclusive\n");
        cli_usage(argv[0]);
        return -1;
    }

    if (!keygen_mode && !o->verify_sig && !o->verify_dec && !o->outfile) {
        cli_usage(argv[0]);
        return -1;
    }

    if (o->verify_sig && !o->sig_path) {
        fprintf(stderr, "--verify-sig requires --sig-path\n");
        cli_usage(argv[0]);
        return -1;
    }

    if (o->verify_dec && (!o->expected_path || !o->aes_key_path || !o->aes_iv_path)) {
        if (!o->expected_path) {
            fprintf(stderr, "--verify-dec requires --expected-file\n");
        }
        if (!o->aes_key_path) {
            fprintf(stderr, "--verify-dec requires --aes-key-path\n");
        }
        if (!o->aes_iv_path) {
            fprintf(stderr, "--verify-dec requires --aes-iv\n");
        }
        cli_usage(argv[0]);
        return -1;
    }

    if (keygen_mode) {
        if (o->alg == CRYPTO_ALG_NONE && o->aes_bits == CRYPTO_AES_KEY_BITS_NONE) {
            fprintf(stderr, "Key generation mode requires -a and/or -b\n");
            cli_usage(argv[0]);
            return -1;
        }
        if (o->pk_path || o->sk_path || o->aes_key_path || o->aes_iv_path ||
            o->sig_path || o->expected_path) {
            fprintf(stderr,
                    "Key generation mode does not accept existing key, IV, or verification paths\n");
            return -1;
        }
        return 0;
    }

    if (o->verify_sig) {
        if (o->alg == CRYPTO_ALG_NONE) {
            fprintf(stderr, "--verify-sig requires -a to select an algorithm\n");
            return -1;
        }
    }

    if (o->verify_dec) {
        if (o->aes_bits == CRYPTO_AES_KEY_BITS_NONE) {
            fprintf(stderr, "--verify-dec requires -b to select an AES key size\n");
            return -1;
        }
    }

    if (!o->verify_sig && !o->verify_dec) {
        if (o->alg == CRYPTO_ALG_NONE) {
            fprintf(stderr, "Signing mode requires -a to select an algorithm\n");
            return -1;
        }
        if (o->aes_bits == CRYPTO_AES_KEY_BITS_NONE) {
            fprintf(stderr, "Signing mode requires -b to select an AES key size\n");
            return -1;
        }
    }

    return 0;
}

void print_run_options(const cli_options *opts, int generate_pk, int generate_aes)
{
    if (!opts) {
        return;
    }

    fprintf(stderr, "Run summary:\n");
    const char *alg_name = NULL;
    if (opts->alg == CRYPTO_ALG_NONE) {
        alg_name = "(not selected)";
    } else {
        alg_name = crypto_alg_name(opts->alg);
    }
    fprintf(stderr, "  Algorithm: %s\n", alg_name);
    if (opts->aes_bits == CRYPTO_AES_KEY_BITS_NONE) {
        fprintf(stderr, "  AES key bits: (not selected)\n");
    } else {
        fprintf(stderr, "  AES key bits: %zu\n", opts->aes_bits);
    }
    const char *pk_status = NULL;
    if (generate_pk) {
        pk_status = "generated new key pair";
    } else if (opts->pk_path && opts->sk_path) {
        pk_status = "using provided key pair";
    } else {
        pk_status = "not generated";
    }

    const char *aes_status = NULL;
    if (generate_aes) {
        aes_status = "generated new key and IV";
    } else if (opts->aes_key_path && opts->aes_iv_path) {
        aes_status = "using provided key and IV";
    } else {
        aes_status = "not generated";
    }

    fprintf(stderr, "  Signing keys: %s\n", pk_status);
    fprintf(stderr, "  AES material: %s\n", aes_status);
}

