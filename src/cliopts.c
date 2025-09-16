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
    fprintf(stderr, "  -a <alg>            signing algorithm: rsa,lms,mldsa87,rsa-lms,rsa-mldsa87,lms-mldsa87\n");
    fprintf(stderr, "  -b <bits>           AES key bits: 128,192,256\n");
    fprintf(stderr,
            "  --pk-path <file[,file]>    public key file(s)\n");
    fprintf(stderr,
            "  --sk-path <file[,file]>    private key file(s)\n");
    fprintf(stderr, "  --aes-key-path <f>  AES key file\n");
    fprintf(stderr, "  --aes-iv <f>        AES IV file (optional)\n");
    fprintf(stderr, "  --verify-sig        verify signature(s) instead of generating output\n");
    fprintf(stderr,
            "  --sig-path <file[,file]>  signature file(s) for verification\n");
    fprintf(stderr, "  -i <file>           input file\n");
    fprintf(stderr, "  -o <file>           output file\n");
}

int cli_parse_args(int argc, char **argv, cli_options *o)
{
    if (!o) {
        return -1;
    }

    optind          = 1;
    o->alg          = CRYPTO_ALG_RSA4096;
    o->aes_bits     = CRYPTO_AES_KEY_BITS_256;
    o->infile       = NULL;
    o->outfile      = NULL;
    o->pk_path      = NULL;
    o->sk_path      = NULL;
    o->aes_key_path = NULL;
    o->aes_iv_path  = NULL;
    o->verify_sig   = 0;
    o->sig_path     = NULL;

    static const struct option long_opts[] = {
        {"pk-path", required_argument, NULL, 1},
        {"sk-path", required_argument, NULL, 2},
        {"aes-key-path", required_argument, NULL, 3},
        {"aes-iv", required_argument, NULL, 4},
        {"verify-sig", no_argument, NULL, 5},
        {"sig-path", required_argument, NULL, 6},
        {0, 0, 0, 0}
    };

    int opt;
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
                fprintf(stderr, "Unknown algorithm %s\n", optarg);
                return -1;
            }
            break;
        case 'b':
            o->aes_bits = (size_t)atoi(optarg);
            if (o->aes_bits != CRYPTO_AES_KEY_BITS_128 &&
                o->aes_bits != CRYPTO_AES_KEY_BITS_192 &&
                o->aes_bits != CRYPTO_AES_KEY_BITS_256) {
                fprintf(stderr, "Invalid AES bits\n");
                return -1;
            }
            break;
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
        default:
            cli_usage(argv[0]);
            return -1;
        }
    }

    if (!o->infile) {
        cli_usage(argv[0]);
        return -1;
    }

    if (!o->verify_sig && !o->outfile) {
        cli_usage(argv[0]);
        return -1;
    }

    if (o->verify_sig && !o->sig_path) {
        cli_usage(argv[0]);
        return -1;
    }

    return 0;
}

