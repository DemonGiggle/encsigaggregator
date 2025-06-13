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
    fprintf(stderr, "  -a <alg>            signing algorithm: rsa,lms,mldsa87\n");
    fprintf(stderr, "  -b <bits>           AES key bits: 128,192,256\n");
    fprintf(stderr, "  --pk-path <file>    public key file\n");
    fprintf(stderr, "  --sk-path <file>    private key file\n");
    fprintf(stderr, "  --aes-key-path <f>  AES key file\n");
    fprintf(stderr, "  --aes-iv <f>        AES IV file (optional)\n");
    fprintf(stderr, "  -i <file>           input file\n");
    fprintf(stderr, "  -o <file>           output file\n");
}

int cli_parse_args(int argc, char **argv, cli_options *o)
{
    if (!o) return -1;
    optind = 1;
    o->alg = CRYPTO_ALG_RSA4096;
    o->aes_bits = CRYPTO_AES_KEY_BITS_256;
    o->infile = o->outfile = NULL;
    o->pk_path = o->sk_path = NULL;
    o->aes_key_path = o->aes_iv_path = NULL;

    static const struct option long_opts[] = {
        {"pk-path", required_argument, NULL, 1},
        {"sk-path", required_argument, NULL, 2},
        {"aes-key-path", required_argument, NULL, 3},
        {"aes-iv", required_argument, NULL, 4},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "a:b:i:o:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a':
            if (strcmp(optarg, "rsa") == 0)
                o->alg = CRYPTO_ALG_RSA4096;
            else if (strcmp(optarg, "lms") == 0)
                o->alg = CRYPTO_ALG_LMS;
            else if (strcmp(optarg, "mldsa87") == 0)
                o->alg = CRYPTO_ALG_MLDSA87;
            else {
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
        default:
            cli_usage(argv[0]);
            return -1;
        }
    }

    if (!o->infile || !o->outfile) {
        cli_usage(argv[0]);
        return -1;
    }
    return 0;
}

