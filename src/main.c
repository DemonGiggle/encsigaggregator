#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cliopts.h"
#include "crypto.h"
#include "hybrid_crypto.h"
#include "verify_mode.h"
#include "util.h"

int main(int argc, char **argv)
{
    cli_options opts;
    if (cli_parse_args(argc, argv, &opts) != 0) {
        return 1;
    }

    if (opts.verify_sig) {
        return verify_sig_mode(&opts);
    }

    int have_pk = opts.pk_path && opts.sk_path;
    int have_aes = opts.aes_key_path != NULL;
    if ((opts.pk_path && !opts.sk_path) || (!opts.pk_path && opts.sk_path)) {
        fprintf(stderr, "Both public and private key files must be specified\n");
        return 1;
    }
    if (opts.aes_iv_path && !opts.aes_key_path) {
        fprintf(stderr, "AES key file must be specified when providing IV file\n");
        return 1;
    }
    int generate_pk = !have_pk;
    int generate_aes = !have_aes;
    int include_keys = generate_pk || generate_aes;

    int ret = 1;
    uint8_t *buf = NULL;
    uint8_t (*sigs)[CRYPTO_MAX_SIG_SIZE] = NULL;
    uint8_t *enc = NULL;
    crypto_key privs[2] = {{0}};
    crypto_key pubs[2] = {{0}};

    /* Load the input file */
    size_t fsize = 0;
    if (read_file(opts.infile, &buf, &fsize) != 0) {
        perror("input");
        goto cleanup;
    }

    /* Load or generate the signing key pair */
    if (crypto_is_hybrid_alg(opts.alg)) {
        if (hybrid_crypto_load_keypair((hybrid_alg)opts.alg, opts.sk_path,
                                       opts.pk_path, privs, pubs) != 0) {
            fprintf(stderr, "Key init failed\n");
            goto cleanup;
        }
    } else {
        if (crypto_load_keypair((crypto_alg)opts.alg, opts.sk_path, opts.pk_path,
                                &privs[0], &pubs[0]) != 0) {
            fprintf(stderr, "Key init failed\n");
            goto cleanup;
        }
    }

    /* Load or generate AES key and IV */
    uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    if (crypto_init_aes(opts.aes_bits, opts.aes_key_path, opts.aes_iv_path,
                        aes_key, iv) != 0) {
        fprintf(stderr, "AES init failed\n");
        goto cleanup;
    }

    /* Sign the input */
    size_t sig_lens[2] = {0};
    sigs = malloc(sizeof(uint8_t[2][CRYPTO_MAX_SIG_SIZE]));
    if (!sigs) {
        goto cleanup;
    }
    if (crypto_is_hybrid_alg(opts.alg)) {
        if (hybrid_crypto_sign((hybrid_alg)opts.alg, privs, buf, fsize,
                               sigs, sig_lens) != 0) {
            fprintf(stderr, "Signing failed\n");
            goto cleanup;
        }
    } else {
        if (crypto_sign((crypto_alg)opts.alg, &privs[0], buf, fsize,
                        sigs[0], &sig_lens[0]) != 0) {
            fprintf(stderr, "Signing failed\n");
            goto cleanup;
        }
    }

    /* Encrypt the input */
    size_t remainder = fsize % CRYPTO_AES_IV_SIZE;
    size_t enc_len = fsize + (CRYPTO_AES_IV_SIZE - remainder);
    enc = malloc(enc_len);
    if (!enc) {
        goto cleanup;
    }
    if (crypto_encrypt_aescbc(aes_key, opts.aes_bits, iv, buf, fsize, enc,
                              &enc_len) != 0) {
        fprintf(stderr, "Encryption failed\n");
        goto cleanup;
    }

    /* Write everything to the requested output */
    if (write_outputs(opts.outfile, include_keys, opts.alg, privs, pubs,
                      aes_key, opts.aes_bits / 8,
                      iv, sigs, sig_lens, enc, enc_len) != 0) {
        fprintf(stderr, "Write failed\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(buf);
    free(sigs);
    free(enc);
    crypto_free_key(&privs[0]);
    crypto_free_key(&privs[1]);
    crypto_free_key(&pubs[0]);
    crypto_free_key(&pubs[1]);
    return ret;
}

