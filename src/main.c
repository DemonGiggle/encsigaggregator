#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cliopts.h"
#include "crypto.h"
#include "util.h"





int main(int argc, char **argv)
{
    cli_options opts;
    if (cli_parse_args(argc, argv, &opts) != 0) {
        return 1;
    }

    /* Determine if all crypto material is provided */
    int generate = !(opts.pk_path || opts.sk_path || opts.aes_key_path || opts.aes_iv_path);
    if (!generate && (!opts.pk_path || !opts.sk_path || !opts.aes_key_path)) {
        fprintf(stderr, "Public key, private key and AES key files must be specified\n");
        return 1;
    }

    int ret = 1;
    uint8_t *buf = NULL;
    uint8_t *sig = NULL;
    uint8_t *enc = NULL;
    crypto_key priv = {0}, pub = {0};
    crypto_key priv_ser = {0}, pub_ser = {0};

    /* Load the input file */
    size_t fsize = 0;
    if (read_file(opts.infile, &buf, &fsize) != 0) {
        perror("input");
        goto cleanup;
    }

    /* Load or generate the signing key pair */
    if (crypto_load_keypair(opts.alg, opts.sk_path, opts.pk_path, &priv, &pub) != 0) {
        fprintf(stderr, "Key init failed\n");
        goto cleanup;
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
    size_t sig_len = CRYPTO_MAX_SIG_SIZE; /* large enough */
    sig = malloc(sig_len);
    if (!sig) {
        goto cleanup;
    }
    if (crypto_sign(opts.alg, &priv, buf, fsize, sig, &sig_len) != 0) {
        fprintf(stderr, "Signing failed\n");
        goto cleanup;
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

    const crypto_key *priv_out = &priv;
    const crypto_key *pub_out  = &pub;
    if (generate) {
        if (crypto_export_keypair(opts.alg, &priv, &pub,
                                  &priv_ser, &pub_ser) != 0) {
            fprintf(stderr, "Key export failed\n");
            goto cleanup;
        }
        priv_out = &priv_ser;
        pub_out  = &pub_ser;
    }

    /* Write everything to the requested output */
    if (write_outputs(opts.outfile, generate, priv_out, pub_out,
                      aes_key, opts.aes_bits / 8,
                      iv, sig, sig_len, enc, enc_len) != 0) {
        fprintf(stderr, "Write failed\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(buf);
    free(sig);
    free(enc);
    if (generate) {
        free(priv_ser.key);
        free(pub_ser.key);
    }
    crypto_free_key(&priv); /* pub shares context */
    return ret;
}

