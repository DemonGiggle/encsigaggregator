#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cliopts.h"
#include "crypto.h"

/* simple helper to load a whole file into memory */
static int read_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *tmp = malloc(sz ? sz : 1);
    if (!tmp) { fclose(f); return -1; }
    if (fread(tmp, 1, sz, f) != (size_t)sz) { fclose(f); free(tmp); return -1; }
    fclose(f);
    *buf = tmp;
    *len = sz;
    return 0;
}

/* write result to the output file, optionally including generated keys */
static int write_output(const char *path, int include_keys, const crypto_key *priv,
                        const crypto_key *pub, size_t aes_bits,
                        const uint8_t aes_key[32], const uint8_t iv[16],
                        const uint8_t *sig, size_t sig_len,
                        const uint8_t *enc, size_t enc_len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (include_keys) {
        uint32_t v = (uint32_t)aes_bits;
        fwrite(&v, sizeof(v), 1, f);
        fwrite(iv, 1, 16, f);
        fwrite(aes_key, 1, aes_bits/8, f);
        v = (uint32_t)priv->key_len; fwrite(&v, sizeof(v), 1, f); fwrite(priv->key, 1, priv->key_len, f);
        v = (uint32_t)pub->key_len; fwrite(&v, sizeof(v), 1, f); fwrite(pub->key, 1, pub->key_len, f);
        v = (uint32_t)sig_len; fwrite(&v, sizeof(v), 1, f); fwrite(sig, 1, sig_len, f);
        v = (uint32_t)enc_len; fwrite(&v, sizeof(v), 1, f); fwrite(enc, 1, enc_len, f);
    } else {
        fwrite(enc, 1, enc_len, f);
    }
    fclose(f);
    return 0;
}



int main(int argc, char **argv) {
    cli_options opts;
    if (cli_parse_args(argc, argv, &opts) != 0)
        return 1;
    /* Determine if all crypto material is provided */
    int generate = !(opts.pk_path || opts.sk_path || opts.aes_key_path || opts.aes_iv_path);
    if (!generate && (!opts.pk_path || !opts.sk_path || !opts.aes_key_path)) {
        fprintf(stderr, "Public key, private key and AES key files must be specified\n");
        return 1;
    }

    /* Load the input file */
    uint8_t *buf = NULL; size_t fsize = 0;
    if (read_file(opts.infile, &buf, &fsize) != 0) {
        perror("input");
        return 1;
    }

    /* Load or generate the signing key pair */
    crypto_key priv = {0}, pub = {0};
    int ret = crypto_load_keypair(opts.alg, opts.sk_path, opts.pk_path, &priv, &pub);
    if (ret != 0) {
        fprintf(stderr, "Key init failed\n");
        free(buf);
        return 1;
    }

    /* Load or generate AES key and IV */
    uint8_t aes_key[32];
    uint8_t iv[16];
    if (crypto_init_aes(opts.aes_bits, opts.aes_key_path, opts.aes_iv_path,
                        aes_key, iv) != 0) {
        fprintf(stderr, "AES init failed\n");
        free(buf); crypto_free_key(&priv); return 1;
    }

    /* Sign the input */
    size_t sig_len = 10240; /* large enough */
    uint8_t *sig = malloc(sig_len);
    if (!sig) { free(buf); crypto_free_key(&priv); return 1; }
    if (crypto_sign(opts.alg, &priv, buf, fsize, sig, &sig_len) != 0) {
        fprintf(stderr, "Signing failed\n");
        free(buf); free(sig); crypto_free_key(&priv); return 1; }

    /* Encrypt the input */
    uint8_t *enc = malloc(fsize);
    if (!enc) { free(buf); free(sig); crypto_free_key(&priv); return 1; }
    if (crypto_encrypt_aescbc(aes_key, opts.aes_bits, iv, buf, fsize, enc) != 0) {
        fprintf(stderr, "Encryption failed\n");
        free(buf); free(sig); free(enc); crypto_free_key(&priv); return 1; }

    /* Write everything to the requested output */
    if (write_output(opts.outfile, generate, &priv, &pub, opts.aes_bits,
                     aes_key, iv, sig, sig_len, enc, fsize) != 0) {
        fprintf(stderr, "Write failed\n");
        free(buf); free(sig); free(enc); crypto_free_key(&priv); return 1;
    }

    free(buf); free(sig); free(enc);
    crypto_free_key(&priv); /* pub shares context */
    return 0;
}

