#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cliopts.h"
#include "crypto.h"
#include "util.h"


/* write binary and hex representations to files */
static int write_bin_hex_pair(const char *bin_path, const char *hex_path,
                              const uint8_t *data, size_t len)
{
    FILE *f = fopen(bin_path, "wb");
    if (!f)
        return -1;
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);

    f = fopen(hex_path, "w");
    if (!f)
        return -1;
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "%02x", data[i]);
        if (i + 1 < len)
            fputc(',', f);
    }
    fputc('\n', f);
    fclose(f);
    return 0;
}

static int write_component(const char *base, const char *name,
                           const uint8_t *data, size_t len)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    char *bin_path = malloc(base_len + 1 + name_len + 4 + 1);
    char *hex_path = malloc(base_len + 1 + name_len + 4 + 1);
    if (!bin_path || !hex_path) {
        free(bin_path);
        free(hex_path);
        return -1;
    }
    sprintf(bin_path, "%s_%s.bin", base, name);
    sprintf(hex_path, "%s_%s.hex", base, name);
    int ret = write_bin_hex_pair(bin_path, hex_path, data, len);
    if (ret == 0) {
        printf("%s binary: %s\n", name, bin_path);
        printf("%s hex: %s\n", name, hex_path);
    }
    free(bin_path);
    free(hex_path);
    return ret;
}

static int write_outputs(const char *out_path, int include_keys,
                         const crypto_key *priv, const crypto_key *pub,
                         size_t aes_bits,
                         const uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE],
                         const uint8_t iv[CRYPTO_AES_IV_SIZE],
                         const uint8_t *sig, size_t sig_len,
                         const uint8_t *enc, size_t enc_len)
{
    size_t out_len = strlen(out_path);
    char *hex_path = malloc(out_len + 4 + 1);
    if (!hex_path)
        return -1;
    sprintf(hex_path, "%s.hex", out_path);
    if (write_bin_hex_pair(out_path, hex_path, enc, enc_len) != 0) {
        free(hex_path);
        return -1;
    }
    printf("ciphertext binary: %s\n", out_path);
    printf("ciphertext hex: %s\n", hex_path);
    free(hex_path);

    if (include_keys) {
        uint32_t v = (uint32_t)aes_bits;
        if (write_component(out_path, "aes_bits", (uint8_t *)&v,
                            sizeof(v)) != 0)
            return -1;
        if (write_component(out_path, "aes_iv", iv,
                            CRYPTO_AES_IV_SIZE) != 0)
            return -1;
        if (write_component(out_path, "aes_key", aes_key,
                            aes_bits / 8) != 0)
            return -1;
        if (write_component(out_path, "priv", priv->key, priv->key_len) != 0)
            return -1;
        if (write_component(out_path, "pub", pub->key, pub->key_len) != 0)
            return -1;
        if (write_component(out_path, "sig", sig, sig_len) != 0)
            return -1;
    }
    return 0;
}



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

    /* Load the input file */
    uint8_t *buf  = NULL;
    size_t   fsize = 0;
    if (read_file(opts.infile, &buf, &fsize) != 0) {
        perror("input");
        return 1;
    }

    /* Load or generate the signing key pair */
    crypto_key priv = {0};
    crypto_key pub  = {0};

    int ret = crypto_load_keypair(opts.alg, opts.sk_path, opts.pk_path, &priv, &pub);
    if (ret != 0) {
        fprintf(stderr, "Key init failed\n");
        free(buf);
        return 1;
    }

    /* Load or generate AES key and IV */
    uint8_t aes_key[CRYPTO_AES_MAX_KEY_SIZE];
    uint8_t iv[CRYPTO_AES_IV_SIZE];
    if (crypto_init_aes(opts.aes_bits, opts.aes_key_path, opts.aes_iv_path,
                        aes_key, iv) != 0) {
        fprintf(stderr, "AES init failed\n");
        free(buf);
        crypto_free_key(&priv);
        return 1;
    }

    /* Sign the input */
    size_t   sig_len = CRYPTO_MAX_SIG_SIZE; /* large enough */
    uint8_t *sig     = malloc(sig_len);
    if (!sig) {
        free(buf);
        crypto_free_key(&priv);
        return 1;
    }
    if (crypto_sign(opts.alg, &priv, buf, fsize, sig, &sig_len) != 0) {
        fprintf(stderr, "Signing failed\n");
        free(buf);
        free(sig);
        crypto_free_key(&priv);
        return 1;
    }

    /* Encrypt the input */
    size_t   remainder = fsize % CRYPTO_AES_IV_SIZE;
    size_t   enc_len   = fsize + (CRYPTO_AES_IV_SIZE - remainder);
    uint8_t *enc       = malloc(enc_len);
    if (!enc) {
        free(buf);
        free(sig);
        crypto_free_key(&priv);
        return 1;
    }
    if (crypto_encrypt_aescbc(aes_key, opts.aes_bits, iv, buf, fsize, enc,
                              &enc_len) != 0) {
        fprintf(stderr, "Encryption failed\n");
        free(buf);
        free(sig);
        free(enc);
        crypto_free_key(&priv);
        return 1;
    }

    /* Write everything to the requested output */
    if (write_outputs(opts.outfile, generate, &priv, &pub, opts.aes_bits,
                      aes_key, iv, sig, sig_len, enc, enc_len) != 0) {
        fprintf(stderr, "Write failed\n");
        free(buf);
        free(sig);
        free(enc);
        crypto_free_key(&priv);
        return 1;
    }

    free(buf);
    free(sig);
    free(enc);
    crypto_free_key(&priv); /* pub shares context */
    return 0;
}

