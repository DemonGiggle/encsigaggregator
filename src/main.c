#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "crypto.h"

static const char rsa_priv_pem[] =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"KyYEvA76HdgOoaypQyGVSwi8gcpMLw==\n"
"-----END PRIVATE KEY-----\n"
;
static const char rsa_pub_pem[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsYU/0WHBBZdPNYDDCxPs\n"
"Ci4yctwkZLcw5u4HwyuHO7iGqkKWrgPla+XoB1gQX8dYY2a4bbxegMQwjs2LOJYp\n"
"6qMZ7a8Bbx5movjw90W+bymU37cuSSzMyufH8mSo0iay9DpjepqvHW3SG51vjxd7\n"
"6ZOrWaAN5xRpC5t1L4crZ2QwLgF1tUjUQ0WEnBQbStXc0yRrvD1AFTp17Ko/X7gz\n"
"XWI2bjKCDgspcgsDFGcxfcItnKiS9QAr9FvEdG8+KhluKhqOs0rHF913JXT2TMJp\n"
"NEo0aqqxmqpCQ44hVJGBNJTUUmRU59tRAesHDd3tU6PeyIdVoJ4cPif7QLILMfiW\n"
"ZA41hhvh4aMxi+r5o2DfTWyOAyLNOK+eXwn0JSLqq4++sRjhQ5gj3LdSUDa10vaB\n"
"/4oo1+wFXAGMt1z49OrS6WYCFOLRIrqhRaA/OBx0p4iNpHAmcW2d55mEp8lEmZqU\n"
"oKrlZ398POJxxUVrbkl38dc10Vyb5hnj37MkKFLPcF6tPSLEUvVQBCpy0Kxg/Etq\n"
"RRyhy6xRxucIRtOvU6ISaHnwEBdxmdK073a4LNGDF2AoTFfKv+61W3z5uZf28Dn0\n"
"tKePz+dVOlgs/FyvFvXV+FzHgHh6Z8EPcNrCdyf3uPKVXRJ4NxAI40kl88twqCEE\n"
"KjQ8CfousjyG3+4lxSY1rvMCAwEAAQ==\n"
"-----END PUBLIC KEY-----\n"
;
static const uint8_t aes_key_128[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t aes_key_192[24] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
};
static const uint8_t aes_key_256[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t default_iv[16] = {0};

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-g] -a <alg> -b <bits> -i <in> -o <out>\n", prog);
    fprintf(stderr, "  -g            generate keys (default uses predefined)\n");
    fprintf(stderr, "  -a <alg>      signing algorithm: rsa,lms,mldsa87\n");
    fprintf(stderr, "  -b <bits>     AES key bits: 128,192,256\n");
    fprintf(stderr, "  -i <file>     input file\n");
    fprintf(stderr, "  -o <file>     output file\n");
}

int main(int argc, char **argv) {
    crypto_alg alg = CRYPTO_ALG_RSA4096;
    size_t aes_bits = 256;
    int generate = 0;
    const char *infile = NULL;
    const char *outfile = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "ga:b:i:o:")) != -1) {
        switch (opt) {
        case 'g':
            generate = 1;
            break;
        case 'a':
            if (strcmp(optarg, "rsa") == 0)
                alg = CRYPTO_ALG_RSA4096;
            else if (strcmp(optarg, "lms") == 0)
                alg = CRYPTO_ALG_LMS;
            else if (strcmp(optarg, "mldsa87") == 0)
                alg = CRYPTO_ALG_MLDSA87;
            else {
                fprintf(stderr, "Unknown algorithm %s\n", optarg);
                return 1;
            }
            break;
        case 'b':
            aes_bits = (size_t)atoi(optarg);
            if (aes_bits != 128 && aes_bits != 192 && aes_bits != 256) {
                fprintf(stderr, "Invalid AES bits\n");
                return 1;
            }
            break;
        case 'i':
            infile = optarg;
            break;
        case 'o':
            outfile = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    if (!infile || !outfile) {
        usage(argv[0]);
        return 1;
    }

    FILE *f = fopen(infile, "rb");
    if (!f) {
        perror("open input");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(fsize);
    if (!buf) { fclose(f); return 1; }
    if (fread(buf, 1, fsize, f) != (size_t)fsize) { fclose(f); free(buf); return 1; }
    fclose(f);

    crypto_key priv = {0}, pub = {0};
    int ret;
    if (generate) {
        ret = crypto_keygen(alg, &priv, &pub);
    } else {
        if (alg != CRYPTO_ALG_RSA4096) {
            fprintf(stderr, "Predefined keys only available for RSA\n");
            free(buf);
            return 1;
        }
        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);
        if (mbedtls_pk_parse_key(&pk, (const unsigned char *)rsa_priv_pem,
                                sizeof(rsa_priv_pem)-1, NULL, 0, NULL, NULL) != 0) {
            fprintf(stderr, "Failed to load RSA key\n");
            mbedtls_pk_free(&pk);
            free(buf);
            return 1;
        }
        priv.alg = CRYPTO_ALG_RSA4096;
        priv.key = mbedtls_pk_rsa(pk);
        priv.key_len = sizeof(mbedtls_rsa_context);
        pub.alg = CRYPTO_ALG_RSA4096;
        pub.key = mbedtls_pk_rsa(pk);
        pub.key_len = sizeof(mbedtls_rsa_context);
        ret = 0;
    }
    if (ret != 0) {
        fprintf(stderr, "Key generation failed\n");
        free(buf);
        return 1;
    }

    uint8_t aes_key[32];
    uint8_t iv[16];
    memcpy(aes_key, aes_bits == 128 ? aes_key_128 : (aes_bits == 192 ? aes_key_192 : aes_key_256), aes_bits/8);
    memcpy(iv, default_iv, sizeof(iv));
    if (generate) {
        mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg;
        mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg);
        if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, NULL, 0) == 0) {
            mbedtls_ctr_drbg_random(&drbg, aes_key, aes_bits/8);
            mbedtls_ctr_drbg_random(&drbg, iv, sizeof(iv));
        }
        mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&ent);
    }

    size_t sig_len = 10240; /* large enough */
    uint8_t *sig = malloc(sig_len);
    if (!sig) { free(buf); crypto_free_key(&priv); return 1; }
    if (crypto_sign(alg, &priv, buf, fsize, sig, &sig_len) != 0) {
        fprintf(stderr, "Signing failed\n");
        free(buf); free(sig); crypto_free_key(&priv); return 1; }

    uint8_t *enc = malloc(fsize);
    if (!enc) { free(buf); free(sig); crypto_free_key(&priv); return 1; }
    if (crypto_encrypt_aescbc(aes_key, aes_bits, iv, buf, fsize, enc) != 0) {
        fprintf(stderr, "Encryption failed\n");
        free(buf); free(sig); free(enc); crypto_free_key(&priv); return 1; }

    f = fopen(outfile, "wb");
    if (!f) { perror("open out"); free(buf); free(sig); free(enc); crypto_free_key(&priv); return 1; }
    if (generate) {
        uint32_t v;
        v = (uint32_t)aes_bits; fwrite(&v, sizeof(v), 1, f);
        fwrite(iv, 1, sizeof(iv), f);
        fwrite(aes_key, 1, aes_bits/8, f);
        v = (uint32_t)priv.key_len; fwrite(&v, sizeof(v), 1, f); fwrite(priv.key, 1, priv.key_len, f);
        v = (uint32_t)pub.key_len; fwrite(&v, sizeof(v), 1, f); fwrite(pub.key, 1, pub.key_len, f);
        v = (uint32_t)sig_len; fwrite(&v, sizeof(v), 1, f); fwrite(sig, 1, sig_len, f);
        v = (uint32_t)fsize; fwrite(&v, sizeof(v), 1, f); fwrite(enc, 1, fsize, f);
    } else {
        fwrite(enc, 1, fsize, f);
    }
    fclose(f);

    free(buf); free(sig); free(enc);
    crypto_free_key(&priv); /* pub shares context */
    return 0;
}

