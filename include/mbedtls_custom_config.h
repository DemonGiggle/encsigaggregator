#ifndef MBEDTLS_CUSTOM_CONFIG_H
#define MBEDTLS_CUSTOM_CONFIG_H

/*
 * Minimal Mbed TLS configuration used by encsigaggregator.
 * Only the modules required by crypto.c are enabled.
 */

/* System support */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* Symmetric cryptography */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_C

/* Hashes and message digests */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C

/* Random number generation */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* Public key and RSA */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PEM_WRITE_C

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CLIENT
#define MBEDTLS_PSA_CRYPTO_CONFIG
#define PSA_WANT_ALG_SHA_256 1
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR 1
/* LMS signatures */
#define MBEDTLS_LMS_C
#define MBEDTLS_LMS_PRIVATE

/* Build_info.h includes the necessary config validation */

#endif /* MBEDTLS_CUSTOM_CONFIG_H */
