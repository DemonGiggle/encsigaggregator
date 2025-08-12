#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
MBEDTLS_DIR="$ROOT_DIR/libs/mbedtls"
PQCLEAN_DIR="$ROOT_DIR/libs/pqclean"
CONFIG_FILE="$ROOT_DIR/include/mbedtls_custom_config.h"

# Clone mbedtls v3.6.0 if not present
if [ ! -d "$MBEDTLS_DIR/.git" ]; then
    rm -rf "$MBEDTLS_DIR"
    git clone --branch v3.6.0 --depth 1 https://github.com/Mbed-TLS/mbedtls.git "$MBEDTLS_DIR"
    (cd "$MBEDTLS_DIR" && git submodule update --init)
fi

# Build mbedtls with the custom configuration
cp "$CONFIG_FILE" "$MBEDTLS_DIR/include/mbedtls"
make -C "$MBEDTLS_DIR" lib CFLAGS="-O2 -DMBEDTLS_CONFIG_FILE='\"mbedtls/mbedtls_custom_config.h\"'"

# Clone pqclean commit 448c71a8 if not present
if [ ! -d "$PQCLEAN_DIR/.git" ]; then
    rm -rf "$PQCLEAN_DIR"
    git clone https://github.com/pqclean/pqclean.git "$PQCLEAN_DIR"
    (cd "$PQCLEAN_DIR" && git checkout 448c71a8)
fi

# Build PQClean's ML-DSA-87 implementation
make -C "$PQCLEAN_DIR/crypto_sign/ml-dsa-87/clean"
