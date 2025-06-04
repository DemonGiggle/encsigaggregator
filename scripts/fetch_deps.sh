#!/bin/sh
set -e

MBEDTLS_DIR="libs/mbedtls"
PQCLEAN_DIR="libs/pqclean"

# Clone mbedtls v3.6.0 if not present
if [ ! -d "$MBEDTLS_DIR/.git" ]; then
    rm -rf "$MBEDTLS_DIR"
    git clone --branch v3.6.0 --depth 1 https://github.com/Mbed-TLS/mbedtls.git "$MBEDTLS_DIR"
fi

# Clone pqclean commit 448c71a8 if not present
if [ ! -d "$PQCLEAN_DIR/.git" ]; then
    rm -rf "$PQCLEAN_DIR"
    git clone https://github.com/pqclean/pqclean.git "$PQCLEAN_DIR"
    (cd "$PQCLEAN_DIR" && git checkout 448c71a8)
fi
