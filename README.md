# encsigaggregator

This project wraps several cryptographic algorithms with an abstract API.

## Dependencies

- [mbedtls](https://github.com/Mbed-TLS/mbedtls) tagged **v3.6.0**
- [pqclean](https://github.com/pqclean/pqclean) commit **448c71a8**

The sources for these libraries are expected inside `libs/mbedtls` and
`libs/pqclean` respectively. A helper script is provided to fetch the
correct versions automatically:

```sh
scripts/fetch_deps.sh
```

The provided `include/mbedtls_custom_config.h` enables all algorithms
required by the project, including LMS private operations.

If you prefer to fetch them manually, run:

```sh
git clone --branch v3.6.0 https://github.com/Mbed-TLS/mbedtls.git libs/mbedtls
cd libs/pqclean && git checkout 448c71a8
```

## Building

Run `make` to build a static library `libcrypto.a`.
The Makefile assumes the library paths above and uses
`include/mbedtls_custom_config.h` as the Mbed TLS configuration.

## Usage

The API defined in `include/crypto.h` allows algorithm independent key
generation, signing, verification and AES‑CBC encryption/decryption with
128/192/256‑bit keys.
It also exposes a helper to compute SHA‑384 digests of arbitrary data.
