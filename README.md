# encsigaggregator

This project wraps several cryptographic algorithms with an abstract API.

## Dependencies

- [mbedtls](https://github.com/Mbed-TLS/mbedtls) tagged **v3.6.0**
- [pqclean](https://github.com/pqclean/pqclean) commit **448c71a8**

The sources for these libraries are expected inside `libs/mbedtls` and
`libs/pqclean` respectively. Because this environment has no network access,
you must obtain them manually. For example:

```sh
git clone --branch v3.6.0 https://github.com/Mbed-TLS/mbedtls.git libs/mbedtls
cd libs/pqclean && git checkout 448c71a8
```

## Building

Run `make` to build a static library `libcrypto.a`.
The Makefile assumes the library paths above.

## Usage

The API defined in `include/crypto.h` allows algorithm independent key
generation, signing, verification and AES‑CBC‑256 encryption/decryption.
