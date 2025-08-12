# encsigaggregator

This project wraps several cryptographic algorithms with an abstract API.

## Dependencies

- [mbedtls](https://github.com/Mbed-TLS/mbedtls) tagged **v3.6.0**
- [pqclean](https://github.com/pqclean/pqclean) commit **448c71a8**

The sources for these libraries are expected inside `libs/mbedtls` and
`libs/pqclean` respectively. A helper script is provided to fetch and build
the correct versions automatically:

```sh
scripts/install_third_party.sh
```

The provided `include/mbedtls_custom_config.h` enables all algorithms
required by the project, including LMS private operations.

If you prefer to fetch them manually, run:

```sh
git clone --branch v3.6.0 https://github.com/Mbed-TLS/mbedtls.git libs/mbedtls
cd libs/pqclean && git checkout 448c71a8
```

After cloning, fetch the Mbed TLS submodule, install the required Python
packages and build both libraries:

```sh
git -C libs/mbedtls submodule update --init
pip install jsonschema jinja2
cp include/mbedtls_custom_config.h libs/mbedtls/include/mbedtls
make -C libs/mbedtls lib CFLAGS="-O2 -DMBEDTLS_CONFIG_FILE='\"mbedtls/mbedtls_custom_config.h\"'"
make -C libs/pqclean/crypto_sign/ml-dsa-87/clean
```

## Building

Run `make` to build a static library `libcrypto.a`.
The Makefile assumes the library paths above and uses
`include/mbedtls_custom_config.h` as the Mbed TLS configuration.

## Running Tests

Unit tests are written with [CMocka](https://cmocka.org). Install the
development package on Debian/Ubuntu systems via:

```sh
sudo apt-get update
sudo apt-get install libcmocka-dev
```

After the dependencies and library sources are prepared, execute

```sh
make test
```

to build and run the suite located under `tests/`.

## Usage

The API defined in `include/crypto.h` allows algorithm independent key
generation, signing, verification and AES‑CBC encryption/decryption with
128/192/256‑bit keys.
It also exposes a helper to compute SHA‑384 digests of arbitrary data.
