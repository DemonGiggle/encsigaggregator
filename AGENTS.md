Coding Guidelines and Build Steps
================================

- Use C99 for all C source files.
- Keep main.c concise by delegating cryptographic loading/generation logic to
  crypto.c helper functions.
- Before building the project, make sure the dependencies are fetched and built:
  1. Run `scripts/fetch_deps.sh` to clone Mbed TLS and PQClean.
  2. Build Mbed TLS with `make -C libs/mbedtls library`.
  3. Build PQClean's ML‑DSA‑87 with `make -C libs/pqclean/crypto_sign/ml-dsa-87/clean`.
- The top level `make` depends on the libraries above to compile `libcrypto.a`
  and the example tool `encsigtool`.
