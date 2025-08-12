Coding Guidelines and Build Steps
================================

- Use C99 for all C source files.
- Keep main.c concise by delegating cryptographic loading/generation logic to
  crypto.c helper functions.
- Before building the project, make sure the prerequisites are installed and the
  dependencies are fetched and built:
  1. Install build tools and Python support:
     `sudo apt-get update && sudo apt-get install -y build-essential cmake git \
     python3 python3-pip`.
  2. Install the Python packages `jsonschema` and `jinja2` required by Mbed TLS
     (e.g. `pip3 install jsonschema jinja2`).
  3. Run `scripts/install_third_party.sh` to clone Mbed TLS and PQClean and
     build their libraries. Mbed TLS is compiled with
     `include/mbedtls_custom_config.h` to enable LMS support.
- Install the cmocka development package (e.g. `sudo apt-get install libcmocka-dev`) to compile the unit tests.
- The top level `make` depends on the libraries above to compile `libcrypto.a`
  and the example tool `encsigtool`.
