Coding Guidelines and Build Steps
================================

- Use C99 for all C source files.
- Keep main.c concise by delegating cryptographic loading/generation logic to
  crypto.c helper functions.

Build & Test Workflow
---------------------

Follow these steps to build the library and run the unit tests:

1. **Install system packages** (compiler, CMake, git, CMocka, Python):

   ```sh
   sudo apt-get update
   sudo apt-get install -y build-essential cmake git python3 python3-pip libcmocka-dev
   ```

2. **Install Python packages** required by Mbed TLS:

   ```sh
   pip3 install jsonschema jinja2
   ```

3. **Fetch and build third-party libraries** (Mbed TLS and PQClean):

   ```sh
   scripts/install_third_party.sh
   ```

   This script clones the correct versions and builds the libraries using
   `include/mbedtls_custom_config.h` to enable LMS support.

4. **Build the project**:

   ```sh
   make
   ```

   This produces `libcrypto.a` and the example command-line tool named according
   to the `TOOL_NAME` variable.

5. **Run the unit tests**:

   ```sh
   make test
   ```

   Re-run `make test` after any code changes to ensure everything builds and all
   tests pass.

