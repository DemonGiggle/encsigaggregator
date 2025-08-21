MBEDTLS_DIR ?= libs/mbedtls
PQCLEAN_DIR ?= libs/pqclean

CFLAGS += -Iinclude -I$(MBEDTLS_DIR)/include \
        -I$(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean \
        -I$(PQCLEAN_DIR)/common \
        -DMBEDTLS_CONFIG_FILE='"mbedtls_custom_config.h"' \
        -std=c99
LDFLAGS += -L$(MBEDTLS_DIR)/library -lmbedtls -lmbedcrypto -lmbedx509 \
           -L$(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean -lml-dsa-87_clean

SRC = src/crypto.c src/util.c \
       $(PQCLEAN_DIR)/common/randombytes.c \
       $(PQCLEAN_DIR)/common/fips202.c \
       $(PQCLEAN_DIR)/common/sha2.c \
       $(PQCLEAN_DIR)/common/nistseedexpander.c \
       $(PQCLEAN_DIR)/common/sp800-185.c
OBJ = $(SRC:.c=.o)
TOOL_SRC = src/main.c src/cliopts.c
TOOL_OBJ = $(TOOL_SRC:.c=.o)
TEST_SRC = tests/test_crypto.c tests/test_cli.c tests/test_runner.c
TEST_OBJ = $(TEST_SRC:.c=.o) src/cliopts.o
TEST_BIN = tests/run_tests

MBEDTLS_LIBS = $(MBEDTLS_DIR)/library/libmbedtls.a \
               $(MBEDTLS_DIR)/library/libmbedcrypto.a \
               $(MBEDTLS_DIR)/library/libmbedx509.a
PQ_LIB = $(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean/libml-dsa-87_clean.a

all: $(MBEDTLS_LIBS) $(PQ_LIB) libcrypto.a encsigtool

$(MBEDTLS_LIBS):
	$(MAKE) -C $(MBEDTLS_DIR) library

$(PQ_LIB):
	$(MAKE) -C $(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean
	
libcrypto.a: $(OBJ)
	ar rcs $@ $^

clean:
	rm -f $(OBJ) $(TOOL_OBJ) $(TEST_OBJ) libcrypto.a encsigtool $(TEST_BIN)

encsigtool: libcrypto.a $(TOOL_OBJ)
	$(CC) $(CFLAGS) -o $@ $(TOOL_OBJ) -Wl,--start-group libcrypto.a $(LDFLAGS) -Wl,--end-group

$(TEST_BIN): $(MBEDTLS_LIBS) $(PQ_LIB) libcrypto.a $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJ) -Wl,--start-group libcrypto.a $(LDFLAGS) -Wl,--end-group -lcmocka

test: $(MBEDTLS_LIBS) $(PQ_LIB) $(TEST_BIN)
	$(TEST_BIN)

debug: CFLAGS += -g -O0
debug: clean encsigtool

.PHONY: all clean test debug
