MBEDTLS_DIR ?= libs/mbedtls
PQCLEAN_DIR ?= libs/pqclean

CFLAGS += -Iinclude -I$(MBEDTLS_DIR)/include \
        -I$(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean \
        -DMBEDTLS_CONFIG_FILE='"mbedtls_custom_config.h"'
LDFLAGS += -L$(MBEDTLS_DIR)/library -lmbedtls -lmbedcrypto -lmbedx509 \
           -L$(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean -lml-dsa-87_clean

SRC = src/crypto.c
OBJ = $(SRC:.c=.o)
TOOL_SRC = src/main.c
TOOL_OBJ = $(TOOL_SRC:.c=.o)

all: libcrypto.a encsigtool

libcrypto.a: $(OBJ)
	ar rcs $@ $^

clean:
	rm -f $(OBJ) $(TOOL_OBJ) libcrypto.a encsigtool

encsigtool: libcrypto.a $(TOOL_OBJ)
	$(CC) $(CFLAGS) -o $@ $(TOOL_OBJ) libcrypto.a $(LDFLAGS)

.PHONY: all clean
