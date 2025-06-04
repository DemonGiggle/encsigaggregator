MBEDTLS_DIR ?= libs/mbedtls
PQCLEAN_DIR ?= libs/pqclean

CFLAGS += -Iinclude -I$(MBEDTLS_DIR)/include \
          -I$(PQCLEAN_DIR)/crypto_sign/mldsa-87/clean
LDFLAGS += -L$(MBEDTLS_DIR)/library -lmbedtls -lmbedcrypto -lmbedx509

SRC = src/crypto.c
OBJ = $(SRC:.c=.o)

all: libcrypto.a

libcrypto.a: $(OBJ)
	ar rcs $@ $^

clean:
	rm -f $(OBJ) libcrypto.a

.PHONY: all clean
