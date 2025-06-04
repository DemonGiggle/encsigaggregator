MBEDTLS_DIR ?= libs/mbedtls
PQCLEAN_DIR ?= libs/pqclean

CFLAGS += -Iinclude -I$(MBEDTLS_DIR)/include \
          -I$(PQCLEAN_DIR)/crypto_sign/mldsa-87/clean
LDFLAGS += -L$(MBEDTLS_DIR)/library -lmbedtls -lmbedcrypto -lmbedx509

SRC = src/aggregator.c
OBJ = $(SRC:.c=.o)

all: libaggregator.a

libaggregator.a: $(OBJ)
	ar rcs $@ $^

clean:
	rm -f $(OBJ) libaggregator.a

.PHONY: all clean
