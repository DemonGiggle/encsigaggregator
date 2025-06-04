MBEDTLS_DIR ?= libs/mbedtls
PQCLEAN_DIR ?= libs/pqclean

CFLAGS += -Iinclude -I$(MBEDTLS_DIR)/include \
        -I$(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean \
        -I$(PQCLEAN_DIR)/common \
        -DMBEDTLS_CONFIG_FILE='"mbedtls_custom_config.h"'
LDFLAGS += -L$(MBEDTLS_DIR)/library -lmbedtls -lmbedcrypto -lmbedx509 \
           -L$(PQCLEAN_DIR)/crypto_sign/ml-dsa-87/clean -lml-dsa-87_clean

SRC = src/crypto.c \
       $(PQCLEAN_DIR)/common/randombytes.c \
       $(PQCLEAN_DIR)/common/fips202.c \
       $(PQCLEAN_DIR)/common/sha2.c \
       $(PQCLEAN_DIR)/common/nistseedexpander.c \
       $(PQCLEAN_DIR)/common/sp800-185.c
OBJ = $(SRC:.c=.o)
TOOL_SRC = src/main.c src/cliopts.c
TOOL_OBJ = $(TOOL_SRC:.c=.o)

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
	rm -f $(OBJ) $(TOOL_OBJ) libcrypto.a encsigtool

encsigtool: libcrypto.a $(TOOL_OBJ)
	$(CC) $(CFLAGS) -o $@ $(TOOL_OBJ) libcrypto.a $(LDFLAGS)

.PHONY: all clean
