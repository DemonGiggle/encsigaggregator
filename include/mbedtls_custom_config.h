#ifndef MBEDTLS_CUSTOM_CONFIG_H
#define MBEDTLS_CUSTOM_CONFIG_H

/*
 * This configuration file enables the features used by encsigaggregator.
 * It is based on the default Mbed TLS configuration for 3.6.0 with
 * LMS private-key operations enabled.
 */

#include "mbedtls/mbedtls_config.h"

/* enable LMS private key operations */
#define MBEDTLS_LMS_PRIVATE

#endif /* MBEDTLS_CUSTOM_CONFIG_H */
