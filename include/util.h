#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Read the entire file at path into a newly allocated buffer.
 * On success, *buf will point to the allocated data and *len contains
 * the number of bytes read. The caller is responsible for freeing *buf.
 * Returns 0 on success, -1 on failure.
 */
int read_file(const char *path, uint8_t **buf, size_t *len);

#endif /* UTIL_H */
