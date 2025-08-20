#include "util.h"
#include <stdio.h>
#include <stdlib.h>

int read_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *tmp = malloc(sz ? sz : 1);
    if (!tmp) {
        fclose(f);
        return -1;
    }
    if (fread(tmp, 1, sz, f) != (size_t)sz) {
        fclose(f);
        free(tmp);
        return -1;
    }
    fclose(f);
    *buf = tmp;
    *len = sz;
    return 0;
}
