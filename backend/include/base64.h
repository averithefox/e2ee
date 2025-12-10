#pragma once

#include <stddef.h>
#include <sys/types.h>

char *b64_decode(const char *b64, ssize_t b64_len, size_t *out_len);
