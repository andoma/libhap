#pragma once

#include <sys/param.h>

typedef struct buf {
  void *data;
  size_t size;
  size_t capacity;
} buf_t;


void buf_append(buf_t *b, const void *data, size_t len);

void buf_append_str(buf_t *b, const char *str);

void buf_reset(buf_t *b);

void buf_free(buf_t *b);

void buf_pop(buf_t *b, size_t bytes);

void buf_append_u8(buf_t *b, uint8_t u8);

void buf_append_and_escape_jsonstr(buf_t *b, const char *str, int escape_slash);

void buf_printf(buf_t *b, const char *fmt, ...)
  __attribute__((format (printf, 2, 3)));

#define scoped_buf_t buf_t __attribute__((cleanup(buf_free)))

