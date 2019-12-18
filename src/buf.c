#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "buf.h"



static void
buf_reserve(buf_t *b, size_t len)
{
  if(b->size + len > b->capacity) {
    b->capacity = MAX(b->size + len, b->capacity * 2);
    b->data = realloc(b->data, b->capacity);
  }
}


void
buf_append(buf_t *b, const void *data, size_t len)
{
  buf_reserve(b, len + 1); // Make space for extra 0 we add at the end
  memcpy(b->data + b->size, data, len);
  b->size += len;
  ((uint8_t *)b->data)[b->size] = 0;
}

void
buf_append_str(buf_t *b, const char *str)
{
  buf_append(b, str, strlen(str));
}


void
buf_append_u8(buf_t *b, uint8_t u8)
{
  buf_append(b, &u8, sizeof(u8));
}


void
buf_reset(buf_t *b)
{
  b->size = 0;
}

void
buf_free(buf_t *b)
{
  free(b->data);
  memset(b, 0, sizeof(buf_t));
}

void
buf_pop(buf_t *b, size_t bytes)
{
  if(bytes == b->size)
    return buf_reset(b);

  assert(bytes < b->size);

  memmove(b->data, b->data + bytes, b->size - bytes);
  b->size -= bytes;
}

void
buf_append_and_escape_jsonstr(buf_t *b, const char *str, int escape_slash)
{
  const char *s = str;

  buf_append(b, "\"", 1);

  while(*s != 0) {
    if(*s == '"' || (escape_slash && *s == '/') || *s == '\\' || *s < 32) {
      buf_append(b, str, s - str);

      if(*s == '"')
	buf_append(b, "\\\"", 2);
      else if(*s == '/')
	buf_append(b, "\\/", 2);
      else if(*s == '\n')
	buf_append(b, "\\n", 2);
      else if(*s == '\r')
	buf_append(b, "\\r", 2);
      else if(*s == '\t')
	buf_append(b, "\\t", 2);
      else if(*s == '\\')
        buf_append(b, "\\\\", 2);
      else {
        char tmp[8];
        buf_append(b, tmp, snprintf(tmp, sizeof(tmp), "\\u%04x", *s));
      }
      s++;
      str = s;
    } else {
      s++;
    }
  }
  buf_append(b, str, s - str);
  buf_append(b, "\"", 1);
}


void
buf_printf(buf_t *b, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int size = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);

  if(size < 0)
    return;

  buf_reserve(b, size + 1);
  va_start(ap, fmt);
  vsnprintf(b->data + b->size, size + 1, fmt, ap);
  va_end(ap);
  b->size += size;
}
