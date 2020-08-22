/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 * This software may be distributed under the terms of the BSD license.
 */

#include <stdlib.h>
#include <string.h>
#include "base64.h"

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char base64_urlsafe_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data, or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
static unsigned char *base64_encode_with_char_table(const unsigned char *src, size_t len, size_t *out_len, const unsigned char char_table[]) {
  unsigned char *out, *pos;
  const unsigned char *end, *in;
  size_t olen;

  olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
  olen++; /* nul termination */
  if (olen < len) return NULL; /* integer overflow */
  out = malloc(olen);
  if (out == NULL) return NULL;

  end = src + len;
  in = src;
  pos = out;
  while (end - in >= 3) {
    *pos++ = char_table[in[0] >> 2];
    *pos++ = char_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = char_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = char_table[in[2] & 0x3f];
    in += 3;
  }

  if (end - in) {
    *pos++ = char_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = char_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    } else {
      *pos++ = char_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
      *pos++ = char_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
  }

  *pos = '\0';
  if (out_len) *out_len = pos - out;
  return out;
}

unsigned char *base64_encode(const unsigned char *src, size_t len, size_t *out_len) {
  return base64_encode_with_char_table(src, len, out_len, base64_table);
}

unsigned char *base64_urlsafe_encode(const unsigned char *src, size_t len, size_t *out_len) {
  return base64_encode_with_char_table(src, len, out_len, base64_urlsafe_table);
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data, or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char *base64_decode(const unsigned char *src, size_t len, size_t *out_len) {
  unsigned char dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (unsigned char) i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[src[i]] != 0x80) count++;
  }

  if (count == 0 || count % 4) return NULL;

  olen = count / 4 * 3;
  pos = out = malloc(olen);
  if (out == NULL) return NULL;

  count = 0;
  for (i = 0; i < len; i++) {
    tmp = dtable[src[i]];
    if (tmp == 0x80) continue;
    if (src[i] == '=') pad++;
    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
        if (pad == 1) pos--;
        else if (pad == 2) pos -= 2;
        else {
          /* Invalid padding */
          free(out);
          return NULL;
        }
        break;
      }
    }
  }

  *out_len = pos - out;
  return out;
}
