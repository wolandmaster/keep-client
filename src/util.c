/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 */

#include <Elementary.h>
#include "util.h"

char *text_escape(const char *text) {
  if (!text) return NULL;
  Eina_Strbuf *buf = eina_strbuf_new();
  const char *text_end = text + strlen(text);
  while (text < text_end) {
    int advance;
    const char *escaped = evas_textblock_string_escape_get(text, &advance);
    if (escaped) {
      eina_strbuf_append(buf, escaped);
    } else {
      advance = 1;
      if (text[0] == '\n') {
        eina_strbuf_append(buf, "<br/>");
      } else if (text[0] == '\t') {
        eina_strbuf_append(buf, "<tab/>");
      } else {
        eina_strbuf_append_char(buf, text[0]);
      }
    }
    text += advance;
  }
  char *ret = eina_strbuf_string_steal(buf);
  eina_strbuf_free(buf);
  return ret;
}
