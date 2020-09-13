/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 */

#include <dlog.h>
#include "log.h"
#include "keepclient.h"

#ifdef EMULATOR
static const char *level2str(log_level level) {
  switch (level) {
    case LOG_UNKNOWN:
      return "unknown";
    case LOG_DEFAULT:
      return "default";
    case LOG_VERBOSE:
      return "verbose";
    case LOG_DEBUG:
      return "debug";
    case LOG_INFO:
      return "info";
    case LOG_WARN:
      return "warn";
    case LOG_ERROR:
      return "error";
    case LOG_FATAL:
      return "fatal";
    case LOG_SILENT:
      return "silent";
    case LOG_PRIO_MAX:
      return "priomax";
    default:
      return "unknown";
  }
}
#endif // EMULATOR

int log_print(log_level level, const char *fmt, ...) {
  int ret;
  va_list ap;
  va_start(ap, fmt);
#ifndef EMULATOR
  ret = dlog_vprint((log_priority) level, LOG_TAG, fmt, ap);
#else
  char format[MAX_LOG_LINE_LENGTH];
  const char *level_str = level2str(level);
  int padding = (int) ((7 - strlen(level_str)) / 2);
  snprintf(format, sizeof(format), "[%*s%s%*s] %s\n",
      padding + 1 - (strlen(level_str) % 2), "", level_str, padding, "", fmt);
  ret = vprintf(format, ap);
#endif // EMULATOR
  va_end (ap);
  return ret;
}
