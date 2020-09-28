/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 */

#include "log.h"

#ifdef EMULATOR
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

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

static const char *level2color(log_level level) {
  switch (level) {
    case LOG_ERROR:
    case LOG_FATAL:
      return ANSI_COLOR_RED;
    case LOG_WARN:
      return ANSI_COLOR_YELLOW;
    case LOG_DEBUG:
      return ANSI_COLOR_GRAY;
    default:
      return "";
  }
}

static const char *get_timestamp(char *timestamp) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  struct tm *tm_time = localtime(&tv.tv_sec);
  size_t time_len = strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", tm_time);
  snprintf(timestamp + time_len, 5, ".%03ld", tv.tv_usec / 1000);
  return timestamp;
}
#else
#include <dlog.h>
#endif // EMULATOR

int log_print(log_level level, const char *fmt, ...) {
  int ret;
  va_list ap;
  va_start(ap, fmt);
#ifdef EMULATOR
  char format[MAX_LOG_LINE_LENGTH];
  const char *level_str = level2str(level);
  const char *level_color = level2color(level);
  int padding = (int) ((7 - strlen(level_str)) / 2);
  char timestamp[25] = {};
  get_timestamp(timestamp);
  snprintf(format, sizeof(format), "%s [%*s%s%s%s%*s] %s\n", timestamp, padding, "", level_color, level_str,
      strcmp(level_color, "") == 0 ? "" : ANSI_COLOR_RESET, padding + 1 - (int) (strlen(level_str) % 2), "", fmt);
  ret = vprintf(format, ap);
#else
  ret = dlog_vprint((log_priority) level, LOG_TAG, fmt, ap);
#endif // EMULATOR
  va_end (ap);
  return ret;
}
