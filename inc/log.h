#ifndef KEEPCLIENT_INC_LOG_H_
#define KEEPCLIENT_INC_LOG_H_

#ifdef  LOG_TAG
#undef  LOG_TAG
#endif
#define LOG_TAG "keepclient"

#define MAX_LOG_LINE_LENGTH 1024

#define ANSI_COLOR_RED    "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_GRAY   "\x1b[90m"
#define ANSI_COLOR_RESET  "\x1b[0m"

typedef enum {
  LOG_UNKNOWN = 0, /**< Keep this always at the start */
  LOG_DEFAULT,     /**< Default */
  LOG_VERBOSE,     /**< Verbose */
  LOG_DEBUG,       /**< Debug */
  LOG_INFO,        /**< Info */
  LOG_WARN,        /**< Warning */
  LOG_ERROR,       /**< Error */
  LOG_FATAL,       /**< Fatal */
  LOG_SILENT,      /**< Silent */
  LOG_PRIO_MAX     /**< Keep this always at the end. */
} log_level;

int log_print(log_level, const char *, ...);

#endif //KEEPCLIENT_INC_LOG_H_
