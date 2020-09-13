#ifndef KEEPCLIENT_INC_LOG_H_
#define KEEPCLIENT_INC_LOG_H_

#define MAX_LOG_LINE_LENGTH 1024

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
