#ifndef KEEPCLIENT_INC_HTTPS_H_
#define KEEPCLIENT_INC_HTTPS_H_

#include <glib.h>

#define GOOGLE_COMPATIBLE_CIPHERS "" \
  "TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:" \
  "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:" \
  "ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:" \
  "!aNULL:!eNULL:!MD5:!RC4:!3DES:!CAMELLIA:!ARIA"

#define SSL_SUCCESS 1
#define READ_ALL_BUF_SIZE 1024
#define WRITE_ALL_BUF_SIZE 1024
#define MAX_START_LINE_LENGTH 256
#define MAX_HEADER_LINE_LENGTH 1024

typedef enum {
  HTTP_ERROR_NONE = 0,
  HTTP_ERROR_PARSE_URL = -1,
  HTTP_ERROR_SOCKET_PARSE_HOST = -2,
  HTTP_ERROR_SOCKET_CREATE = -3,
  HTTP_ERROR_SOCKET_CONNECT = -4,
  HTTP_ERROR_GET_CONNECTION_TYPE = -5,
  HTTP_ERROR_GET_CONNECTION_PROXY = -6,
  HTTP_ERROR_PROXY_MESSAGE_SEND = -7,
  HTTP_ERROR_PROXY_CONNECT = -8,
  HTTP_ERROR_GET_SSL_METHOD = -9,
  HTTP_ERROR_CREATE_SSL_CONTEXT = -10,
  HTTP_ERROR_CREATE_SSL = -11,
  HTTP_ERROR_SET_SSL_FD = -12,
  HTTP_ERROR_SET_CIPHERS = -13,
  HTTP_ERROR_SET_TLS_HOST = -14,
  HTTP_ERROR_CONNECT = -15,
  HTTP_ERROR_SEND = -16
} http_error;

typedef struct http_buffer http_buffer;
struct http_buffer {
  char *data;
  size_t len;
};

typedef struct http_response http_response;
struct http_response {
  char *protocol;
  int status_code;
  char *status_message;
  GHashTable *headers;
  char *body;
};

void http_initialize();
void http_terminate();
const char *http_error_message(http_error error);
char *http_urlencode(const char *);
http_error https_post(const char *, GHashTable *, const char *, http_response **);
void http_response_free(http_response *);

#endif //KEEPCLIENT_INC_HTTPS_H_
