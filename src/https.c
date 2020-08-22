/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 */

#include <net_connection.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <dlog.h>
#include "keepclient.h"
#include "https.h"

static connection_h connection;
static char hex[] = "0123456789ABCDEF";

void http_initialize() {
  int err;
  if (CONNECTION_ERROR_NONE != (err = connection_create(&connection))) {
    dlog_print(DLOG_ERROR, LOG_TAG, "[connection_create] failed (%d): %s", err, get_error_message(err));
    return;
  }
}

void http_terminate() {
  int err;
  if (CONNECTION_ERROR_NONE != (err = connection_destroy(connection))) {
    dlog_print(DLOG_ERROR, LOG_TAG, "[connection_destroy] failed (%d): %s", err, get_error_message(err));
  }
  connection = NULL;
}

const char *http_error_message(http_error error) {
  switch (error) {
    case HTTP_ERROR_NONE:
      return "No error";
    case HTTP_ERROR_PARSE_URL:
      return "Failed to parse url";
    case HTTP_ERROR_SOCKET_PARSE_HOST:
      return "Failed to parse socket host";
    case HTTP_ERROR_SOCKET_CREATE:
      return "Failed to create socket";
    case HTTP_ERROR_SOCKET_CONNECT:
      return "Failed to connect to socket";
    case HTTP_ERROR_GET_CONNECTION_TYPE:
      return "Failed to get connection type";
    case HTTP_ERROR_GET_CONNECTION_PROXY:
      return "Failed to get connection proxy";
    case HTTP_ERROR_PROXY_MESSAGE_SEND:
      return "Failed to send message to proxy";
    case HTTP_ERROR_PROXY_CONNECT:
      return "Failed to connect to proxy";
    case HTTP_ERROR_GET_SSL_METHOD:
      return "Failed to select connection method";
    case HTTP_ERROR_CREATE_SSL_CONTEXT:
      return "Failed to create SSL context";
    case HTTP_ERROR_CREATE_SSL:
      return "Failed to create SSL";
    case HTTP_ERROR_SET_SSL_FD:
      return "Failed to set SSL file descriptor";
    case HTTP_ERROR_SET_CIPHERS:
      return "Failed to set cipher list";
    case HTTP_ERROR_SET_TLS_HOST:
      return "Failed to set TLS hostname";
    case HTTP_ERROR_CONNECT:
      return "Failed to connect";
    case HTTP_ERROR_SEND:
      return "Failed to send";
    default:
      return "Unknown error";
  }
}

char *http_urlencode(const char *str) {
  char *pstr = (char *) str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
      *pbuf++ = *pstr;
    } else if (*pstr == ' ') {
      *pbuf++ = '+';
    } else {
      *pbuf++ = '%', *pbuf++ = hex[*pstr >> 4], *pbuf++ = hex[*pstr & 15u];
    }
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

static void http_buffer_append(http_buffer *buffer, const char *data, size_t data_len) {
  buffer->data = realloc(buffer->data, buffer->len + data_len + 1);
  if (buffer->data == NULL) {
    dlog_print(DLOG_ERROR, LOG_TAG, "[http_buffer_append] failed: not enough memory");
    return;
  }
  memcpy(&(buffer->data[buffer->len]), data, data_len);
  buffer->len += data_len;
  buffer->data[buffer->len] = '\0';
}

static int SSL_should_retry(SSL *ssl, int ret_code) {
  switch (SSL_get_error(ssl, ret_code)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_CONNECT:
      return true;
    default:
      return false;
  };
}

static size_t SSL_write_all(SSL *ssl, http_buffer *buffer) {
  size_t data_len, data_written = 0;
  int ret_code;
  do {
    ret_code = SSL_write_ex(ssl, &(buffer->data[data_written]), MIN(WRITE_ALL_BUF_SIZE, buffer->len), &data_len);
    buffer->len -= data_len;
    data_written += data_len;
  } while (data_len > 0 || SSL_should_retry(ssl, ret_code));
  return data_written;
}

static char *SSL_read_all(SSL *ssl) {
  http_buffer response = { .data = malloc(1), .len = 0 };
  size_t data_len;
  char data[READ_ALL_BUF_SIZE] = {};
  int ret_code;
  do {
    bzero(data, sizeof(data));
    ret_code = SSL_read_ex(ssl, data, sizeof(data), &data_len);
    http_buffer_append(&response, data, data_len);
  } while (ret_code > 0 || SSL_should_retry(ssl, ret_code));
  return response.data;
}

static int open_socket_connection(const char *host, int port) {
  struct hostent *server = gethostbyname(host);
  if (server == NULL) {
    return HTTP_ERROR_SOCKET_PARSE_HOST;
  }
  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    return HTTP_ERROR_SOCKET_CREATE;
  }
  struct sockaddr_in server_addr;
  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  bcopy(server->h_addr, &server_addr.sin_addr.s_addr, server->h_length);
  if (connect(socket_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    close(socket_fd);
    dlog_print(DLOG_ERROR, LOG_TAG, "[open_socket_connection] failed to connect to socket: %s:%d", host, port);
    return HTTP_ERROR_SOCKET_CONNECT;
  }
  return socket_fd;
}

static int open_http_connection(const char *host, int port) {
  int err;
  connection_type_e connection_type;
  if (CONNECTION_ERROR_NONE != (err = connection_get_type(connection, &connection_type))) {
    dlog_print(DLOG_ERROR, LOG_TAG, "[connection_get_type] failed (%d): %s", err, get_error_message(err));
    return HTTP_ERROR_GET_CONNECTION_TYPE;
  }
  if (connection_type > CONNECTION_TYPE_WIFI) {
    char *proxy_address;
    if (CONNECTION_ERROR_NONE != (err = connection_get_proxy(connection, CONNECTION_ADDRESS_FAMILY_IPV4, &proxy_address))) {
      dlog_print(DLOG_ERROR, LOG_TAG, "[connection_get_proxy] failed (%d): %s", err, get_error_message(err));
      return HTTP_ERROR_GET_CONNECTION_PROXY;
    }
    char *proxy_host = strtok(proxy_address, ":");
    int proxy_port = atoi(strtok(NULL, ":"));
    int proxy_fd = open_socket_connection(proxy_host, proxy_port);
    free(proxy_address);
    if (proxy_fd >= 0) {
      char buf[MAX_START_LINE_LENGTH] = {};
      snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\n\r\n", host, port);
      if (strlen(buf) != write(proxy_fd, buf, strlen(buf))) {
        close(proxy_fd);
        return HTTP_ERROR_PROXY_MESSAGE_SEND;
      }
      bzero(buf, sizeof(buf));
      if (read(proxy_fd, buf, sizeof(buf) - 1) <= 0 || NULL == strstr(buf, " 200 ")) {
        close(proxy_fd);
        return HTTP_ERROR_PROXY_CONNECT;
      }
    }
    return proxy_fd;
  } else {
    return open_socket_connection(host, port);
  }
}

static void add_header(gpointer key, gpointer value, gpointer data) {
  struct http_buffer *request = data;
  char header[MAX_HEADER_LINE_LENGTH] = {};
  snprintf(header, sizeof(header), "%s: %s\r\n", (char *) key, (char *) value);
  http_buffer_append(request, header, strlen(header));
}

static http_response *parse_http_response(const char *raw) {
  http_response *response = calloc(1, sizeof(http_response));
  // protocol
  size_t protocol_len = strcspn(raw, " ");
  response->protocol = calloc(protocol_len + 1, sizeof(char));
  strncpy(response->protocol, raw, protocol_len);
  raw += protocol_len + 1;
  // status code
  size_t status_code_len = strcspn(raw, " ");
  response->status_code = (int) strtol(raw, NULL, 10);
  raw += status_code_len + 1;
  // status message
  size_t status_message_len = strcspn(raw, "\r\n");
  response->status_message = calloc(status_message_len + 1, sizeof(char));
  strncpy(response->status_message, raw, status_message_len);
  raw += status_message_len + 2;
  // headers
  response->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  while (!(raw[0] == '\r' && raw[1] == '\n')) {
    // name
    size_t name_len = strcspn(raw, ":");
    gchar *name = g_strndup(raw, name_len);
    raw += name_len + 1;
    while (*raw == ' ') raw++;
    // value
    size_t value_len = strcspn(raw, "\r\n");
    g_hash_table_insert(response->headers, name, g_strndup(raw, value_len));
    raw += value_len + 2;
  }
  raw += 2;
  // body
  size_t body_len = strlen(raw);
  response->body = calloc(body_len + 1, sizeof(char));
  strncpy(response->body, raw, body_len);
  return response;
}

http_error https_post(const char *url, GHashTable *headers, const char *body, http_response **response) {
  http_error ret = HTTP_ERROR_NONE;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  int http_fd, port;
  char host[100] = {}, path[100] = {};
  if (3 != sscanf(url, "https://%99[^:]:%5d/%99[^\n]", host, &port, path)) {
    ret = HTTP_ERROR_PARSE_URL;
    goto end;
  }
  const SSL_METHOD *ssl_method = SSLv23_method();
  if (NULL == ssl_method) {
    ret = HTTP_ERROR_GET_SSL_METHOD;
    goto end;
  }
  ctx = SSL_CTX_new(ssl_method);
  if (NULL == ctx) {
    ret = HTTP_ERROR_CREATE_SSL_CONTEXT;
    goto end;
  }
  SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  ssl = SSL_new(ctx);
  if (NULL == ssl) {
    ret = HTTP_ERROR_CREATE_SSL;
    goto ssl_ctx_free;
  }
  http_fd = open_http_connection(host, port);
  if (http_fd < 0) {
    ret = http_fd;
    goto ssl_free;
  }
  if (SSL_SUCCESS != SSL_set_fd(ssl, http_fd)) {
    ret = HTTP_ERROR_SET_SSL_FD;
    goto http_fd_free;
  }
  if (SSL_SUCCESS != SSL_set_cipher_list(ssl, GOOGLE_COMPATIBLE_CIPHERS)) {
    ret = HTTP_ERROR_SET_CIPHERS;
    goto http_fd_free;
  }
  if (SSL_SUCCESS != SSL_set_tlsext_host_name(ssl, host)) {
    ret = HTTP_ERROR_SET_TLS_HOST;
    goto http_fd_free;
  }
  if (SSL_SUCCESS != SSL_connect(ssl)) {
    ret = HTTP_ERROR_CONNECT;
    goto http_fd_free;
  }
  char start_line[MAX_START_LINE_LENGTH] = {};
  snprintf(start_line, sizeof(start_line), "POST /%s HTTP/1.0\r\n", path);
  http_buffer request = { .data = malloc(1), .len = 0 };
  http_buffer_append(&request, start_line, strlen(start_line));
  g_hash_table_insert(headers, "Host", g_strdup(host));
  g_hash_table_insert(headers, "Content-Length", g_strdup_printf("%d", (int) strlen(body)));
  if (NULL == g_hash_table_lookup(headers, "Content-Type")) {
    g_hash_table_insert(headers, "Content-Type", g_strdup("application/x-www-form-urlencoded"));
  }
  g_hash_table_foreach(headers, add_header, &request);
  http_buffer_append(&request, "\r\n", 2);
  http_buffer_append(&request, body, strlen(body));
  // printf("------------\n| REQUEST  |\n------------\n%s\n", request.data);
  if (request.len != SSL_write_all(ssl, &request)) {
    ret = HTTP_ERROR_SEND;
    goto request_data_free;
  }
  char *raw_response = SSL_read_all(ssl);
  // printf("------------\n| RESPONSE |\n------------\n%s\n===================================================\n\n\n", raw_response);
  *response = parse_http_response(raw_response);
  free(raw_response);
request_data_free:
  free(request.data);
http_fd_free:
  close(http_fd);
ssl_free:
  SSL_free(ssl);
ssl_ctx_free:
  SSL_CTX_free(ctx);
end:
  return ret;
}

void http_response_free(http_response *response) {
  free(response->protocol);
  free(response->status_message);
  g_hash_table_destroy(response->headers);
  free(response->body);
  free(response);
}
