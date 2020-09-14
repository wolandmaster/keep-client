/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 *
 * Based on Simon Weber's Google Play Services OAuth python library.
 * (https://github.com/simon-weber/gpsoauth)
 */

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <glib.h>
#include "keepclient.h"
#include "log.h"
#include "gpsoauth.h"
#include "base64.h"
#include "https.h"

static int bytes_to_int(const unsigned char *bytes) {
  return (bytes[0] << 24u) + (bytes[1] << 16u) + (bytes[2] << 8u) + bytes[3];
}

static RSA *rsa_from_key(const char *key) {
  unsigned char buf[4];
  memcpy(buf, key, 4);
  int modulus_len = bytes_to_int(buf);
  unsigned char modulus_data[modulus_len];
  memcpy(modulus_data, key + 4, modulus_len);
  BIGNUM *modulus = BN_bin2bn(modulus_data, modulus_len, NULL);
  memcpy(buf, key + 4 + modulus_len, 4);
  int exponent_len = bytes_to_int(buf);
  unsigned char exponent_data[exponent_len];
  memcpy(exponent_data, key + 4 + modulus_len + 4, exponent_len);
  BIGNUM *exponent = BN_bin2bn(exponent_data, exponent_len, NULL);
  RSA *rsa = RSA_new();
  RSA_set0_key(rsa, modulus, exponent, NULL);
  return rsa;
}

static unsigned char *hash_of_key(unsigned char *key, size_t key_len) {
  unsigned char *hash = calloc(SHA_DIGEST_LENGTH, sizeof(unsigned char));
  SHA1(key, key_len, hash);
  return hash;
}

static unsigned char *encrypt_credential(const char *email, const char *password, RSA *rsa, size_t *out_len) {
  size_t email_len = strlen((const char *) email);
  size_t password_len = strlen((const char *) password);
  unsigned char credential[email_len + password_len + 1];
  memcpy(credential, email, email_len);
  credential[email_len] = '\0';
  memcpy(credential + email_len + 1, password, password_len);
  unsigned char *encrypted_credential = (unsigned char *) calloc(RSA_size(rsa), sizeof(unsigned char));
  if (-1 == (*out_len = RSA_public_encrypt((int) sizeof(credential), credential, encrypted_credential, rsa, RSA_PKCS1_OAEP_PADDING))) {
    log_print(LOG_ERROR, "encrypt credential RSA_public_encrypt failed");
    free(encrypted_credential);
    return NULL;
  }
  return encrypted_credential;
}

static unsigned char *signature(const char *email, const char *password, const char *base64_key) {
  size_t key_len, credential_len, base64_signature_len;
  unsigned char *key = base64_decode((unsigned char *) base64_key, strlen(base64_key), &key_len);
  RSA *rsa = rsa_from_key((const char *) key);
  unsigned char *key_hash = hash_of_key(key, key_len);
  free(key);
  unsigned char *signature = calloc(1 + 4, sizeof(unsigned char));
  signature[0] = '\0';
  memcpy(signature + 1, key_hash, 4);
  free(key_hash);
  unsigned char *encrypted_credential = encrypt_credential(email, password, rsa, &credential_len);
  RSA_free(rsa);
  signature = realloc(signature, 1 + 4 + credential_len);
  memcpy(signature + 1 + 4, encrypted_credential, credential_len);
  free(encrypted_credential);
  unsigned char *base64_signature = base64_urlsafe_encode(signature, 1 + 4 + credential_len, &base64_signature_len);
  free(signature);
  return base64_signature;
}

static void parse_auth_response(const char *body, GHashTable *response_data) {
  while (body[0] != '\0') {
    // key
    size_t key_len = strcspn(body, "=");
    gchar *key = g_strndup(body, key_len);
    body += key_len + 1;
    // value
    size_t value_len = strcspn(body, "\n");
    g_hash_table_insert(response_data, key, g_strndup(body, value_len));
    body += value_len + MIN(strlen(body) - value_len, 1);
  }
}

static GHashTable *perform_auth_request(const char *body) {
  GHashTable *headers = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
  g_hash_table_insert(headers, "User-Agent", g_strdup(HTTPS_USER_AGENT));
  g_hash_table_insert(headers, "Accept-Encoding", g_strdup(""));
  g_hash_table_insert(headers, "Connection", g_strdup("close"));
  int err;
  http_response *response;
  GHashTable *response_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  if (HTTP_ERROR_NONE != (err = https_post(GOOGLE_PLAY_SERVICES_AUTH_URL, headers, body, &response))) {
    log_print(LOG_ERROR, "perform google play services auth request failed (%d): %s", err, http_error_message(err));
    g_hash_table_insert(response_data, g_strdup(HTTPS_ERROR_KEY), g_strdup(http_error_message(err)));
  } else {
    parse_auth_response(response->body, response_data);
    http_response_free(response);
  }
  g_hash_table_destroy(headers);
  return response_data;
}

GHashTable *gpsoauth_perform_master_login(const char *email, const char *password, const char *android_id) {
  char *email_urlencode = http_urlencode(email);
  unsigned char *base64_signature = signature(email, password, ANDROID_KEY_7_3_29);
  char *base64_signature_urlencode = http_urlencode((char *) base64_signature);
  char body[512] = {};
  snprintf(body, sizeof(body),
      "accountType=HOSTED_OR_GOOGLE&Email=%s&has_permission=1&add_account=1&EncryptedPasswd=%s&"
      "service=ac2dm&source=android&androidId=%s&device_country=us&operatorCountry=us&lang=en&sdk_version=17",
      email_urlencode, base64_signature_urlencode, android_id);
  free(base64_signature_urlencode);
  free(base64_signature);
  free(email_urlencode);
  return perform_auth_request(body);
}

GHashTable *gpsoauth_perform_oauth(const char *email, const char *master_token, const char *android_id,
    const char *service, const char *app, const char *client_sig) {
  char *email_urlencode = http_urlencode(email);
  char *master_token_urlencode = http_urlencode(master_token);
  char *service_urlencode = http_urlencode(service);
  char body[1024] = {};
  snprintf(body, sizeof(body),
      "accountType=HOSTED_OR_GOOGLE&Email=%s&has_permission=1&EncryptedPasswd=%s&service=%s&source=android&"
      "androidId=%s&app=%s&client_sig=%s&device_country=us&operatorCountry=us&lang=en&sdk_version=17",
      email_urlencode, master_token_urlencode, service_urlencode, android_id, app, client_sig);
  free(service_urlencode);
  free(master_token_urlencode);
  free(email_urlencode);
  return perform_auth_request(body);
}
