/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 *
 * Based on Kai Zhong's unofficial python client for Google Keep API.
 * (https://github.com/kiwiz/gkeepapi)
 */

#include <glib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "log.h"
#include "data.h"
#include "https.h"
#include "gpsoauth.h"
#include "gkeep.h"

static gkeep_context *context = NULL;

static void *from_json(const char *json, JsonNodeType type) {
  GError *error = NULL;
  JsonParser *parser = json_parser_new();
  json_parser_load_from_data(parser, json, -1, &error);
  if (error) {
    log_print(LOG_ERROR, "json parsing failed (%d): %s", error->code, error->message);
    g_object_unref(parser);
    g_error_free(error);
    return NULL;
  }
  JsonNode *node = json_parser_get_root(parser);
  void *target = NULL;
  if (JSON_NODE_OBJECT == type) {
    target = json_node_dup_object(node);
  } else if (JSON_NODE_ARRAY == type) {
    target = json_node_dup_array(node);
  } else {
    log_print(LOG_ERROR, "unsupported from json node type");
  }
  g_object_unref(parser);
  return target;
}

static char *to_json(void *source, JsonNodeType type) {
  JsonNode *node = json_node_new(type);
  if (JSON_NODE_OBJECT == type) {
    json_node_set_object(node, (JsonObject *) source);
  } else if (JSON_NODE_ARRAY == type) {
    json_node_set_array(node, (JsonArray *) source);
  } else {
    log_print(LOG_ERROR, "unsupported to json node type");
  }
  JsonGenerator *generator = json_generator_new();
  json_generator_set_root(generator, node);
  gsize len;
  gchar *json = json_generator_to_data(generator, &len);
  g_object_unref(generator);
  json_node_free(node);
  return json;
}

void gkeep_initialize(const char *android_id) {
  if (NULL == context) {
    srand(time(NULL)); // NOLINT(cert-msc51-cpp)
    context = calloc(1, sizeof(gkeep_context));
    context->android_id = strdup(android_id);
    context->email = data_get("email");
    context->master_token = data_get("master_token");
    context->oauth_token = data_get("oauth_token");
    char *oauth_expiry = data_get("oauth_expiry");
    if (NULL != oauth_expiry) {
      context->oauth_expiry = strtol(oauth_expiry, NULL, 10);
      free(oauth_expiry);
    } else {
      context->oauth_expiry = 0;
    }
    context->version = data_get("version");
    char *nodes = data_get("nodes");
    if (NULL != nodes) {
      context->nodes = from_json(nodes, JSON_NODE_ARRAY);
      free(nodes);
    } else {
      context->nodes = json_array_new();
    }
  }
}

void gkeep_terminate() {
  free(context->android_id);
  if (NULL != context->email) free(context->email);
  if (NULL != context->master_token) free(context->master_token);
  if (NULL != context->oauth_token) free(context->oauth_token);
  if (NULL != context->version) free(context->version);
  json_array_unref(context->nodes);
  free(context);
  context = NULL;
}

void gkeep_login(const char *email, const char *password) {
  data_set("email", email);
  GHashTable *response_data = gpsoauth_perform_master_login(email, password, context->android_id);
  if (NULL != context->email) free(context->email);
  context->email = strdup(email);
  if (NULL != context->master_token) free(context->master_token);
  gpointer master_token = g_hash_table_lookup(response_data, "Token");
  if (NULL != master_token) {
    log_print(LOG_DEBUG, "gkeep login success");
    context->master_token = strdup(master_token);
    data_set("master_token", master_token);
  } else {
    log_print(LOG_ERROR, "gkeep login failed");
    context->master_token = NULL;
    data_delete("master_token");
  }
  g_hash_table_destroy(response_data);
  context->oauth_expiry = 0;
  gkeep_oauth_refresh();
}

void gkeep_oauth_refresh() {
  if (NULL == context->oauth_token || context->oauth_expiry < time(NULL)) {
    GHashTable *response_data = gpsoauth_perform_oauth(context->email, context->master_token, context->android_id,
        KEEP_OAUTH_SCOPES, KEEP_OAUTH_APP, KEEP_OAUTH_CLIENT_SIG);
    if (NULL != context->oauth_token) free(context->oauth_token);
    gpointer oauth_token = g_hash_table_lookup(response_data, "Auth");
    gpointer oauth_expiry = g_hash_table_lookup(response_data, "Expiry");
    if (NULL != oauth_token && NULL != oauth_expiry) {
      log_print(LOG_INFO, "gkeep oauth success");
      context->oauth_token = strdup(oauth_token);
      context->oauth_expiry = strtol(oauth_expiry, NULL, 10);
      data_set("oauth_token", oauth_token);
      data_set("oauth_expiry", oauth_expiry);
    } else {
      log_print(LOG_ERROR, "gkeep oauth failed");
      context->oauth_token = NULL;
      context->oauth_expiry = 0;
      data_delete("oauth_token");
      data_delete("oauth_expiry");
    }
    g_hash_table_destroy(response_data);
  } else {
    log_print(LOG_INFO, "gkeep oauth still valid");
  }
}

static void generate_session_id(struct timeval tv, char *session_id) {
  unsigned long long epoch = (unsigned long long) (tv.tv_sec) * 1000 + (unsigned long long) (tv.tv_usec) / 1000;
  unsigned long long random = rand() % (9999999999 - 1000000000 + 1) + 1000000000;  // NOLINT(cert-msc50-cpp)
  snprintf(session_id, 29, "s--%llu--%llu", epoch, random);
}

static void get_timestamp(struct timeval tv, char *timestamp) {
  struct tm *tm_time = localtime(&tv.tv_sec);
  size_t time_len = strftime(timestamp, 20, "%Y-%m-%dT%H:%M:%S", tm_time);
  snprintf(timestamp + time_len, 6, ".%03ldZ", tv.tv_usec / 1000);
}

static JsonObject *gkeep_post_json(const char *url, JsonObject *json) {
  gkeep_oauth_refresh();
  GHashTable *headers = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
  g_hash_table_insert(headers, "Authorization", g_strdup_printf("OAuth %s", context->oauth_token));
  g_hash_table_insert(headers, "User-Agent", g_strdup(HTTPS_USER_AGENT));
  // g_hash_table_insert(headers, "Accept-Encoding", g_strdup(""));
  g_hash_table_insert(headers, "Connection", g_strdup("close"));
  g_hash_table_insert(headers, "Content-Type", g_strdup("application/json"));
  char *body = to_json(json, JSON_NODE_OBJECT);
  int err;
  JsonObject *response_json = NULL;
  http_response *response;
  if (HTTP_ERROR_NONE != (err = https_post(url, headers, body, &response))) {
    log_print(LOG_ERROR, "gkeep post json failed (%d): %s", err, http_error_message(err));
  } else {
    response_json = from_json(response->body, JSON_NODE_OBJECT);
    http_response_free(response);
  }
  g_hash_table_destroy(headers);
  free(body);
  return response_json;
}

static void gkeep_find_nodes_cb(JsonArray *array G_GNUC_UNUSED, guint index, JsonNode *json_node, gpointer data) {
  gkeep_find *find = data;
  JsonObject *node = json_node_get_object(json_node);
  if (json_object_has_member(node, find->field) && g_strcmp0(find->looking_for, json_object_get_string_member(node, find->field)) == 0) {
    g_array_append_val(find->indices, index);
  }
}

static GArray *gkeep_find_nodes(JsonArray *array, const gchar *field, const gchar *looking_for) {
  gkeep_find find = { .field = field, .looking_for = looking_for, .indices = g_array_new(FALSE, FALSE, sizeof(guint)) };
  json_array_foreach_element(array, gkeep_find_nodes_cb, &find);
  return find.indices;
}

static void gkeep_merge_node_changes_cb(JsonArray *array G_GNUC_UNUSED, guint index G_GNUC_UNUSED, JsonNode *changed_json_node, gpointer data G_GNUC_UNUSED) {
  JsonObject *changed_node = json_node_get_object(changed_json_node);
  GArray *existing_node_indices = gkeep_find_nodes(context->nodes, "id", json_object_get_string_member(changed_node, "id"));
  for (guint i = 0; i < existing_node_indices->len; i++) {
    // we already have this node, let's remove our one
    log_print(LOG_DEBUG, "gkeep merge node changes - remove node: %s", json_object_get_string_member(changed_node, "id"));
    json_array_remove_element(context->nodes, g_array_index(existing_node_indices, guint, i));
  }
  g_array_free(existing_node_indices, TRUE);
  if (json_object_has_member(changed_node, "parentId")) {
    // the parentId field is set so this is an update, let's add this node
    log_print(LOG_DEBUG, "gkeep merge node changes - add node: %s", json_object_get_string_member(changed_node, "id"));
    json_array_add_object_element(context->nodes, json_object_ref(changed_node));
  }
}

static void gkeep_merge_changes_cb(JsonObject *object G_GNUC_UNUSED, const gchar *member_name, JsonNode *member_node, gpointer data G_GNUC_UNUSED) {
  if (g_strcmp0("nodes", member_name) == 0) {
    json_array_foreach_element(json_node_get_array(member_node), gkeep_merge_node_changes_cb, NULL);
  }
}

static void add_capability(JsonArray *capabilities, char *capability_type) {
  JsonObject *capability = json_object_new();
  json_object_set_string_member(capability, "type", capability_type);
  json_array_add_object_element(capabilities, capability);
}

void gkeep_fetch_changes(JsonArray *nodes, JsonArray *labels) {
  gboolean truncated = FALSE;
  log_print(LOG_DEBUG, "gkeep fetch changes started");
  do {
    JsonObject *root = json_object_new();
    // nodes
    json_object_set_array_member(root, "nodes", NULL != nodes ? json_array_ref(nodes) : json_array_new());
    // client timestamp
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char timestamp[25] = {};
    get_timestamp(tv, timestamp);
    json_object_set_string_member(root, "clientTimestamp", timestamp);
    // request header
    JsonObject *request_header = json_object_new();
    char session_id[29] = {};
    generate_session_id(tv, session_id);
    json_object_set_string_member(request_header, "clientSessionId", session_id);
    json_object_set_string_member(request_header, "clientPlatform", "ANDROID");
    // request header: client version
    JsonObject *client_version = json_object_new();
    json_object_set_string_member(client_version, "major", "9");
    json_object_set_string_member(client_version, "minor", "9");
    json_object_set_string_member(client_version, "build", "9");
    json_object_set_string_member(client_version, "revision", "9");
    json_object_set_object_member(request_header, "clientVersion", client_version);
    // request header: capabilities
    JsonArray *capabilities = json_array_new();
    add_capability(capabilities, "NC"); // color support (send note color)
    add_capability(capabilities, "PI"); // pinned support (send note pinned)
    add_capability(capabilities, "LB"); // labels support (send note labels)
    add_capability(capabilities, "AN"); // annotations support (send annotations)
    add_capability(capabilities, "SH"); // sharing support
    add_capability(capabilities, "DR"); // drawing support
    add_capability(capabilities, "TR"); // trash support (stop setting the delete timestamp)
    add_capability(capabilities, "IN"); // indentation support (send listitem parent)
    add_capability(capabilities, "SND"); // allows modification of shared notes?
    add_capability(capabilities, "MI"); // concise blob info?
    add_capability(capabilities, "CO"); // VSS_SUCCEEDED when off?
    json_object_set_array_member(request_header, "capabilities", capabilities);
    json_object_set_object_member(root, "requestHeader", request_header);
    // target version
    if (NULL != context->version) json_object_set_string_member(root, "targetVersion", context->version);
    // labels
    if (NULL != labels) {
      JsonObject *user_info = json_object_new();
      json_object_set_array_member(user_info, "labels", json_array_ref(labels));
      json_object_set_object_member(root, "userInfo", user_info);
    }
    // perform https post
    JsonObject *changes = gkeep_post_json(KEEP_API_URL "changes", root);
    if (json_object_has_member(changes, "error")) {
      log_print(LOG_ERROR, "gkeep fetch changes failed: %s", json_object_get_string_member(
          json_object_get_object_member(changes, "error"), "message"));
    } else {
      json_object_foreach_member(changes, gkeep_merge_changes_cb, NULL);
      if (NULL != context->version) free(context->version);
      context->version = strdup(json_object_get_string_member(changes, "toVersion"));
      truncated = json_object_get_boolean_member(changes, "truncated");
    }
    json_object_unref(changes);
    json_object_unref(root);
  } while (truncated);
  log_print(LOG_DEBUG, "gkeep fetch changes finished");
  // save nodes & version
  char *persisted_version = data_get("version");
  if (NULL == persisted_version || strcmp(context->version, persisted_version) != 0) {
    char *merged_nodes = to_json(context->nodes, JSON_NODE_ARRAY);
    data_set("nodes", merged_nodes);
    free(merged_nodes);
    data_set("version", context->version);
  }
  if (NULL != persisted_version) {
    free(persisted_version);
  }
}

static gint gkeep_sort_node_cb(gconstpointer a, gconstpointer b, gpointer data) {
  JsonArray *nodes = data;
  JsonObject *node_a = json_array_get_object_element(nodes, *(guint *) a);
  JsonObject *node_b = json_array_get_object_element(nodes, *(guint *) b);
  if (json_object_has_member(node_a, "isPinned") && json_object_has_member(node_b, "isPinned")) {
    gint sort_by_pinned = json_object_get_boolean_member(node_b, "isPinned") - json_object_get_boolean_member(node_a, "isPinned");
    if (sort_by_pinned != 0) return sort_by_pinned;
  }
  if (json_object_has_member(node_a, "checked") && json_object_has_member(node_b, "checked")) {
    gint sort_by_checked = json_object_get_boolean_member(node_a, "checked") - json_object_get_boolean_member(node_b, "checked");
    if (sort_by_checked != 0) return sort_by_checked;
  }
  return strcmp(json_object_get_string_member(node_b, "sortValue"), json_object_get_string_member(node_a, "sortValue"));
}

JsonObject *gkeep_get_node_by_id(const char *id) {
  GArray *node_indices = gkeep_find_nodes(context->nodes, "id", id);
  // TODO: error on zero / more than one match
  JsonObject *node = json_array_get_object_element(context->nodes, g_array_index(node_indices, guint, 0));
  g_array_free(node_indices, TRUE);
  return node;
}

void gkeep_foreach_parent_node(gkeep_foreach_cb callback, void *data) {
  GArray *node_indices = g_array_new(FALSE, FALSE, sizeof(guint));
  GArray *list_node_indices = gkeep_find_nodes(context->nodes, "type", "LIST");
  g_array_append_vals(node_indices, list_node_indices->data, list_node_indices->len);
  g_array_free(list_node_indices, TRUE);
  GArray *note_node_indices = gkeep_find_nodes(context->nodes, "type", "NOTE");
  g_array_append_vals(node_indices, note_node_indices->data, note_node_indices->len);
  g_array_free(note_node_indices, TRUE);
  g_array_sort_with_data(node_indices, gkeep_sort_node_cb, context->nodes);
  for (guint index = 0; index < node_indices->len; index++) {
    JsonObject *node = json_array_get_object_element(context->nodes, g_array_index(node_indices, guint, index));
    (*callback)(node, index, node_indices->len, data);
  }
  g_array_free(node_indices, TRUE);
}

void gkeep_foreach_child_node(const char *parent_id, gkeep_foreach_cb callback, void *data) {
  GArray *node_indices = gkeep_find_nodes(context->nodes, "parentId", parent_id);
  g_array_sort_with_data(node_indices, gkeep_sort_node_cb, context->nodes);
  for (guint index = 0; index < node_indices->len; index++) {
    JsonObject *node = json_array_get_object_element(context->nodes, g_array_index(node_indices, guint, index));
    (*callback)(node, index, node_indices->len, data);
  }
  g_array_free(node_indices, TRUE);
}
