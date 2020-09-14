/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 */

#include <stdlib.h>
#include <app_preference.h>
#include <string.h>
#include "log.h"
#include "data.h"

static bundle *bundle_items = NULL;

static void bundle_load() {
  int len = 0, err;
  char *str = NULL;
  if (PREFERENCE_ERROR_NONE != (err = preference_get_string(DATA_BUNDLE_RAW, &str))) {
    log_print(LOG_ERROR, "preference get data bundle raw failed (%d): %s", err, get_error_message(err));
    return;
  }
  if (PREFERENCE_ERROR_NONE != (err = preference_get_int(DATA_BUNDLE_LEN, &len))) {
    log_print(LOG_ERROR, " preference get data bundle len failed (%d): %s", err, get_error_message(err));
    return;
  }
  bundle_raw *raw = (bundle_raw *) str;
  if (NULL == (bundle_items = bundle_decode(raw, len))) {
    log_print(LOG_ERROR, "bundle decode failed");
  }
  free(str);
}

static void bundle_save() {
  int len = 0, err;
  bundle_raw *raw = NULL;
  if (BUNDLE_ERROR_NONE != (err = bundle_encode(bundle_items, &raw, &len))) {
    log_print(LOG_ERROR, "bundle encode failed (%d): %s", err, get_error_message(err));
    return;
  } else {
    if (PREFERENCE_ERROR_NONE != (err = preference_set_string(DATA_BUNDLE_RAW, (const char *) raw))) {
      log_print(LOG_ERROR, "preference set data bundle raw failed (%d): %s", err, get_error_message(err));
    }
    if (PREFERENCE_ERROR_NONE != (err = preference_set_int(DATA_BUNDLE_LEN, len))) {
      log_print(LOG_ERROR, "preference set data bundle len failed (%d): %s", err, get_error_message(err));
    }
    free(raw);
  }
}

void data_initialize() {
  if (NULL == bundle_items) {
    bool bundle_raw_exists = false, bundle_len_exists = false;
    int err;
    if (PREFERENCE_ERROR_NONE != (err = preference_is_existing(DATA_BUNDLE_RAW, &bundle_raw_exists))) {
      log_print(LOG_ERROR, "preference is existing of data bundle raw failed (%d): %s", err, get_error_message(err));
      return;
    }
    if (PREFERENCE_ERROR_NONE != (err = preference_is_existing(DATA_BUNDLE_LEN, &bundle_len_exists))) {
      log_print(LOG_ERROR, "preference is existing of data bundle len failed (%d): %s", err, get_error_message(err));
      return;
    }
    if (bundle_raw_exists && bundle_len_exists) {
      bundle_load();
    } else {
      if (NULL == (bundle_items = bundle_create())) {
        log_print(LOG_ERROR, "bundle create failed");
      }
    }
  }
}

void data_terminate() {
  int err;
  if (BUNDLE_ERROR_NONE != (err = bundle_free(bundle_items))) {
    log_print(LOG_ERROR, "bundle free items failed (%d): %s", err, get_error_message(err));
  }
  bundle_items = NULL;
}

void data_reset() {
  int err;
  data_terminate();
  if (PREFERENCE_ERROR_NONE != (err = preference_remove_all())) {
    log_print(LOG_ERROR, "preference reset failed (%d): %s", err, get_error_message(err));
  }
  data_initialize();
}

void data_set(const char *key, const char *value) { // NOLINT(misc-no-recursion)
  // log_print(LOG_DEBUG, "bundle data set key: %s, value: %s", key, value);
  int err = bundle_add_str(bundle_items, key, value);
  if (BUNDLE_ERROR_KEY_EXISTS == err) {
    data_delete(key);
    data_set(key, value);
  } else if (BUNDLE_ERROR_NONE != err) {
    log_print(LOG_ERROR, "bundle data save \"%s\" failed (%d): %s", key, err, get_error_message(err));
    return;
  }
  bundle_save();
}

char *data_get(const char *key) {
  int err;
  char *value = NULL;
  if (BUNDLE_ERROR_NONE != (err = bundle_get_str(bundle_items, key, &value))) {
    log_print(BUNDLE_ERROR_KEY_NOT_AVAILABLE == err ? LOG_DEBUG : LOG_ERROR,
        "bundle data get \"%s\" failed (%d): %s", key, err, get_error_message(err));
    return NULL;
  }
  return strdup(value);
}

void data_iterate(bundle_iterate_cb_t callback, void *data) {
  bundle_iterate(bundle_items, callback, data);
}

void data_delete(const char *key) {
  int err;
  if (BUNDLE_ERROR_NONE != (err = bundle_del(bundle_items, key))) {
    log_print(LOG_ERROR, "bundle data delete failed (%d): %s", err, get_error_message(err));
    return;
  }
  bundle_save();
}
