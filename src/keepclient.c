/*
 * Google Keep client for Samsung Gear Fit 2 (Pro)
 * Copyright (c) 2020, Sandor Balazsi <sandor.balazsi@gmail.com>
 * This software may be distributed under the terms of the Apache 2.0 license.
 */

#include <app.h>
#include <system_settings.h>
#include <efl_extension.h>
#include <dlog.h>
#include "keepclient.h"
#include "main_view.h"
#include "https.h"

static void delete_request_cb(void *data EINA_UNUSED, Evas_Object *obj EINA_UNUSED, void *event_info EINA_UNUSED) {
  dlog_print(DLOG_DEBUG, LOG_TAG, "application window delete");
  http_terminate();
  ui_app_exit();
}

static void hw_key_back_cb(void *data, Evas_Object *obj EINA_UNUSED, void *event_info EINA_UNUSED) {
  app_context *context = data;
  if (elm_naviframe_top_item_get(context->naviframe) == elm_naviframe_bottom_item_get(context->naviframe)) {
    dlog_print(DLOG_DEBUG, LOG_TAG, "application window hw back: win lower");
    // elm_win_lower(context->window);
    ui_app_exit();
  } else {
    dlog_print(DLOG_DEBUG, LOG_TAG, "application window hw back: naviframe pop");
    elm_naviframe_item_pop(context->naviframe);
  }
}

static void application_terminate_cb(void *data) {
  dlog_print(DLOG_DEBUG, LOG_TAG, "application terminate");
  app_context *context = data;
  evas_object_del(context->window);
  free(context);
}

static void application_control_cb(app_control_h app_control, void *data) {
  dlog_print(DLOG_DEBUG, LOG_TAG, "application control");
  app_context *context = data;
  char *app_caller = calloc(128, sizeof(char));
  if (APP_CONTROL_ERROR_NONE == app_control_get_caller(app_control, &app_caller) && strcmp(app_caller, "starter") == 0) {
    dlog_print(DLOG_INFO, LOG_TAG, "started by double press home key");
    context->quick_start = true;
  }
  free(app_caller);
}

static void application_pause_cb(void *data EINA_UNUSED) {
  dlog_print(DLOG_DEBUG, LOG_TAG, "application pause");
}

static void application_resume_cb(void *data) {
  dlog_print(DLOG_DEBUG, LOG_TAG, "application resume");
  app_context *context = data;
  if (context->quick_start) {
    // perform quick start action
    context->quick_start = false;
  }
}

static void language_changed_cb(app_event_info_h event_info EINA_UNUSED, void *user_data EINA_UNUSED) {
  char *language = NULL;
  system_settings_get_value_string(SYSTEM_SETTINGS_KEY_LOCALE_LANGUAGE, &language);
  elm_language_set(language);
  free(language);
}

static void create_base_gui(app_context *context) {
  /* Window */
  context->window = elm_win_util_standard_add(PACKAGE, PACKAGE);
  elm_win_autodel_set(context->window, EINA_TRUE);
  evas_object_smart_callback_add(context->window, "delete,request", delete_request_cb, context);
  eext_object_event_callback_add(context->window, EEXT_CALLBACK_BACK, hw_key_back_cb, context);

  /* Conformant */
  context->conform = elm_conformant_add(context->window);
  evas_object_size_hint_weight_set(context->conform, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
  evas_object_size_hint_align_set(context->conform, EVAS_HINT_FILL, EVAS_HINT_FILL);
  elm_win_indicator_mode_set(context->window, ELM_WIN_INDICATOR_SHOW);
  elm_win_indicator_opacity_set(context->window, ELM_WIN_INDICATOR_OPAQUE);
  elm_win_resize_object_add(context->window, context->conform);

  /* Naviframe */
  context->naviframe = elm_naviframe_add(context->conform);
  elm_object_content_set(context->conform, context->naviframe);

  /* Main View */
  context->main_context = main_view_create(context->naviframe);
  context->main_context->show(context->main_context);

  evas_object_show(context->naviframe);
  evas_object_show(context->conform);
  evas_object_show(context->window);
}

static bool application_create_cb(void *data) {
  dlog_print(DLOG_DEBUG, LOG_TAG, "application create");
  app_context *context = data;
  http_initialize();
  create_base_gui(context);
  return true;
}

int main(int argc, char *argv[]) {
  app_context context = { .quick_start = false };
  ui_app_lifecycle_callback_s event_callback = { 0, };
  app_event_handler_h handlers[5] = { NULL, };

  event_callback.create = application_create_cb;
  event_callback.terminate = application_terminate_cb;
  event_callback.pause = application_pause_cb;
  event_callback.resume = application_resume_cb;
  event_callback.app_control = application_control_cb;

  ui_app_add_event_handler(&handlers[APP_EVENT_LANGUAGE_CHANGED], APP_EVENT_LANGUAGE_CHANGED, language_changed_cb, &context);

  return ui_app_main(argc, argv, &event_callback, &context);
}
