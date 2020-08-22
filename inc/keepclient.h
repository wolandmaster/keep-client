#ifndef KEEPCLIENT_INC_KEEPCLIENT_H_
#define KEEPCLIENT_INC_KEEPCLIENT_H_

#include <Elementary.h>
#include <stdbool.h>

#ifdef  LOG_TAG
#undef  LOG_TAG
#endif
#define LOG_TAG "keepclient"

#if !defined(PACKAGE)
#define PACKAGE "com.github.wolandmaster.keepclient"
#endif

#define VERSION "1.0.0"

typedef struct main_view_context main_view_context;
struct main_view_context {
  Evas_Object *naviframe;
  Evas_Object *box;
  Evas_Object *label;

  Ecore_Timer *timer;

  Elm_Object_Item *(*show)(main_view_context *);
};

typedef struct app_context app_context;
struct app_context {
  Evas_Object *window;
  Evas_Object *conform;
  Evas_Object *naviframe;

  bool quick_start;

  main_view_context *main_context;
};

#endif /* KEEPCLIENT_INC_KEEPCLIENT_H_ */
