#ifndef KEEPCLIENT_INC_GKEEP_H_
#define KEEPCLIENT_INC_GKEEP_H_

#include <json-glib/json-glib.h>

#define KEEP_OAUTH_SCOPES "oauth2:https://www.googleapis.com/auth/memento https://www.googleapis.com/auth/reminders"
#define KEEP_OAUTH_APP "com.google.android.keep"
#define KEEP_OAUTH_CLIENT_SIG "38918a453d07199354f8b19af05ec6562ced5788"
#define KEEP_API_URL "https://www.googleapis.com:443/notes/v1/"

typedef struct gkeep_context gkeep_context;
struct gkeep_context {
  char *android_id;
  char *email;
  char *master_token;
  char *oauth_token;
  time_t oauth_expiry;
  char *version;
  JsonArray *nodes;
};

typedef struct gkeep_find gkeep_find;
struct gkeep_find {
  const gchar *field;
  const gchar *looking_for;
  GArray *indices;
};

typedef void (*GKeepForeach)(JsonObject *, void *data);

void gkeep_initialize(const char *);
void gkeep_terminate();
void gkeep_login(const char *, const char *);
void gkeep_oauth_refresh();
void gkeep_fetch_changes(JsonArray *, JsonArray *);
JsonObject *gkeep_get_node_by_id(const char *id);
void gkeep_foreach_parent_node(GKeepForeach, void *);
void gkeep_foreach_child_node(const char *, GKeepForeach, void *);

#endif //KEEPCLIENT_INC_GKEEP_H_
