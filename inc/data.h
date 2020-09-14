#ifndef KEEPCLIENT_INC_DATA_H_
#define KEEPCLIENT_INC_DATA_H_

#include <bundle.h>

#define DATA_BUNDLE_RAW "keepclient-bundle-raw"
#define DATA_BUNDLE_LEN "keepclient-bundle-len"

void data_initialize();
void data_terminate();
void data_reset();
void data_set(const char *, const char *);
char *data_get(const char *);
void data_iterate(bundle_iterate_cb_t, void *);
void data_delete(const char *);

#endif //KEEPCLIENT_INC_DATA_H_
