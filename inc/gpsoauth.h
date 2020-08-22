#ifndef KEEPCLIENT_INC_GPSOAUTH_H_
#define KEEPCLIENT_INC_GPSOAUTH_H_

#include <glib.h>

#define GOOGLE_PLAY_SERVICES_AUTH_URL "https://android.clients.google.com:443/auth"
#define HTTPS_USER_AGENT "gear-fit-2-keep-client/1.0.0"
#define HTTPS_ERROR_KEY "HttpsError"

#define ANDROID_KEY_7_3_29 "" \
  "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3" \
  "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK" \
  "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/" \
  "6rmf5AAAAAwEAAQ=="

GHashTable *gpsoauth_perform_master_login(const char *, const char *, const char *);
GHashTable *gpsoauth_perform_oauth(const char *, const char *, const char *, const char *, const char *, const char *);

#endif //KEEPCLIENT_INC_GPSOAUTH_H_
