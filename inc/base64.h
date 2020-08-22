#ifndef KEEPCLIENT_INC_BASE64_H_
#define KEEPCLIENT_INC_BASE64_H_

unsigned char *base64_encode(const unsigned char *, size_t, size_t *);
unsigned char *base64_urlsafe_encode(const unsigned char *, size_t, size_t *);
unsigned char *base64_decode(const unsigned char *, size_t, size_t *);

#endif //KEEPCLIENT_INC_BASE64_H_
