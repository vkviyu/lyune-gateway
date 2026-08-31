#ifndef LYUNE_WSS_TLS_SHIM_H
#define LYUNE_WSS_TLS_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lyune_tls_context lyune_tls_context;
typedef struct lyune_tls_connection lyune_tls_connection;

enum lyune_tls_context_result {
    LYUNE_TLS_CONTEXT_OK = 0,
    LYUNE_TLS_CONTEXT_CREATE_FAILED = -1,
    LYUNE_TLS_CERTIFICATE_LOAD_FAILED = -2,
    LYUNE_TLS_PRIVATE_KEY_LOAD_FAILED = -3,
    LYUNE_TLS_PRIVATE_KEY_MISMATCH = -4,
    LYUNE_TLS_CONFIGURATION_FAILED = -5,
};

enum lyune_tls_io_result {
    LYUNE_TLS_IO_WOULD_BLOCK = 0,
    LYUNE_TLS_IO_CLOSED = -1,
    LYUNE_TLS_IO_FAILED = -2,
};

int lyune_tls_context_create(const char *cert_file, const char *key_file,
                             lyune_tls_context **out);
void lyune_tls_context_free(lyune_tls_context *ctx);

lyune_tls_connection *lyune_tls_connection_create(lyune_tls_context *ctx,
                                                  size_t bio_capacity);
void lyune_tls_connection_free(lyune_tls_connection *connection);

size_t lyune_tls_provide_encrypted(lyune_tls_connection *connection,
                                   const unsigned char *bytes, size_t len);
long lyune_tls_take_encrypted(lyune_tls_connection *connection,
                              unsigned char *out, size_t len);
int lyune_tls_handshake(lyune_tls_connection *connection);
const char *lyune_tls_server_name(const lyune_tls_connection *connection);
long lyune_tls_read_plain(lyune_tls_connection *connection, unsigned char *out,
                          size_t len);
long lyune_tls_write_plain(lyune_tls_connection *connection,
                           const unsigned char *bytes, size_t len);
void lyune_tls_shutdown(lyune_tls_connection *connection);

#ifdef __cplusplus
}
#endif

#endif
