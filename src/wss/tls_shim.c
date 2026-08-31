#include "tls_shim.h"

#include <limits.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdlib.h>

struct lyune_tls_context {
    SSL_CTX *inner;
};

struct lyune_tls_connection {
    SSL *ssl;
    BIO *network_bio;
};

int lyune_tls_context_create(const char *cert_file, const char *key_file,
                             lyune_tls_context **out) {
    if (out == NULL) return LYUNE_TLS_CONTEXT_CREATE_FAILED;
    *out = NULL;
    lyune_tls_context *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return LYUNE_TLS_CONTEXT_CREATE_FAILED;

    ctx->inner = SSL_CTX_new(TLS_server_method());
    if (ctx->inner == NULL) {
        free(ctx);
        return LYUNE_TLS_CONTEXT_CREATE_FAILED;
    }
    if (SSL_CTX_set_min_proto_version(ctx->inner, TLS1_2_VERSION) != 1) {
        lyune_tls_context_free(ctx);
        return LYUNE_TLS_CONFIGURATION_FAILED;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx->inner, cert_file) != 1) {
        lyune_tls_context_free(ctx);
        return LYUNE_TLS_CERTIFICATE_LOAD_FAILED;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx->inner, key_file, SSL_FILETYPE_PEM) != 1) {
        lyune_tls_context_free(ctx);
        return LYUNE_TLS_PRIVATE_KEY_LOAD_FAILED;
    }
    if (SSL_CTX_check_private_key(ctx->inner) != 1) {
        lyune_tls_context_free(ctx);
        return LYUNE_TLS_PRIVATE_KEY_MISMATCH;
    }
    SSL_CTX_set_mode(ctx->inner,
                     SSL_MODE_ENABLE_PARTIAL_WRITE |
                         SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    *out = ctx;
    return LYUNE_TLS_CONTEXT_OK;
}

void lyune_tls_context_free(lyune_tls_context *ctx) {
    if (ctx == NULL) return;
    SSL_CTX_free(ctx->inner);
    free(ctx);
}

lyune_tls_connection *lyune_tls_connection_create(lyune_tls_context *ctx,
                                                  size_t bio_capacity) {
    if (ctx == NULL || bio_capacity == 0) return NULL;
    lyune_tls_connection *connection = calloc(1, sizeof(*connection));
    if (connection == NULL) return NULL;
    connection->ssl = SSL_new(ctx->inner);
    if (connection->ssl == NULL) {
        free(connection);
        return NULL;
    }

    BIO *internal = NULL;
    if (BIO_new_bio_pair(&internal, bio_capacity, &connection->network_bio,
                         bio_capacity) != 1) {
        SSL_free(connection->ssl);
        free(connection);
        return NULL;
    }
    SSL_set_bio(connection->ssl, internal, internal);
    SSL_set_accept_state(connection->ssl);
    return connection;
}

void lyune_tls_connection_free(lyune_tls_connection *connection) {
    if (connection == NULL) return;
    SSL_free(connection->ssl);
    BIO_free(connection->network_bio);
    free(connection);
}

size_t lyune_tls_provide_encrypted(lyune_tls_connection *connection,
                                   const unsigned char *bytes, size_t len) {
    if (connection == NULL || bytes == NULL || len == 0) return 0;
    size_t count = len;
    size_t guaranteed = BIO_ctrl_get_write_guarantee(connection->network_bio);
    if (count > guaranteed) count = guaranteed;
    if (count > INT_MAX) count = INT_MAX;
    if (count == 0) return 0;
    int written = BIO_write(connection->network_bio, bytes, (int)count);
    return written > 0 ? (size_t)written : 0;
}

long lyune_tls_take_encrypted(lyune_tls_connection *connection,
                              unsigned char *out, size_t len) {
    if (connection == NULL || out == NULL || len == 0) return 0;
    if (len > INT_MAX) len = INT_MAX;
    int result = BIO_read(connection->network_bio, out, (int)len);
    if (result > 0) return result;
    return BIO_should_retry(connection->network_bio) ? LYUNE_TLS_IO_WOULD_BLOCK
                                                     : LYUNE_TLS_IO_FAILED;
}

static long lyune_tls_classify(SSL *ssl, int result) {
    switch (SSL_get_error(ssl, result)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return LYUNE_TLS_IO_WOULD_BLOCK;
        case SSL_ERROR_ZERO_RETURN:
            return LYUNE_TLS_IO_CLOSED;
        default:
            return LYUNE_TLS_IO_FAILED;
    }
}

int lyune_tls_handshake(lyune_tls_connection *connection) {
    if (connection == NULL) return LYUNE_TLS_IO_FAILED;
    int result = SSL_do_handshake(connection->ssl);
    return result == 1 ? 1 : (int)lyune_tls_classify(connection->ssl, result);
}

const char *lyune_tls_server_name(const lyune_tls_connection *connection) {
    if (connection == NULL) return NULL;
    return SSL_get_servername(connection->ssl, TLSEXT_NAMETYPE_host_name);
}

long lyune_tls_read_plain(lyune_tls_connection *connection, unsigned char *out,
                          size_t len) {
    if (connection == NULL || out == NULL || len == 0) return 0;
    if (len > INT_MAX) len = INT_MAX;
    int result = SSL_read(connection->ssl, out, (int)len);
    return result > 0 ? result : lyune_tls_classify(connection->ssl, result);
}

long lyune_tls_write_plain(lyune_tls_connection *connection,
                           const unsigned char *bytes, size_t len) {
    if (connection == NULL || bytes == NULL || len == 0) return 0;
    if (len > INT_MAX) len = INT_MAX;
    int result = SSL_write(connection->ssl, bytes, (int)len);
    return result > 0 ? result : lyune_tls_classify(connection->ssl, result);
}

void lyune_tls_shutdown(lyune_tls_connection *connection) {
    if (connection != NULL) (void)SSL_shutdown(connection->ssl);
}
