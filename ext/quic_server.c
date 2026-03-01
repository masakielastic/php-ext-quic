#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_server.h"
#include "quic_stream.h"

#include "main/php_network.h"
#include "main/php_streams.h"

#include <errno.h>
#include <fcntl.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <inttypes.h>
#include <netdb.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define QUIC_SERVER_DEFAULT_ALPN "hq-interop"
#define QUIC_SERVER_DEFAULT_CERT_FILE "/tmp/nghttp3-localhost.crt"
#define QUIC_SERVER_DEFAULT_KEY_FILE "/tmp/nghttp3-localhost.key"
#define QUIC_SERVER_DEFAULT_RESPONSE "server response\n"

struct _quic_server_connection_object {
  php_socket_t fd;
  zend_string *host;
  zend_string *port;
  zend_string *alpn;
  zend_string *certfile;
  zend_string *keyfile;
  zend_string *response;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct _quic_server_peer_state *peer;
  zend_object std;
};

typedef struct _quic_server_peer_state {
  quic_server_connection_object *server;
  struct sockaddr_storage peer_addr;
  socklen_t peer_addrlen;
  ngtcp2_crypto_conn_ref conn_ref;
  gnutls_certificate_credentials_t cred;
  gnutls_session_t session;
  ngtcp2_conn *conn;
  ngtcp2_ccerr last_error;
  HashTable streams;
  zend_llist accepted_streams;
  bool started;
  bool handshake_complete;
} quic_server_peer_state;

zend_class_entry *quic_server_connection_ce;

static zend_object_handlers quic_server_connection_handlers;

static const char quic_server_tls_priority[] =
  "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
  "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
  "+GROUP-SECP384R1:+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

static inline quic_server_connection_object *quic_server_connection_from_obj(zend_object *object)
{
  return (quic_server_connection_object *) ((char *) object - XtOffsetOf(quic_server_connection_object, std));
}

#define Z_QUIC_SERVER_CONNECTION_P(zv) \
  quic_server_connection_from_obj(Z_OBJ_P((zv)))

static size_t quic_server_stream_key(char *buffer, size_t buffer_len, int64_t stream_id)
{
  return (size_t) snprintf(buffer, buffer_len, "%" PRId64, stream_id);
}

static quic_stream_state *quic_server_find_stream_state(
  quic_server_peer_state *peer,
  int64_t stream_id
)
{
  char key[32];
  size_t key_len;

  key_len = quic_server_stream_key(key, sizeof(key), stream_id);

  return zend_hash_str_find_ptr(&peer->streams, key, key_len);
}

static bool quic_server_register_stream_state(
  quic_server_peer_state *peer,
  quic_stream_state *state
)
{
  char key[32];
  size_t key_len;

  key_len = quic_server_stream_key(key, sizeof(key), state->stream_id);

  quic_stream_state_addref(state);
  if (zend_hash_str_update_ptr(&peer->streams, key, key_len, state) == NULL) {
    quic_stream_state_release(state);
    zend_throw_exception_ex(quic_exception_ce, 0, "Failed to register stream state");
    return false;
  }

  return true;
}

static quic_stream_state *quic_server_get_next_writable_stream(
  quic_server_peer_state *peer
)
{
  quic_stream_state *state;

  ZEND_HASH_FOREACH_PTR(&peer->streams, state) {
    if (quic_stream_state_has_pending_write(state)) {
      return state;
    }
  } ZEND_HASH_FOREACH_END();

  return NULL;
}

static void quic_server_release_accepted_stream_entry(void *data)
{
  quic_stream_state *state = *(quic_stream_state **) data;

  quic_stream_state_release(state);
}

static quic_server_peer_state *quic_server_peer_state_create(quic_server_connection_object *server)
{
  quic_server_peer_state *peer;

  peer = ecalloc(1, sizeof(quic_server_peer_state));
  peer->server = server;
  peer->cred = NULL;
  peer->session = NULL;
  peer->conn = NULL;
  peer->peer_addrlen = 0;
  peer->started = false;
  peer->handshake_complete = false;
  ngtcp2_ccerr_default(&peer->last_error);
  zend_hash_init(&peer->streams, 8, NULL, NULL, 0);
  zend_llist_init(
    &peer->accepted_streams,
    sizeof(quic_stream_state *),
    quic_server_release_accepted_stream_entry,
    0
  );

  return peer;
}

static void quic_server_peer_state_destroy(quic_server_peer_state *peer)
{
  quic_stream_state *state;

  if (peer == NULL) {
    return;
  }

  if (peer->conn != NULL) {
    ngtcp2_conn_del(peer->conn);
    peer->conn = NULL;
  }

  if (peer->session != NULL) {
    gnutls_deinit(peer->session);
    peer->session = NULL;
  }

  if (peer->cred != NULL) {
    gnutls_certificate_free_credentials(peer->cred);
    peer->cred = NULL;
  }

  ZEND_HASH_FOREACH_PTR(&peer->streams, state) {
    quic_stream_state_detach(state);
    quic_stream_state_release(state);
  } ZEND_HASH_FOREACH_END();
  zend_hash_destroy(&peer->streams);
  zend_llist_destroy(&peer->accepted_streams);

  efree(peer);
}

static void quic_server_queue_accepted_stream_state(
  quic_server_peer_state *peer,
  quic_stream_state *state
)
{
  quic_stream_state_addref(state);
  zend_llist_prepend_element(&peer->accepted_streams, &state);
}

static quic_stream_state *quic_server_pop_accepted_stream_state(
  quic_server_peer_state *peer
)
{
  quic_stream_state **state_ptr;
  quic_stream_state *state;

  state_ptr = zend_llist_get_last(&peer->accepted_streams);
  if (state_ptr == NULL) {
    return NULL;
  }

  state = *state_ptr;
  quic_stream_state_addref(state);
  zend_llist_remove_tail(&peer->accepted_streams);

  return state;
}

static quic_stream_state *quic_server_ensure_stream_state(
  quic_server_peer_state *peer,
  int64_t stream_id,
  bool queue_if_new
)
{
  quic_stream_state *state;

  state = quic_server_find_stream_state(peer, stream_id);
  if (state != NULL) {
    return state;
  }

  state = quic_stream_state_create(QUIC_STREAM_OWNER_SERVER, peer, stream_id);
  if (!quic_server_register_stream_state(peer, state)) {
    quic_stream_state_release(state);
    return NULL;
  }

  if (peer->conn != NULL) {
    ngtcp2_conn_set_stream_user_data(peer->conn, stream_id, state);
  }

  if (queue_if_new) {
    quic_server_queue_accepted_stream_state(peer, state);
  }

  quic_stream_state_release(state);

  return quic_server_find_stream_state(peer, stream_id);
}

static uint64_t quic_server_timestamp(void)
{
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      errno,
      "clock_gettime() failed: %s",
      strerror(errno)
    );
    return 0;
  }

  return (uint64_t) tp.tv_sec * NGTCP2_SECONDS + (uint64_t) tp.tv_nsec;
}

static bool quic_server_fill_random(void *dest, size_t destlen)
{
  int rv = gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);

  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_rnd() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  return true;
}

static ngtcp2_conn *quic_server_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  quic_server_peer_state *peer = conn_ref->user_data;
  return peer->conn;
}

static void quic_server_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
  (void) rand_ctx;

  if (!quic_server_fill_random(dest, destlen)) {
    abort();
  }
}

static int quic_server_get_new_connection_id_cb(
  ngtcp2_conn *conn,
  ngtcp2_cid *cid,
  uint8_t *token,
  size_t cidlen,
  void *user_data
)
{
  (void) conn;
  (void) user_data;

  if (!quic_server_fill_random(cid->data, cidlen)) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;

  if (!quic_server_fill_random(token, NGTCP2_STATELESS_RESET_TOKENLEN)) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static bool quic_server_is_client_bidi_stream(int64_t stream_id)
{
  return (stream_id & 0x3) == 0;
}

static int quic_server_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
  quic_server_peer_state *peer = user_data;

  (void) conn;

  peer->handshake_complete = true;

  return 0;
}

static int quic_server_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  quic_server_peer_state *peer = user_data;

  (void) conn;

  if (quic_server_is_client_bidi_stream(stream_id) &&
      quic_server_ensure_stream_state(peer, stream_id, true) == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int quic_server_stream_close_cb(
  ngtcp2_conn *conn,
  uint32_t flags,
  int64_t stream_id,
  uint64_t app_error_code,
  void *user_data,
  void *stream_user_data
)
{
  quic_server_peer_state *peer = user_data;
  quic_stream_state *state = stream_user_data;

  (void) conn;
  (void) flags;
  (void) app_error_code;

  if (state == NULL) {
    state = quic_server_find_stream_state(peer, stream_id);
  }

  if (state != NULL) {
    quic_stream_state_mark_closed(state);
  }

  return 0;
}

static int quic_server_recv_stream_data_cb(
  ngtcp2_conn *conn,
  uint32_t flags,
  int64_t stream_id,
  uint64_t offset,
  const uint8_t *data,
  size_t datalen,
  void *user_data,
  void *stream_user_data
)
{
  quic_server_peer_state *peer = user_data;
  quic_stream_state *state = stream_user_data;

  (void) conn;
  (void) offset;

  if (state == NULL && quic_server_is_client_bidi_stream(stream_id)) {
    state = quic_server_ensure_stream_state(peer, stream_id, true);
  }

  if (state == NULL) {
    return 0;
  }

  if (datalen > 0 && !quic_stream_state_append_read(state, data, datalen)) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
    quic_stream_state_mark_peer_fin(state);

    if (peer->server->response != NULL && !state->fin_requested) {
      if (!quic_stream_state_append_write(
            state,
            (const uint8_t *) ZSTR_VAL(peer->server->response),
            ZSTR_LEN(peer->server->response)
          )) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      state->fin_requested = true;
    }
  }

  return 0;
}

static int quic_server_acked_stream_data_offset_cb(
  ngtcp2_conn *conn,
  int64_t stream_id,
  uint64_t offset,
  uint64_t datalen,
  void *user_data,
  void *stream_user_data
)
{
  (void) conn;
  (void) stream_id;
  (void) offset;
  (void) datalen;
  (void) user_data;
  (void) stream_user_data;

  return 0;
}

static zend_string *quic_server_port_to_string(zval *port)
{
  char buffer[32];
  int length;

  if (Z_TYPE_P(port) == IS_LONG) {
    if (Z_LVAL_P(port) < 0 || Z_LVAL_P(port) > 65535) {
      zend_argument_value_error(2, "must be between 0 and 65535");
      return NULL;
    }

    length = snprintf(buffer, sizeof(buffer), "%ld", Z_LVAL_P(port));
    if (length <= 0) {
      zend_throw_exception_ex(quic_exception_ce, 0, "Failed to format port");
      return NULL;
    }

    return zend_string_init(buffer, (size_t) length, 0);
  }

  if (Z_TYPE_P(port) == IS_STRING) {
    if (Z_STRLEN_P(port) == 0) {
      zend_argument_must_not_be_empty_error(2);
      return NULL;
    }

    return zend_string_copy(Z_STR_P(port));
  }

  zend_argument_type_error(2, "must be of type string|int");
  return NULL;
}

static zend_string *quic_server_get_string_option(HashTable *options, const char *key)
{
  zval *value = zend_hash_str_find(options, key, strlen(key));

  if (value == NULL || Z_TYPE_P(value) == IS_NULL) {
    return NULL;
  }

  if (Z_TYPE_P(value) != IS_STRING) {
    zend_type_error("Option \"%s\" must be of type ?string", key);
    return NULL;
  }

  return zend_string_copy(Z_STR_P(value));
}

static bool quic_server_apply_options(quic_server_connection_object *intern, HashTable *options)
{
  zval *value;

  intern->alpn = quic_server_get_string_option(options, "alpn");
  if (EG(exception) != NULL) {
    return false;
  }
  if (intern->alpn == NULL) {
    intern->alpn = zend_string_init(QUIC_SERVER_DEFAULT_ALPN, sizeof(QUIC_SERVER_DEFAULT_ALPN) - 1, 0);
  }

  intern->certfile = quic_server_get_string_option(options, "certfile");
  if (EG(exception) != NULL) {
    return false;
  }
  if (intern->certfile == NULL) {
    intern->certfile = zend_string_init(
      QUIC_SERVER_DEFAULT_CERT_FILE,
      sizeof(QUIC_SERVER_DEFAULT_CERT_FILE) - 1,
      0
    );
  }

  intern->keyfile = quic_server_get_string_option(options, "keyfile");
  if (EG(exception) != NULL) {
    return false;
  }
  if (intern->keyfile == NULL) {
    intern->keyfile = zend_string_init(
      QUIC_SERVER_DEFAULT_KEY_FILE,
      sizeof(QUIC_SERVER_DEFAULT_KEY_FILE) - 1,
      0
    );
  }

  value = zend_hash_str_find(options, "response", sizeof("response") - 1);
  if (value == NULL) {
    intern->response = zend_string_init(
      QUIC_SERVER_DEFAULT_RESPONSE,
      sizeof(QUIC_SERVER_DEFAULT_RESPONSE) - 1,
      0
    );
    return true;
  }

  if (Z_TYPE_P(value) == IS_NULL) {
    intern->response = NULL;
    return true;
  }

  if (Z_TYPE_P(value) != IS_STRING) {
    zend_type_error("Option \"response\" must be of type ?string");
    return false;
  }

  intern->response = zend_string_copy(Z_STR_P(value));
  return true;
}

static void quic_server_address_to_array(
  zval *return_value,
  const struct sockaddr *addr,
  socklen_t addrlen
)
{
  char host[NI_MAXHOST];
  char service[NI_MAXSERV];
  long port;
  int rv;

  array_init(return_value);

  if (addr == NULL || addrlen == 0) {
    return;
  }

  rv = getnameinfo(
    addr,
    addrlen,
    host,
    sizeof(host),
    service,
    sizeof(service),
    NI_NUMERICHOST | NI_NUMERICSERV
  );
  if (rv != 0) {
    add_assoc_null(return_value, "family");
    add_assoc_null(return_value, "address");
    add_assoc_null(return_value, "port");
    return;
  }

  switch (addr->sa_family) {
    case AF_INET:
      add_assoc_string(return_value, "family", "AF_INET");
      break;
    case AF_INET6:
      add_assoc_string(return_value, "family", "AF_INET6");
      break;
    default:
      add_assoc_string(return_value, "family", "AF_UNSPEC");
      break;
  }

  add_assoc_string(return_value, "address", host);

  port = strtol(service, NULL, 10);
  add_assoc_long(return_value, "port", port);
}

static bool quic_server_set_nonblocking(php_socket_t fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      errno,
      "fcntl(F_GETFL) failed: %s",
      strerror(errno)
    );
    return false;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      errno,
      "fcntl(F_SETFL) failed: %s",
      strerror(errno)
    );
    return false;
  }

  return true;
}

static bool quic_server_bind_socket(quic_server_connection_object *intern)
{
  struct addrinfo hints = {0};
  struct addrinfo *result = NULL;
  struct addrinfo *rp;
  const char *host;
  int last_errno = 0;
  int rv;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  host = ZSTR_VAL(intern->host);
  if (strcmp(host, "*") == 0) {
    host = NULL;
    hints.ai_flags |= AI_PASSIVE;
  }

  rv = getaddrinfo(host, ZSTR_VAL(intern->port), &hints, &result);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      rv,
      "getaddrinfo() failed: %s",
      gai_strerror(rv)
    );
    return false;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    int optval = 1;

    intern->fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (intern->fd < 0) {
      continue;
    }

    setsockopt(intern->fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(optval));

    if (bind(intern->fd, rp->ai_addr, rp->ai_addrlen) < 0) {
      last_errno = errno;
      close(intern->fd);
      intern->fd = -1;
      continue;
    }

    if (!quic_server_set_nonblocking(intern->fd)) {
      close(intern->fd);
      intern->fd = -1;
      freeaddrinfo(result);
      return false;
    }

    intern->local_addrlen = sizeof(intern->local_addr);
    if (getsockname(intern->fd, (struct sockaddr *) &intern->local_addr, &intern->local_addrlen) < 0) {
      zend_throw_exception_ex(
        quic_exception_ce,
        errno,
        "getsockname() failed: %s",
        strerror(errno)
      );
      close(intern->fd);
      intern->fd = -1;
      freeaddrinfo(result);
      return false;
    }

    freeaddrinfo(result);
    return true;
  }

  freeaddrinfo(result);
  zend_throw_exception_ex(
    quic_exception_ce,
    last_errno,
    "Failed to bind UDP socket%s%s",
    last_errno != 0 ? ": " : "",
    last_errno != 0 ? strerror(last_errno) : ""
  );
  return false;
}

static bool quic_server_send_packet(quic_server_connection_object *intern, const uint8_t *data, size_t datalen)
{
  ssize_t nwrite;

  do {
    nwrite = send(intern->fd, data, datalen, 0);
  } while (nwrite < 0 && errno == EINTR);

  if (nwrite < 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      errno,
      "send() failed: %s",
      strerror(errno)
    );
    return false;
  }

  if ((size_t) nwrite != datalen) {
    zend_throw_exception_ex(
      quic_exception_ce,
      0,
      "Short UDP send: %zd != %zu",
      nwrite,
      datalen
    );
    return false;
  }

  return true;
}

static bool quic_server_record_protocol_error(quic_server_peer_state *peer, int rv)
{
  if (!peer->last_error.error_code) {
    if (rv == NGTCP2_ERR_CRYPTO) {
      ngtcp2_ccerr_set_tls_alert(
        &peer->last_error,
        ngtcp2_conn_get_tls_alert(peer->conn),
        NULL,
        0
      );
    } else {
      ngtcp2_ccerr_set_liberr(&peer->last_error, rv, NULL, 0);
    }
  }

  zend_throw_exception_ex(
    quic_protocol_exception_ce,
    rv,
    "%s",
    ngtcp2_strerror(rv)
  );

  return false;
}

static void quic_server_reset_connection_state(quic_server_connection_object *intern)
{
  if (intern->peer != NULL) {
    quic_server_peer_state_destroy(intern->peer);
    intern->peer = NULL;
  }
}

static bool quic_server_tls_init(
  quic_server_connection_object *intern,
  quic_server_peer_state *peer
)
{
  gnutls_datum_t alpn;
  int rv;

  rv = gnutls_certificate_allocate_credentials(&peer->cred);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_certificate_allocate_credentials() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  rv = gnutls_certificate_set_x509_key_file(
    peer->cred,
    ZSTR_VAL(intern->certfile),
    ZSTR_VAL(intern->keyfile),
    GNUTLS_X509_FMT_PEM
  );
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_certificate_set_x509_key_file() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  rv = gnutls_init(
    &peer->session,
    GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA |
      GNUTLS_NO_AUTO_SEND_TICKET | GNUTLS_NO_END_OF_EARLY_DATA
  );
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_init() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  rv = gnutls_priority_set_direct(peer->session, quic_server_tls_priority, NULL);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_priority_set_direct() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  rv = ngtcp2_crypto_gnutls_configure_server_session(peer->session);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "ngtcp2_crypto_gnutls_configure_server_session() failed"
    );
    return false;
  }

  rv = gnutls_credentials_set(peer->session, GNUTLS_CRD_CERTIFICATE, peer->cred);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_credentials_set() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  alpn.data = (unsigned char *) ZSTR_VAL(intern->alpn);
  alpn.size = (unsigned int) ZSTR_LEN(intern->alpn);
  rv = gnutls_alpn_set_protocols(
    peer->session,
    &alpn,
    1,
    GNUTLS_ALPN_MANDATORY | GNUTLS_ALPN_SERVER_PRECEDENCE
  );
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_alpn_set_protocols() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  peer->conn_ref.get_conn = quic_server_get_conn;
  peer->conn_ref.user_data = peer;
  gnutls_session_set_ptr(peer->session, &peer->conn_ref);
  gnutls_handshake_set_timeout(peer->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  return true;
}

static bool quic_server_quic_init(
  quic_server_connection_object *intern,
  quic_server_peer_state *peer,
  const ngtcp2_cid *client_dcid,
  const ngtcp2_cid *client_scid,
  uint32_t version
)
{
  ngtcp2_callbacks callbacks = {
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = quic_server_handshake_completed_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = quic_server_recv_stream_data_cb,
    .acked_stream_data_offset = quic_server_acked_stream_data_offset_cb,
    .stream_open = quic_server_stream_open_cb,
    .stream_close = quic_server_stream_close_cb,
    .rand = quic_server_rand_cb,
    .get_new_connection_id = quic_server_get_new_connection_id_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
  };
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_path path = {
    .local = {
      .addr = (struct sockaddr *) &intern->local_addr,
      .addrlen = intern->local_addrlen,
    },
    .remote = {
      .addr = (struct sockaddr *) &peer->peer_addr,
      .addrlen = peer->peer_addrlen,
    },
  };
  ngtcp2_cid scid;
  int rv;

  scid.datalen = 18;
  if (!quic_server_fill_random(scid.data, scid.datalen)) {
    return false;
  }

  ngtcp2_settings_default(&settings);
  settings.initial_ts = quic_server_timestamp();
  if (EG(exception) != NULL) {
    return false;
  }

  ngtcp2_transport_params_default(&params);
  params.initial_max_stream_data_bidi_local = 64 * 1024;
  params.initial_max_stream_data_bidi_remote = 64 * 1024;
  params.initial_max_stream_data_uni = 64 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.initial_max_streams_bidi = 16;
  params.initial_max_streams_uni = 16;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 7;
  params.stateless_reset_token_present = 1;
  params.original_dcid = *client_dcid;
  params.original_dcid_present = 1;

  if (!quic_server_fill_random(params.stateless_reset_token, sizeof(params.stateless_reset_token))) {
    return false;
  }

  rv = ngtcp2_conn_server_new(
    &peer->conn,
    client_scid,
    &scid,
    &path,
    version,
    &callbacks,
    &settings,
    &params,
    NULL,
    peer
  );
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_protocol_exception_ce,
      rv,
      "ngtcp2_conn_server_new() failed: %s",
      ngtcp2_strerror(rv)
    );
    return false;
  }

  ngtcp2_conn_set_tls_native_handle(peer->conn, peer->session);

  return true;
}

static bool quic_server_flush_packets(quic_server_connection_object *intern)
{
  quic_server_peer_state *peer = intern->peer;
  ngtcp2_path_storage path_storage;
  ngtcp2_pkt_info packet_info;
  uint8_t buffer[1452];
  uint64_t now;

  if (peer == NULL || peer->conn == NULL) {
    return true;
  }

  now = quic_server_timestamp();
  if (EG(exception) != NULL) {
    return false;
  }

  ngtcp2_path_storage_zero(&path_storage);

  for (;;) {
    quic_stream_state *state;
    ngtcp2_vec datav = {
      .base = NULL,
      .len = 0,
    };
    int64_t stream_id = -1;
    ngtcp2_ssize data_written = 0;
    ngtcp2_ssize nwrite;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    bool fin_attempted = false;

    state = quic_server_get_next_writable_stream(peer);
    if (state != NULL) {
      stream_id = state->stream_id;

      if (state->write_buffer_off < state->write_buffer_len) {
        datav.base = state->write_buffer + state->write_buffer_off;
        datav.len = state->write_buffer_len - state->write_buffer_off;
      }

      if (state->fin_requested && !state->fin_sent) {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        fin_attempted = true;
      }
    }

    nwrite = ngtcp2_conn_writev_stream(
      peer->conn,
      &path_storage.path,
      &packet_info,
      buffer,
      sizeof(buffer),
      &data_written,
      flags,
      stream_id,
      stream_id >= 0 ? &datav : NULL,
      stream_id >= 0 ? 1 : 0,
      now
    );
    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_WRITE_MORE) {
        if (state != NULL) {
          quic_stream_state_mark_write_progress(
            state,
            (size_t) data_written,
            fin_attempted,
            false
          );
        }
        continue;
      }

      ngtcp2_ccerr_set_liberr(&peer->last_error, (int) nwrite, NULL, 0);
      zend_throw_exception_ex(
        quic_protocol_exception_ce,
        (int) nwrite,
        "ngtcp2_conn_writev_stream() failed: %s",
        ngtcp2_strerror((int) nwrite)
      );
      return false;
    }

    if (nwrite == 0) {
      return true;
    }

    if (state != NULL) {
      quic_stream_state_mark_write_progress(
        state,
        (size_t) data_written,
        fin_attempted,
        true
      );
    }

    if (!quic_server_send_packet(intern, buffer, (size_t) nwrite)) {
      return false;
    }
  }
}

static bool quic_server_handle_connected_readable(quic_server_connection_object *intern)
{
  quic_server_peer_state *peer = intern->peer;
  uint8_t buffer[65536];
  ngtcp2_pkt_info packet_info = {0};

  if (peer == NULL) {
    return true;
  }

  for (;;) {
    ngtcp2_path path = {
      .local = {
        .addr = (struct sockaddr *) &intern->local_addr,
        .addrlen = intern->local_addrlen,
      },
      .remote = {
        .addr = (struct sockaddr *) &peer->peer_addr,
        .addrlen = peer->peer_addrlen,
      },
    };
    ssize_t nread;
    uint64_t now;
    int rv;

    nread = recv(intern->fd, buffer, sizeof(buffer), 0);
    if (nread < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return true;
      }

      if (errno == EINTR) {
        continue;
      }

      zend_throw_exception_ex(
        quic_exception_ce,
        errno,
        "recv() failed: %s",
        strerror(errno)
      );
      return false;
    }

    now = quic_server_timestamp();
    if (EG(exception) != NULL) {
      return false;
    }

    rv = ngtcp2_conn_read_pkt(peer->conn, &path, &packet_info, buffer, (size_t) nread, now);
    if (rv != 0) {
      return quic_server_record_protocol_error(peer, rv);
    }
  }
}

static bool quic_server_try_accept_initial(quic_server_connection_object *intern, bool *accepted)
{
  quic_server_peer_state *peer;
  uint8_t buffer[2048];

  *accepted = false;

  for (;;) {
    struct sockaddr_storage peer_addr;
    ngtcp2_version_cid version_cid;
    ngtcp2_cid client_dcid;
    ngtcp2_cid client_scid;
    ngtcp2_path path;
    ngtcp2_pkt_info packet_info = {0};
    socklen_t peer_addrlen = sizeof(peer_addr);
    ssize_t nread;
    uint32_t version;
    uint64_t now;
    int rv;

    nread = recvfrom(
      intern->fd,
      buffer,
      sizeof(buffer),
      0,
      (struct sockaddr *) &peer_addr,
      &peer_addrlen
    );
    if (nread < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return true;
      }

      if (errno == EINTR) {
        continue;
      }

      zend_throw_exception_ex(
        quic_exception_ce,
        errno,
        "recvfrom() failed: %s",
        strerror(errno)
      );
      return false;
    }

    rv = ngtcp2_pkt_decode_version_cid(&version_cid, buffer, (size_t) nread, 0);
    if (rv != 0 && rv != NGTCP2_ERR_VERSION_NEGOTIATION) {
      continue;
    }

    if (!ngtcp2_is_supported_version(version_cid.version)) {
      continue;
    }

    if (version_cid.dcidlen > NGTCP2_MAX_CIDLEN || version_cid.scidlen > NGTCP2_MAX_CIDLEN) {
      continue;
    }

    ngtcp2_cid_init(&client_dcid, version_cid.dcid, version_cid.dcidlen);
    ngtcp2_cid_init(&client_scid, version_cid.scid, version_cid.scidlen);
    version = version_cid.version;

    if (connect(intern->fd, (struct sockaddr *) &peer_addr, peer_addrlen) != 0) {
      zend_throw_exception_ex(
        quic_exception_ce,
        errno,
        "connect() failed: %s",
        strerror(errno)
      );
      return false;
    }

    peer = quic_server_peer_state_create(intern);
    memcpy(&peer->peer_addr, &peer_addr, peer_addrlen);
    peer->peer_addrlen = peer_addrlen;

    intern->local_addrlen = sizeof(intern->local_addr);
    if (getsockname(intern->fd, (struct sockaddr *) &intern->local_addr, &intern->local_addrlen) < 0) {
      zend_throw_exception_ex(
        quic_exception_ce,
        errno,
        "getsockname() failed: %s",
        strerror(errno)
      );
      return false;
    }

    if (!quic_server_tls_init(intern, peer)) {
      quic_server_peer_state_destroy(peer);
      return false;
    }

    if (!quic_server_quic_init(intern, peer, &client_dcid, &client_scid, version)) {
      quic_server_peer_state_destroy(peer);
      return false;
    }

    path.local.addr = (struct sockaddr *) &intern->local_addr;
    path.local.addrlen = intern->local_addrlen;
    path.remote.addr = (struct sockaddr *) &peer->peer_addr;
    path.remote.addrlen = peer->peer_addrlen;
    path.user_data = NULL;

    now = quic_server_timestamp();
    if (EG(exception) != NULL) {
      return false;
    }

    rv = ngtcp2_conn_read_pkt(peer->conn, &path, &packet_info, buffer, (size_t) nread, now);
    if (rv != 0) {
      bool ok = quic_server_record_protocol_error(peer, rv);
      quic_server_peer_state_destroy(peer);
      return ok;
    }

    peer->started = true;
    intern->peer = peer;
    *accepted = true;
    return true;
  }
}

static bool quic_server_process_readable(quic_server_connection_object *intern)
{
  bool accepted = false;

  if (intern->fd < 0) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Socket is closed");
    return false;
  }

  if (intern->peer == NULL || intern->peer->conn == NULL) {
    if (!quic_server_try_accept_initial(intern, &accepted)) {
      return false;
    }

    if (!accepted) {
      return true;
    }
  }

  return quic_server_handle_connected_readable(intern);
}

static bool quic_server_process_expiry(quic_server_connection_object *intern)
{
  quic_server_peer_state *peer = intern->peer;
  uint64_t now;
  int rv;

  if (peer == NULL || peer->conn == NULL) {
    return true;
  }

  now = quic_server_timestamp();
  if (EG(exception) != NULL) {
    return false;
  }

  rv = ngtcp2_conn_handle_expiry(peer->conn, now);
  if (rv != 0) {
    return quic_server_record_protocol_error(peer, rv);
  }

  return true;
}

static bool quic_server_write_connection_close_packet(
  quic_server_connection_object *intern,
  const ngtcp2_ccerr *ccerr
)
{
  quic_server_peer_state *peer = intern->peer;
  ngtcp2_path_storage path_storage;
  ngtcp2_pkt_info packet_info;
  uint8_t buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
  ngtcp2_ssize nwrite;
  uint64_t now;

  if (peer == NULL || peer->conn == NULL) {
    return true;
  }

  if (ngtcp2_conn_in_closing_period(peer->conn) ||
      ngtcp2_conn_in_draining_period(peer->conn)) {
    return true;
  }

  now = quic_server_timestamp();
  if (EG(exception) != NULL) {
    return false;
  }

  ngtcp2_path_storage_zero(&path_storage);

  nwrite = ngtcp2_conn_write_connection_close(
    peer->conn,
    &path_storage.path,
    &packet_info,
    buffer,
    sizeof(buffer),
    ccerr,
    now
  );
  if (nwrite < 0) {
    zend_throw_exception_ex(
      quic_protocol_exception_ce,
      (int) nwrite,
      "ngtcp2_conn_write_connection_close() failed: %s",
      ngtcp2_strerror((int) nwrite)
    );
    return false;
  }

  if (nwrite == 0) {
    return true;
  }

  return quic_server_send_packet(intern, buffer, (size_t) nwrite);
}

static void quic_server_connection_free_object(zend_object *object)
{
  quic_server_connection_object *intern = quic_server_connection_from_obj(object);

  quic_server_reset_connection_state(intern);

  if (intern->fd >= 0) {
    close(intern->fd);
    intern->fd = -1;
  }

  if (intern->host != NULL) {
    zend_string_release(intern->host);
    intern->host = NULL;
  }

  if (intern->port != NULL) {
    zend_string_release(intern->port);
    intern->port = NULL;
  }

  if (intern->alpn != NULL) {
    zend_string_release(intern->alpn);
    intern->alpn = NULL;
  }

  if (intern->certfile != NULL) {
    zend_string_release(intern->certfile);
    intern->certfile = NULL;
  }

  if (intern->keyfile != NULL) {
    zend_string_release(intern->keyfile);
    intern->keyfile = NULL;
  }

  if (intern->response != NULL) {
    zend_string_release(intern->response);
    intern->response = NULL;
  }

  zend_object_std_dtor(&intern->std);
}

static zend_object *quic_server_connection_create_object(zend_class_entry *class_type)
{
  quic_server_connection_object *intern;

  intern = zend_object_alloc(sizeof(quic_server_connection_object), class_type);
  intern->fd = -1;
  intern->host = NULL;
  intern->port = NULL;
  intern->alpn = zend_string_init(QUIC_SERVER_DEFAULT_ALPN, sizeof(QUIC_SERVER_DEFAULT_ALPN) - 1, 0);
  intern->certfile = zend_string_init(
    QUIC_SERVER_DEFAULT_CERT_FILE,
    sizeof(QUIC_SERVER_DEFAULT_CERT_FILE) - 1,
    0
  );
  intern->keyfile = zend_string_init(
    QUIC_SERVER_DEFAULT_KEY_FILE,
    sizeof(QUIC_SERVER_DEFAULT_KEY_FILE) - 1,
    0
  );
  intern->response = zend_string_init(
    QUIC_SERVER_DEFAULT_RESPONSE,
    sizeof(QUIC_SERVER_DEFAULT_RESPONSE) - 1,
    0
  );
  intern->local_addrlen = 0;
  intern->peer = NULL;

  zend_object_std_init(&intern->std, class_type);
  object_properties_init(&intern->std, class_type);
  intern->std.handlers = &quic_server_connection_handlers;

  return &intern->std;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_server_construct, 0, 0, 2)
  ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
  ZEND_ARG_TYPE_MASK(0, port, MAY_BE_LONG | MAY_BE_STRING, NULL)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_server_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_server_get_stream, 0, 0, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_server_get_timeout, 0, 0, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_server_is_handshake_complete, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_quic_server_pop_accepted_stream, 0, 0, Quic\\Stream, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_server_get_address, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_server_close, 0, 0, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, errorCode, IS_LONG, 1, "null")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, reason, IS_STRING, 0, "\"\"")
ZEND_END_ARG_INFO()

PHP_METHOD(Quic_ServerConnection, __construct)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);
  zend_string *host;
  zend_string *port = NULL;
  zval *port_value;
  zval *options = NULL;

  ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_STR(host)
    Z_PARAM_ZVAL(port_value)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY(options)
  ZEND_PARSE_PARAMETERS_END();

  if (ZSTR_LEN(host) == 0) {
    zend_argument_must_not_be_empty_error(1);
    RETURN_THROWS();
  }

  port = quic_server_port_to_string(port_value);
  if (port == NULL) {
    RETURN_THROWS();
  }

  intern->host = zend_string_copy(host);
  intern->port = port;

  if (!quic_server_bind_socket(intern)) {
    RETURN_THROWS();
  }

  if (options != NULL) {
    if (intern->alpn != NULL) {
      zend_string_release(intern->alpn);
      intern->alpn = NULL;
    }
    if (intern->certfile != NULL) {
      zend_string_release(intern->certfile);
      intern->certfile = NULL;
    }
    if (intern->keyfile != NULL) {
      zend_string_release(intern->keyfile);
      intern->keyfile = NULL;
    }
    if (intern->response != NULL) {
      zend_string_release(intern->response);
      intern->response = NULL;
    }

    if (!quic_server_apply_options(intern, Z_ARRVAL_P(options))) {
      RETURN_THROWS();
    }
  }
}

PHP_METHOD(Quic_ServerConnection, getStream)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);
  php_stream *stream;
  php_socket_t dup_fd;

  if (intern->fd < 0) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Socket is closed");
    RETURN_THROWS();
  }

  dup_fd = dup(intern->fd);
  if (dup_fd < 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      errno,
      "dup() failed: %s",
      strerror(errno)
    );
    RETURN_THROWS();
  }

  stream = php_stream_sock_open_from_socket(dup_fd, NULL);
  if (stream == NULL) {
    close(dup_fd);
    zend_throw_exception_ex(quic_exception_ce, 0, "Failed to create PHP stream from socket");
    RETURN_THROWS();
  }

  php_stream_to_zval(stream, return_value);
}

PHP_METHOD(Quic_ServerConnection, accept)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);

  if (!quic_server_process_readable(intern)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ServerConnection, handleReadable)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);

  if (!quic_server_process_readable(intern)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ServerConnection, handleExpiry)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);

  if (!quic_server_process_expiry(intern)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ServerConnection, flush)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);

  if (!quic_server_flush_packets(intern)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ServerConnection, getTimeout)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);
  quic_server_peer_state *peer = intern->peer;
  ngtcp2_tstamp expiry;
  uint64_t now;
  uint64_t delta_ms;

  if (peer == NULL || peer->conn == NULL) {
    RETURN_NULL();
  }

  expiry = ngtcp2_conn_get_expiry(peer->conn);

  now = quic_server_timestamp();
  if (EG(exception) != NULL) {
    RETURN_THROWS();
  }

  if (expiry <= now) {
    RETURN_LONG(0);
  }

  delta_ms = (expiry - now) / NGTCP2_MILLISECONDS;

  RETURN_LONG((zend_long) delta_ms);
}

PHP_METHOD(Quic_ServerConnection, isHandshakeComplete)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);

  RETURN_BOOL(intern->peer != NULL && intern->peer->handshake_complete);
}

PHP_METHOD(Quic_ServerConnection, popAcceptedStream)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);
  quic_stream_state *state;

  if (intern->peer == NULL) {
    RETURN_NULL();
  }

  state = quic_server_pop_accepted_stream_state(intern->peer);
  if (state == NULL) {
    RETURN_NULL();
  }

  quic_stream_object_init(return_value, state);
}

PHP_METHOD(Quic_ServerConnection, close)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);
  quic_server_peer_state *peer = intern->peer;
  zval *error_code = NULL;
  zend_string *reason = NULL;
  ngtcp2_ccerr ccerr;
  bool ok = true;

  ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(error_code)
    Z_PARAM_STR_OR_NULL(reason)
  ZEND_PARSE_PARAMETERS_END();

  if (error_code != NULL && Z_TYPE_P(error_code) != IS_NULL && Z_TYPE_P(error_code) != IS_LONG) {
    zend_argument_type_error(1, "must be of type ?int");
    RETURN_THROWS();
  }

  ngtcp2_ccerr_default(&ccerr);

  if (error_code != NULL && Z_TYPE_P(error_code) == IS_LONG) {
    ngtcp2_ccerr_set_application_error(
      &ccerr,
      (uint64_t) Z_LVAL_P(error_code),
      reason != NULL ? (const uint8_t *) ZSTR_VAL(reason) : NULL,
      reason != NULL ? ZSTR_LEN(reason) : 0
    );
  } else if (reason != NULL && ZSTR_LEN(reason) > 0) {
    ngtcp2_ccerr_set_transport_error(
      &ccerr,
      NGTCP2_NO_ERROR,
      (const uint8_t *) ZSTR_VAL(reason),
      ZSTR_LEN(reason)
    );
  }

  if (peer != NULL && peer->started && peer->conn != NULL) {
    ok = quic_server_write_connection_close_packet(intern, &ccerr);
  }

  quic_server_reset_connection_state(intern);

  if (intern->fd >= 0) {
    close(intern->fd);
    intern->fd = -1;
  }

  if (!ok) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ServerConnection, getPeerAddress)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);

  quic_server_address_to_array(
    return_value,
    intern->peer != NULL ? (const struct sockaddr *) &intern->peer->peer_addr : NULL,
    intern->peer != NULL ? intern->peer->peer_addrlen : 0
  );
}

PHP_METHOD(Quic_ServerConnection, getLocalAddress)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);

  quic_server_address_to_array(
    return_value,
    (const struct sockaddr *) &intern->local_addr,
    intern->local_addrlen
  );
}

static const zend_function_entry quic_server_connection_methods[] = {
  PHP_ME(Quic_ServerConnection, __construct, arginfo_quic_server_construct, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, getStream, arginfo_quic_server_get_stream, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, accept, arginfo_quic_server_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, handleReadable, arginfo_quic_server_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, handleExpiry, arginfo_quic_server_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, flush, arginfo_quic_server_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, getTimeout, arginfo_quic_server_get_timeout, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, isHandshakeComplete, arginfo_quic_server_is_handshake_complete, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, popAcceptedStream, arginfo_quic_server_pop_accepted_stream, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, close, arginfo_quic_server_close, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, getPeerAddress, arginfo_quic_server_get_address, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, getLocalAddress, arginfo_quic_server_get_address, ZEND_ACC_PUBLIC)
  PHP_FE_END
};

void quic_server_register_classes(void)
{
  zend_class_entry ce;

  INIT_NS_CLASS_ENTRY(ce, "Quic", "ServerConnection", quic_server_connection_methods);
  quic_server_connection_ce = zend_register_internal_class(&ce);
  quic_server_connection_ce->create_object = quic_server_connection_create_object;

  memcpy(&quic_server_connection_handlers, &std_object_handlers, sizeof(zend_object_handlers));
  quic_server_connection_handlers.offset = XtOffsetOf(quic_server_connection_object, std);
  quic_server_connection_handlers.free_obj = quic_server_connection_free_object;
}
