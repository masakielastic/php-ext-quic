#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_client.h"
#include "quic_stream.h"

#include "main/php_network.h"
#include "main/php_streams.h"

#include <arpa/inet.h>
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

#define QUIC_CLIENT_DEFAULT_ALPN "hq-interop"

struct _quic_client_connection_object {
  php_socket_t fd;
  zend_string *host;
  zend_string *port;
  zend_string *alpn;
  zend_string *server_name;
  zend_string *cafile;
  zend_string *capath;
  bool verify_peer;
  bool started;
  bool handshake_complete;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct sockaddr_storage peer_addr;
  socklen_t peer_addrlen;
  ngtcp2_crypto_conn_ref conn_ref;
  gnutls_certificate_credentials_t cred;
  gnutls_session_t session;
  ngtcp2_conn *conn;
  ngtcp2_ccerr last_error;
  HashTable streams;
  zend_object std;
};

zend_class_entry *quic_client_connection_ce;

static zend_object_handlers quic_client_connection_handlers;

static const char quic_client_tls_priority[] =
  "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
  "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
  "+GROUP-SECP384R1:+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

static inline quic_client_connection_object *quic_client_connection_from_obj(zend_object *object)
{
  return (quic_client_connection_object *) ((char *) object - XtOffsetOf(quic_client_connection_object, std));
}

#define Z_QUIC_CLIENT_CONNECTION_P(zv) \
  quic_client_connection_from_obj(Z_OBJ_P((zv)))

static size_t quic_client_stream_key(char *buffer, size_t buffer_len, int64_t stream_id)
{
  return (size_t) snprintf(buffer, buffer_len, "%" PRId64, stream_id);
}

static quic_stream_state *quic_client_find_stream_state(
  quic_client_connection_object *intern,
  int64_t stream_id
)
{
  char key[32];
  size_t key_len;

  key_len = quic_client_stream_key(key, sizeof(key), stream_id);

  return zend_hash_str_find_ptr(&intern->streams, key, key_len);
}

static bool quic_client_register_stream_state(
  quic_client_connection_object *intern,
  quic_stream_state *state
)
{
  char key[32];
  size_t key_len;

  key_len = quic_client_stream_key(key, sizeof(key), state->stream_id);

  quic_stream_state_addref(state);
  if (zend_hash_str_update_ptr(&intern->streams, key, key_len, state) == NULL) {
    quic_stream_state_release(state);
    zend_throw_exception_ex(quic_exception_ce, 0, "Failed to register stream state");
    return false;
  }

  return true;
}

static quic_stream_state *quic_client_get_next_writable_stream(
  quic_client_connection_object *intern
)
{
  quic_stream_state *state;

  ZEND_HASH_FOREACH_PTR(&intern->streams, state) {
    if (quic_stream_state_has_pending_write(state)) {
      return state;
    }
  } ZEND_HASH_FOREACH_END();

  return NULL;
}

static bool quic_client_fill_random(void *dest, size_t destlen)
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

static uint64_t quic_client_timestamp(void)
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

static int quic_client_numeric_host_family(const char *hostname, int family)
{
  uint8_t buffer[sizeof(struct in6_addr)];

  return inet_pton(family, hostname, buffer) == 1;
}

static int quic_client_numeric_host(const char *hostname)
{
  return quic_client_numeric_host_family(hostname, AF_INET) ||
    quic_client_numeric_host_family(hostname, AF_INET6);
}

static ngtcp2_conn *quic_client_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  quic_client_connection_object *intern = conn_ref->user_data;

  return intern->conn;
}

static void quic_client_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
  (void) rand_ctx;

  if (gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen) != 0) {
    abort();
  }
}

static int quic_client_get_new_connection_id_cb(
  ngtcp2_conn *conn,
  ngtcp2_cid *cid,
  uint8_t *token,
  size_t cidlen,
  void *user_data
)
{
  (void) conn;
  (void) user_data;

  if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int quic_client_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
  quic_client_connection_object *intern = user_data;

  (void) conn;

  intern->handshake_complete = true;

  return 0;
}

static int quic_client_stream_close_cb(
  ngtcp2_conn *conn,
  uint32_t flags,
  int64_t stream_id,
  uint64_t app_error_code,
  void *user_data,
  void *stream_user_data
)
{
  quic_client_connection_object *intern = user_data;
  quic_stream_state *state = stream_user_data;

  (void) conn;
  (void) flags;
  (void) app_error_code;

  if (state == NULL) {
    state = quic_client_find_stream_state(intern, stream_id);
  }

  if (state != NULL) {
    quic_stream_state_mark_closed(state);
  }

  return 0;
}

static int quic_client_recv_stream_data_cb(
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
  quic_client_connection_object *intern = user_data;
  quic_stream_state *state = stream_user_data;

  (void) conn;
  (void) offset;

  if (state == NULL) {
    state = quic_client_find_stream_state(intern, stream_id);
  }

  if (state == NULL) {
    return 0;
  }

  if (datalen > 0 && !quic_stream_state_append_read(state, data, datalen)) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
    quic_stream_state_mark_peer_fin(state);
  }

  return 0;
}

static void quic_client_reset_connection_state(quic_client_connection_object *intern)
{
  quic_stream_state *state;

  if (intern->conn != NULL) {
    ngtcp2_conn_del(intern->conn);
    intern->conn = NULL;
  }

  if (intern->session != NULL) {
    gnutls_deinit(intern->session);
    intern->session = NULL;
  }

  if (intern->cred != NULL) {
    gnutls_certificate_free_credentials(intern->cred);
    intern->cred = NULL;
  }

  ZEND_HASH_FOREACH_PTR(&intern->streams, state) {
    quic_stream_state_detach(state);
    quic_stream_state_release(state);
  } ZEND_HASH_FOREACH_END();
  zend_hash_clean(&intern->streams);

  intern->started = false;
  intern->handshake_complete = false;
  ngtcp2_ccerr_default(&intern->last_error);
}

static zend_string *quic_client_port_to_string(zval *port)
{
  char buffer[32];
  int length;

  if (Z_TYPE_P(port) == IS_LONG) {
    if (Z_LVAL_P(port) <= 0 || Z_LVAL_P(port) > 65535) {
      zend_argument_value_error(2, "must be between 1 and 65535");
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

static zend_string *quic_client_get_string_option(HashTable *options, const char *key)
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

static bool quic_client_get_bool_option(HashTable *options, const char *key, bool default_value)
{
  zval *value = zend_hash_str_find(options, key, strlen(key));

  if (value == NULL) {
    return default_value;
  }

  if (Z_TYPE_P(value) != IS_TRUE && Z_TYPE_P(value) != IS_FALSE) {
    zend_type_error("Option \"%s\" must be of type bool", key);
    return default_value;
  }

  return Z_TYPE_P(value) == IS_TRUE;
}

static bool quic_client_apply_options(quic_client_connection_object *intern, zval *options)
{
  zend_string *alpn;
  zend_string *server_name;
  zend_string *cafile;
  zend_string *capath;

  if (options == NULL) {
    return true;
  }

  alpn = quic_client_get_string_option(Z_ARRVAL_P(options), "alpn");
  if (EG(exception) != NULL) {
    return false;
  }

  server_name = quic_client_get_string_option(Z_ARRVAL_P(options), "server_name");
  if (EG(exception) != NULL) {
    if (alpn != NULL) {
      zend_string_release(alpn);
    }
    return false;
  }

  cafile = quic_client_get_string_option(Z_ARRVAL_P(options), "cafile");
  if (EG(exception) != NULL) {
    if (alpn != NULL) {
      zend_string_release(alpn);
    }
    if (server_name != NULL) {
      zend_string_release(server_name);
    }
    return false;
  }

  capath = quic_client_get_string_option(Z_ARRVAL_P(options), "capath");
  if (EG(exception) != NULL) {
    if (alpn != NULL) {
      zend_string_release(alpn);
    }
    if (server_name != NULL) {
      zend_string_release(server_name);
    }
    if (cafile != NULL) {
      zend_string_release(cafile);
    }
    return false;
  }

  if (alpn != NULL) {
    zend_string_release(intern->alpn);
    intern->alpn = alpn;
  }

  if (server_name != NULL) {
    if (intern->server_name != NULL) {
      zend_string_release(intern->server_name);
    }
    intern->server_name = server_name;
  }

  if (cafile != NULL) {
    if (intern->cafile != NULL) {
      zend_string_release(intern->cafile);
    }
    intern->cafile = cafile;
  }

  if (capath != NULL) {
    if (intern->capath != NULL) {
      zend_string_release(intern->capath);
    }
    intern->capath = capath;
  }

  intern->verify_peer = quic_client_get_bool_option(Z_ARRVAL_P(options), "verify_peer", intern->verify_peer);

  return EG(exception) == NULL;
}

static bool quic_client_set_nonblocking(php_socket_t fd)
{
  int flags = fcntl(fd, F_GETFL, 0);

  if (flags < 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      errno,
      "fcntl(F_GETFL) failed: %s",
      strerror(errno)
    );
    return false;
  }

  if ((flags & O_NONBLOCK) == 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
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

static bool quic_client_connect_socket(
  quic_client_connection_object *intern,
  zend_string *host,
  zend_string *port
)
{
  struct addrinfo hints = {0};
  struct addrinfo *result = NULL;
  struct addrinfo *rp;
  int rv;
  int saved_errno = 0;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rv = getaddrinfo(ZSTR_VAL(host), ZSTR_VAL(port), &hints, &result);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_exception_ce,
      0,
      "getaddrinfo(%s, %s) failed: %s",
      ZSTR_VAL(host),
      ZSTR_VAL(port),
      gai_strerror(rv)
    );
    return false;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    php_socket_t fd;

    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) {
      saved_errno = errno;
      continue;
    }

    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      socklen_t local_addrlen = sizeof(intern->local_addr);

      if (!quic_client_set_nonblocking(fd)) {
        close(fd);
        freeaddrinfo(result);
        return false;
      }

      if (getsockname(fd, (struct sockaddr *) &intern->local_addr, &local_addrlen) != 0) {
        saved_errno = errno;
        zend_throw_exception_ex(
          quic_exception_ce,
          saved_errno,
          "getsockname() failed: %s",
          strerror(saved_errno)
        );
        close(fd);
        freeaddrinfo(result);
        return false;
      }

      intern->fd = fd;
      intern->local_addrlen = local_addrlen;
      intern->peer_addrlen = rp->ai_addrlen;
      memcpy(&intern->peer_addr, rp->ai_addr, rp->ai_addrlen);

      freeaddrinfo(result);
      return true;
    }

    saved_errno = errno;
    close(fd);
  }

  freeaddrinfo(result);

  zend_throw_exception_ex(
    quic_exception_ce,
    saved_errno,
    "Could not connect UDP socket to %s:%s: %s",
    ZSTR_VAL(host),
    ZSTR_VAL(port),
    strerror(saved_errno)
  );

  return false;
}

static bool quic_client_load_trust_store(quic_client_connection_object *intern)
{
  int rv;
  int loaded = 0;

  if (!intern->verify_peer) {
    return true;
  }

  if (intern->cafile != NULL) {
    rv = gnutls_certificate_set_x509_trust_file(
      intern->cred,
      ZSTR_VAL(intern->cafile),
      GNUTLS_X509_FMT_PEM
    );
    if (rv < 0) {
      zend_throw_exception_ex(
        quic_tls_exception_ce,
        rv,
        "gnutls_certificate_set_x509_trust_file(%s) failed: %s",
        ZSTR_VAL(intern->cafile),
        gnutls_strerror(rv)
      );
      return false;
    }
    loaded += rv;
  }

  if (intern->capath != NULL) {
    rv = gnutls_certificate_set_x509_trust_dir(
      intern->cred,
      ZSTR_VAL(intern->capath),
      GNUTLS_X509_FMT_PEM
    );
    if (rv < 0) {
      zend_throw_exception_ex(
        quic_tls_exception_ce,
        rv,
        "gnutls_certificate_set_x509_trust_dir(%s) failed: %s",
        ZSTR_VAL(intern->capath),
        gnutls_strerror(rv)
      );
      return false;
    }
    loaded += rv;
  }

  if (loaded > 0) {
    return true;
  }

  rv = gnutls_certificate_set_x509_system_trust(intern->cred);
  if (rv < 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_certificate_set_x509_system_trust() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  return true;
}

static bool quic_client_tls_init(quic_client_connection_object *intern)
{
  gnutls_datum_t alpn;
  const char *server_name;
  int rv;

  rv = gnutls_certificate_allocate_credentials(&intern->cred);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_certificate_allocate_credentials() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  if (!quic_client_load_trust_store(intern)) {
    return false;
  }

  rv = gnutls_init(
    &intern->session,
    GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA
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

  rv = gnutls_priority_set_direct(intern->session, quic_client_tls_priority, NULL);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_priority_set_direct() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  if (ngtcp2_crypto_gnutls_configure_client_session(intern->session) != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      0,
      "ngtcp2_crypto_gnutls_configure_client_session() failed"
    );
    return false;
  }

  rv = gnutls_credentials_set(intern->session, GNUTLS_CRD_CERTIFICATE, intern->cred);
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

  rv = gnutls_alpn_set_protocols(intern->session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_tls_exception_ce,
      rv,
      "gnutls_alpn_set_protocols() failed: %s",
      gnutls_strerror(rv)
    );
    return false;
  }

  server_name = intern->server_name != NULL ? ZSTR_VAL(intern->server_name) : NULL;
  if (server_name == NULL) {
    if (quic_client_numeric_host(ZSTR_VAL(intern->host))) {
      server_name = "localhost";
    } else {
      server_name = ZSTR_VAL(intern->host);
    }
  }

  if (server_name != NULL && *server_name != '\0') {
    rv = gnutls_server_name_set(
      intern->session,
      GNUTLS_NAME_DNS,
      server_name,
      strlen(server_name)
    );
    if (rv != 0) {
      zend_throw_exception_ex(
        quic_tls_exception_ce,
        rv,
        "gnutls_server_name_set() failed: %s",
        gnutls_strerror(rv)
      );
      return false;
    }
  }

  if (intern->verify_peer) {
    gnutls_session_set_verify_cert(intern->session, server_name, 0);
  }

  intern->conn_ref.get_conn = quic_client_get_conn;
  intern->conn_ref.user_data = intern;
  gnutls_session_set_ptr(intern->session, &intern->conn_ref);

  return true;
}

static bool quic_client_quic_init(quic_client_connection_object *intern)
{
  ngtcp2_path path = {
    .local = {
      .addr = (struct sockaddr *) &intern->local_addr,
      .addrlen = intern->local_addrlen,
    },
    .remote = {
      .addr = (struct sockaddr *) &intern->peer_addr,
      .addrlen = intern->peer_addrlen,
    },
  };
  ngtcp2_callbacks callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = quic_client_handshake_completed_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = quic_client_recv_stream_data_cb,
    .stream_close = quic_client_stream_close_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .rand = quic_client_rand_cb,
    .get_new_connection_id = quic_client_get_new_connection_id_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
  };
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  uint64_t now;
  int rv;

  now = quic_client_timestamp();
  if (EG(exception) != NULL) {
    return false;
  }

  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  if (!quic_client_fill_random(dcid.data, dcid.datalen)) {
    return false;
  }

  scid.datalen = 8;
  if (!quic_client_fill_random(scid.data, scid.datalen)) {
    return false;
  }

  ngtcp2_settings_default(&settings);
  settings.initial_ts = now;

  ngtcp2_transport_params_default(&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;

  rv = ngtcp2_conn_client_new(
    &intern->conn,
    &dcid,
    &scid,
    &path,
    NGTCP2_PROTO_VER_V1,
    &callbacks,
    &settings,
    &params,
    NULL,
    intern
  );
  if (rv != 0) {
    zend_throw_exception_ex(
      quic_protocol_exception_ce,
      rv,
      "ngtcp2_conn_client_new() failed: %s",
      ngtcp2_strerror(rv)
    );
    return false;
  }

  ngtcp2_conn_set_tls_native_handle(intern->conn, intern->session);

  return true;
}

static bool quic_client_send_packet(quic_client_connection_object *intern, const uint8_t *data, size_t datalen)
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

static bool quic_client_flush_packets(quic_client_connection_object *intern)
{
  ngtcp2_path_storage path_storage;
  ngtcp2_pkt_info packet_info;
  uint8_t buffer[1452];
  uint64_t now;

  now = quic_client_timestamp();
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
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    ngtcp2_ssize nwrite;
    ngtcp2_ssize data_written = 0;
    bool fin_attempted = false;

    state = quic_client_get_next_writable_stream(intern);
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
      intern->conn,
      &path_storage.path,
      &packet_info,
      buffer,
      sizeof(buffer),
      &data_written,
      flags,
      stream_id,
      &datav,
      stream_id >= 0 ? 1 : 0,
      now
    );

    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_WRITE_MORE) {
        if (state != NULL && data_written >= 0) {
          quic_stream_state_mark_write_progress(
            state,
            (size_t) data_written,
            fin_attempted,
            false
          );
        }
        continue;
      }

      ngtcp2_ccerr_set_liberr(&intern->last_error, (int) nwrite, NULL, 0);
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

    if (state != NULL && data_written >= 0) {
      quic_stream_state_mark_write_progress(
        state,
        (size_t) data_written,
        fin_attempted,
        true
      );
    }

    if (!quic_client_send_packet(intern, buffer, (size_t) nwrite)) {
      return false;
    }
  }
}

static bool quic_client_write_connection_close_packet(
  quic_client_connection_object *intern,
  const ngtcp2_ccerr *ccerr
)
{
  ngtcp2_path_storage path_storage;
  ngtcp2_pkt_info packet_info;
  uint8_t buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
  ngtcp2_ssize nwrite;
  uint64_t now;

  if (intern->conn == NULL) {
    return true;
  }

  if (ngtcp2_conn_in_closing_period(intern->conn) ||
      ngtcp2_conn_in_draining_period(intern->conn)) {
    return true;
  }

  now = quic_client_timestamp();
  if (EG(exception) != NULL) {
    return false;
  }

  ngtcp2_path_storage_zero(&path_storage);

  nwrite = ngtcp2_conn_write_connection_close(
    intern->conn,
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

  return quic_client_send_packet(intern, buffer, (size_t) nwrite);
}

static bool quic_client_record_protocol_error(quic_client_connection_object *intern, int rv)
{
  if (!intern->last_error.error_code) {
    if (rv == NGTCP2_ERR_CRYPTO) {
      ngtcp2_ccerr_set_tls_alert(
        &intern->last_error,
        ngtcp2_conn_get_tls_alert(intern->conn),
        NULL,
        0
      );
    } else {
      ngtcp2_ccerr_set_liberr(&intern->last_error, rv, NULL, 0);
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

static bool quic_client_handle_readable_packets(quic_client_connection_object *intern)
{
  uint8_t buffer[65536];
  struct sockaddr_storage remote_addr;
  struct iovec iov = {
    .iov_base = buffer,
    .iov_len = sizeof(buffer),
  };
  struct msghdr msg = {0};
  ngtcp2_pkt_info packet_info = {0};

  msg.msg_name = &remote_addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  for (;;) {
    ssize_t nread;
    ngtcp2_path path;
    uint64_t now;
    int rv;

    msg.msg_namelen = sizeof(remote_addr);

    nread = recvmsg(intern->fd, &msg, MSG_DONTWAIT);
    if (nread < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return true;
      }

      if (errno == ECONNREFUSED) {
        zend_throw_exception_ex(
          quic_exception_ce,
          errno,
          "recvmsg() failed: %s",
          strerror(errno)
        );
        return false;
      }

      zend_throw_exception_ex(
        quic_exception_ce,
        errno,
        "recvmsg() failed: %s",
        strerror(errno)
      );
      return false;
    }

    path.local.addr = (struct sockaddr *) &intern->local_addr;
    path.local.addrlen = intern->local_addrlen;
    path.remote.addr = msg.msg_name;
    path.remote.addrlen = msg.msg_namelen;
    path.user_data = NULL;

    now = quic_client_timestamp();
    if (EG(exception) != NULL) {
      return false;
    }

    rv = ngtcp2_conn_read_pkt(
      intern->conn,
      &path,
      &packet_info,
      buffer,
      (size_t) nread,
      now
    );
    if (rv != 0) {
      return quic_client_record_protocol_error(intern, rv);
    }
  }
}

static bool quic_client_process_expiry(quic_client_connection_object *intern)
{
  uint64_t now;
  int rv;

  now = quic_client_timestamp();
  if (EG(exception) != NULL) {
    return false;
  }

  rv = ngtcp2_conn_handle_expiry(intern->conn, now);
  if (rv != 0) {
    return quic_client_record_protocol_error(intern, rv);
  }

  return true;
}

static void quic_client_address_to_array(
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

static void quic_client_connection_free_object(zend_object *object)
{
  quic_client_connection_object *intern = quic_client_connection_from_obj(object);

  quic_client_reset_connection_state(intern);

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

  if (intern->server_name != NULL) {
    zend_string_release(intern->server_name);
    intern->server_name = NULL;
  }

  if (intern->cafile != NULL) {
    zend_string_release(intern->cafile);
    intern->cafile = NULL;
  }

  if (intern->capath != NULL) {
    zend_string_release(intern->capath);
    intern->capath = NULL;
  }

  zend_hash_destroy(&intern->streams);
  zend_object_std_dtor(&intern->std);
}

static zend_object *quic_client_connection_create_object(zend_class_entry *class_type)
{
  quic_client_connection_object *intern;

  intern = zend_object_alloc(sizeof(quic_client_connection_object), class_type);
  intern->fd = -1;
  intern->host = NULL;
  intern->port = NULL;
  intern->alpn = zend_string_init(QUIC_CLIENT_DEFAULT_ALPN, sizeof(QUIC_CLIENT_DEFAULT_ALPN) - 1, 0);
  intern->server_name = NULL;
  intern->cafile = NULL;
  intern->capath = NULL;
  intern->verify_peer = true;
  intern->started = false;
  intern->handshake_complete = false;
  intern->local_addrlen = 0;
  intern->peer_addrlen = 0;
  intern->cred = NULL;
  intern->session = NULL;
  intern->conn = NULL;
  ngtcp2_ccerr_default(&intern->last_error);
  zend_hash_init(&intern->streams, 8, NULL, NULL, 0);

  zend_object_std_init(&intern->std, class_type);
  object_properties_init(&intern->std, class_type);
  intern->std.handlers = &quic_client_connection_handlers;

  return &intern->std;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_client_construct, 0, 0, 2)
  ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
  ZEND_ARG_TYPE_MASK(0, port, MAY_BE_LONG | MAY_BE_STRING, NULL)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_client_get_stream, 0, 0, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_client_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_client_get_timeout, 0, 0, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_client_is_handshake_complete, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(arginfo_quic_client_open_bidi_stream, 0, 0, Quic\\Stream, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_client_get_address, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_client_close, 0, 0, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, errorCode, IS_LONG, 1, "null")
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, reason, IS_STRING, 0, "\"\"")
ZEND_END_ARG_INFO()

PHP_METHOD(Quic_ClientConnection, __construct)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);
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

  if (intern->fd >= 0) {
    zend_throw_error(NULL, "Cannot reinitialize Quic\\ClientConnection");
    RETURN_THROWS();
  }

  if (ZSTR_LEN(host) == 0) {
    zend_argument_must_not_be_empty_error(1);
    RETURN_THROWS();
  }

  port = quic_client_port_to_string(port_value);
  if (port == NULL) {
    RETURN_THROWS();
  }

  intern->host = zend_string_copy(host);
  intern->port = port;

  if (!quic_client_apply_options(intern, options)) {
    RETURN_THROWS();
  }

  if (!quic_client_connect_socket(intern, host, port)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ClientConnection, getStream)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);
  php_stream *stream;
  php_socket_t dup_fd;

  if (intern->fd < 0) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Connection is closed");
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
    zend_throw_exception_ex(quic_exception_ce, 0, "Failed to expose UDP socket as a PHP stream");
    RETURN_THROWS();
  }

  php_stream_to_zval(stream, return_value);
}

PHP_METHOD(Quic_ClientConnection, getPollStream)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);
  php_stream *stream;
  php_socket_t dup_fd;

  if (intern->fd < 0) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Connection is closed");
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
    zend_throw_exception_ex(quic_exception_ce, 0, "Failed to expose UDP socket as a PHP stream");
    RETURN_THROWS();
  }

  php_stream_to_zval(stream, return_value);
}

PHP_METHOD(Quic_ClientConnection, startHandshake)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);

  if (intern->fd < 0) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Connection is closed");
    RETURN_THROWS();
  }

  if (intern->started) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Handshake has already been started");
    RETURN_THROWS();
  }

  if (!quic_client_tls_init(intern) || !quic_client_quic_init(intern)) {
    quic_client_reset_connection_state(intern);
    RETURN_THROWS();
  }

  intern->started = true;
}

PHP_METHOD(Quic_ClientConnection, handleReadable)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);

  if (!intern->started || intern->conn == NULL) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Handshake has not been started");
    RETURN_THROWS();
  }

  if (!quic_client_handle_readable_packets(intern)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ClientConnection, handleExpiry)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);

  if (!intern->started || intern->conn == NULL) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Handshake has not been started");
    RETURN_THROWS();
  }

  if (!quic_client_process_expiry(intern)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ClientConnection, flush)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);

  if (!intern->started || intern->conn == NULL) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Handshake has not been started");
    RETURN_THROWS();
  }

  if (!quic_client_flush_packets(intern)) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ClientConnection, getTimeout)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);
  uint64_t now;
  uint64_t expiry;
  uint64_t delta_ms;

  if (!intern->started || intern->conn == NULL) {
    RETURN_NULL();
  }

  now = quic_client_timestamp();
  if (EG(exception) != NULL) {
    RETURN_THROWS();
  }

  expiry = ngtcp2_conn_get_expiry(intern->conn);
  if (expiry <= now) {
    RETURN_LONG(0);
  }

  delta_ms = (expiry - now) / NGTCP2_MILLISECONDS;

  RETURN_LONG((zend_long) delta_ms);
}

PHP_METHOD(Quic_ClientConnection, isHandshakeComplete)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);

  RETURN_BOOL(intern->handshake_complete);
}

PHP_METHOD(Quic_ClientConnection, openBidirectionalStream)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);
  quic_stream_state *state;
  int64_t stream_id;
  int rv;

  if (!intern->started || intern->conn == NULL) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Handshake has not been started");
    RETURN_THROWS();
  }

  if (!intern->handshake_complete) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Handshake is not complete");
    RETURN_THROWS();
  }

  state = quic_stream_state_create(QUIC_STREAM_OWNER_CLIENT, intern, -1);
  rv = ngtcp2_conn_open_bidi_stream(intern->conn, &stream_id, state);
  if (rv != 0) {
    quic_stream_state_release(state);
    zend_throw_exception_ex(
      quic_protocol_exception_ce,
      rv,
      "ngtcp2_conn_open_bidi_stream() failed: %s",
      ngtcp2_strerror(rv)
    );
    RETURN_THROWS();
  }

  state->stream_id = stream_id;

  if (!quic_client_register_stream_state(intern, state)) {
    ngtcp2_conn_set_stream_user_data(intern->conn, stream_id, NULL);
    quic_stream_state_release(state);
    RETURN_THROWS();
  }

  quic_stream_object_init(return_value, state);
}

PHP_METHOD(Quic_ClientConnection, close)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);
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

  if (intern->started && intern->conn != NULL) {
    ok = quic_client_write_connection_close_packet(intern, &ccerr);
  }

  quic_client_reset_connection_state(intern);

  if (intern->fd >= 0) {
    close(intern->fd);
    intern->fd = -1;
  }

  if (!ok) {
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ClientConnection, getPeerAddress)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);

  quic_client_address_to_array(
    return_value,
    (const struct sockaddr *) &intern->peer_addr,
    intern->peer_addrlen
  );
}

PHP_METHOD(Quic_ClientConnection, getLocalAddress)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);

  quic_client_address_to_array(
    return_value,
    (const struct sockaddr *) &intern->local_addr,
    intern->local_addrlen
  );
}

static const zend_function_entry quic_client_connection_methods[] = {
  PHP_ME(Quic_ClientConnection, __construct, arginfo_quic_client_construct, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, getPollStream, arginfo_quic_client_get_stream, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, getStream, arginfo_quic_client_get_stream, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, startHandshake, arginfo_quic_client_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, handleReadable, arginfo_quic_client_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, handleExpiry, arginfo_quic_client_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, flush, arginfo_quic_client_void, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, getTimeout, arginfo_quic_client_get_timeout, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, isHandshakeComplete, arginfo_quic_client_is_handshake_complete, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, openBidirectionalStream, arginfo_quic_client_open_bidi_stream, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, close, arginfo_quic_client_close, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, getPeerAddress, arginfo_quic_client_get_address, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, getLocalAddress, arginfo_quic_client_get_address, ZEND_ACC_PUBLIC)
  PHP_FE_END
};

void quic_client_register_classes(void)
{
  zend_class_entry ce;

  INIT_NS_CLASS_ENTRY(ce, "Quic", "ClientConnection", quic_client_connection_methods);
  quic_client_connection_ce = zend_register_internal_class(&ce);
  quic_client_connection_ce->create_object = quic_client_connection_create_object;

  memcpy(&quic_client_connection_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
  quic_client_connection_handlers.offset = XtOffsetOf(quic_client_connection_object, std);
  quic_client_connection_handlers.free_obj = quic_client_connection_free_object;
  quic_client_connection_handlers.clone_obj = NULL;
}
