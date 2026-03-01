#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_client.h"
#include "quic_stream.h"

#include "main/php_network.h"
#include "main/php_streams.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct _quic_client_connection_object {
  php_socket_t fd;
  zend_string *host;
  zend_string *port;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct sockaddr_storage peer_addr;
  socklen_t peer_addrlen;
  zend_object std;
} quic_client_connection_object;

zend_class_entry *quic_client_connection_ce;

static zend_object_handlers quic_client_connection_handlers;

static inline quic_client_connection_object *quic_client_connection_from_obj(zend_object *object)
{
  return (quic_client_connection_object *) ((char *) object - XtOffsetOf(quic_client_connection_object, std));
}

#define Z_QUIC_CLIENT_CONNECTION_P(zv) \
  quic_client_connection_from_obj(Z_OBJ_P((zv)))

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
        zend_throw_exception_ex(
          quic_exception_ce,
          errno,
          "getsockname() failed: %s",
          strerror(errno)
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

    close(fd);
  }

  freeaddrinfo(result);

  zend_throw_exception_ex(
    quic_exception_ce,
    errno,
    "Could not connect UDP socket to %s:%s: %s",
    ZSTR_VAL(host),
    ZSTR_VAL(port),
    strerror(errno)
  );

  return false;
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

  zend_object_std_dtor(&intern->std);
}

static zend_object *quic_client_connection_create_object(zend_class_entry *class_type)
{
  quic_client_connection_object *intern;

  intern = zend_object_alloc(sizeof(quic_client_connection_object), class_type);
  intern->fd = -1;
  intern->host = NULL;
  intern->port = NULL;
  intern->local_addrlen = 0;
  intern->peer_addrlen = 0;

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

PHP_METHOD(Quic_ClientConnection, startHandshake)
{
  quic_throw_not_implemented("Quic\\ClientConnection::startHandshake");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ClientConnection, handleReadable)
{
  quic_throw_not_implemented("Quic\\ClientConnection::handleReadable");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ClientConnection, handleExpiry)
{
  quic_throw_not_implemented("Quic\\ClientConnection::handleExpiry");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ClientConnection, flush)
{
  quic_throw_not_implemented("Quic\\ClientConnection::flush");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ClientConnection, getTimeout)
{
  RETURN_NULL();
}

PHP_METHOD(Quic_ClientConnection, isHandshakeComplete)
{
  RETURN_FALSE;
}

PHP_METHOD(Quic_ClientConnection, openBidirectionalStream)
{
  quic_throw_not_implemented("Quic\\ClientConnection::openBidirectionalStream");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ClientConnection, close)
{
  quic_client_connection_object *intern = Z_QUIC_CLIENT_CONNECTION_P(ZEND_THIS);
  zval *error_code = NULL;
  zend_string *reason = NULL;

  ZEND_PARSE_PARAMETERS_START(0, 2)
    Z_PARAM_OPTIONAL
    Z_PARAM_ZVAL(error_code)
    Z_PARAM_STR_OR_NULL(reason)
  ZEND_PARSE_PARAMETERS_END();

  if (error_code != NULL && Z_TYPE_P(error_code) != IS_NULL && Z_TYPE_P(error_code) != IS_LONG) {
    zend_argument_type_error(1, "must be of type ?int");
    RETURN_THROWS();
  }

  (void) reason;

  if (intern->fd >= 0) {
    close(intern->fd);
    intern->fd = -1;
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
