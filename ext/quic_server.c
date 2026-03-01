#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_server.h"

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

struct _quic_server_connection_object {
  php_socket_t fd;
  zend_string *host;
  zend_string *port;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  zend_object std;
};

zend_class_entry *quic_server_connection_ce;

static zend_object_handlers quic_server_connection_handlers;

static inline quic_server_connection_object *quic_server_connection_from_obj(zend_object *object)
{
  return (quic_server_connection_object *) ((char *) object - XtOffsetOf(quic_server_connection_object, std));
}

#define Z_QUIC_SERVER_CONNECTION_P(zv) \
  quic_server_connection_from_obj(Z_OBJ_P((zv)))

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
  zend_throw_exception_ex(quic_exception_ce, 0, "Failed to bind UDP socket");
  return false;
}

static void quic_server_connection_free_object(zend_object *object)
{
  quic_server_connection_object *intern = quic_server_connection_from_obj(object);

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

static zend_object *quic_server_connection_create_object(zend_class_entry *class_type)
{
  quic_server_connection_object *intern;

  intern = zend_object_alloc(sizeof(quic_server_connection_object), class_type);
  intern->fd = -1;
  intern->host = NULL;
  intern->port = NULL;
  intern->local_addrlen = 0;

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

  (void) options;

  port = quic_server_port_to_string(port_value);
  if (port == NULL) {
    RETURN_THROWS();
  }

  intern->host = zend_string_copy(host);
  intern->port = port;

  if (!quic_server_bind_socket(intern)) {
    RETURN_THROWS();
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
  quic_throw_not_implemented("Quic\\ServerConnection::accept");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ServerConnection, handleReadable)
{
  quic_throw_not_implemented("Quic\\ServerConnection::handleReadable");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ServerConnection, handleExpiry)
{
  quic_throw_not_implemented("Quic\\ServerConnection::handleExpiry");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ServerConnection, flush)
{
  quic_throw_not_implemented("Quic\\ServerConnection::flush");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ServerConnection, getTimeout)
{
  RETURN_NULL();
}

PHP_METHOD(Quic_ServerConnection, isHandshakeComplete)
{
  RETURN_FALSE;
}

PHP_METHOD(Quic_ServerConnection, popAcceptedStream)
{
  RETURN_NULL();
}

PHP_METHOD(Quic_ServerConnection, close)
{
  quic_server_connection_object *intern = Z_QUIC_SERVER_CONNECTION_P(ZEND_THIS);
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

PHP_METHOD(Quic_ServerConnection, getPeerAddress)
{
  array_init(return_value);
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
