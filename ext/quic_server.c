#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_server.h"
#include "quic_stream.h"

zend_class_entry *quic_server_connection_ce;

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_server_construct, 0, 0, 2)
  ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
  ZEND_ARG_TYPE_MASK(0, port, MAY_BE_LONG | MAY_BE_STRING, NULL)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_server_void, 0, 0, 0)
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
  zend_string *host;
  zval *port;
  zval *options = NULL;

  ZEND_PARSE_PARAMETERS_START(2, 3)
    Z_PARAM_STR(host)
    Z_PARAM_ZVAL(port)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY(options)
  ZEND_PARSE_PARAMETERS_END();

  if (ZSTR_LEN(host) == 0) {
    zend_argument_must_not_be_empty_error(1);
    RETURN_THROWS();
  }

  if (Z_TYPE_P(port) == IS_LONG && Z_LVAL_P(port) <= 0) {
    zend_argument_value_error(2, "must be greater than 0");
    RETURN_THROWS();
  }

  if (Z_TYPE_P(port) == IS_STRING && Z_STRLEN_P(port) == 0) {
    zend_argument_must_not_be_empty_error(2);
    RETURN_THROWS();
  }
}

PHP_METHOD(Quic_ServerConnection, getStream)
{
  quic_throw_not_implemented("Quic\\ServerConnection::getStream");
  RETURN_THROWS();
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

  quic_throw_not_implemented("Quic\\ServerConnection::close");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ServerConnection, getPeerAddress)
{
  array_init(return_value);
}

PHP_METHOD(Quic_ServerConnection, getLocalAddress)
{
  array_init(return_value);
}

static const zend_function_entry quic_server_connection_methods[] = {
  PHP_ME(Quic_ServerConnection, __construct, arginfo_quic_server_construct, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ServerConnection, getStream, arginfo_quic_server_void, ZEND_ACC_PUBLIC)
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
}
