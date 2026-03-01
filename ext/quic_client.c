#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_client.h"
#include "quic_stream.h"

zend_class_entry *quic_client_connection_ce;

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_client_construct, 0, 0, 2)
  ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
  ZEND_ARG_TYPE_MASK(0, port, MAY_BE_LONG | MAY_BE_STRING, NULL)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
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

PHP_METHOD(Quic_ClientConnection, getStream)
{
  quic_throw_not_implemented("Quic\\ClientConnection::getStream");
  RETURN_THROWS();
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

  quic_throw_not_implemented("Quic\\ClientConnection::close");
  RETURN_THROWS();
}

PHP_METHOD(Quic_ClientConnection, getPeerAddress)
{
  array_init(return_value);
}

PHP_METHOD(Quic_ClientConnection, getLocalAddress)
{
  array_init(return_value);
}

static const zend_function_entry quic_client_connection_methods[] = {
  PHP_ME(Quic_ClientConnection, __construct, arginfo_quic_client_construct, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_ClientConnection, getStream, arginfo_quic_client_void, ZEND_ACC_PUBLIC)
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
}
