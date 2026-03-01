#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_stream.h"

zend_class_entry *quic_stream_ce;

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_stream_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_get_id, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_write, 0, 1, IS_LONG, 0)
  ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, fin, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_read, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_bool, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Quic_Stream, getId)
{
  quic_throw_not_implemented("Quic\\Stream::getId");
  RETURN_THROWS();
}

PHP_METHOD(Quic_Stream, write)
{
  zend_string *data;
  bool fin = false;

  ZEND_PARSE_PARAMETERS_START(1, 2)
    Z_PARAM_STR(data)
    Z_PARAM_OPTIONAL
    Z_PARAM_BOOL(fin)
  ZEND_PARSE_PARAMETERS_END();

  if (ZSTR_LEN(data) == 0 && !fin) {
    zend_argument_must_not_be_empty_error(1);
    RETURN_THROWS();
  }

  quic_throw_not_implemented("Quic\\Stream::write");
  RETURN_THROWS();
}

PHP_METHOD(Quic_Stream, read)
{
  RETURN_EMPTY_STRING();
}

PHP_METHOD(Quic_Stream, isReadable)
{
  RETURN_FALSE;
}

PHP_METHOD(Quic_Stream, isWritable)
{
  RETURN_FALSE;
}

PHP_METHOD(Quic_Stream, isFinished)
{
  RETURN_FALSE;
}

PHP_METHOD(Quic_Stream, close)
{
  quic_throw_not_implemented("Quic\\Stream::close");
  RETURN_THROWS();
}

static const zend_function_entry quic_stream_methods[] = {
  PHP_ME(Quic_Stream, getId, arginfo_quic_stream_get_id, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, write, arginfo_quic_stream_write, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, read, arginfo_quic_stream_read, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isReadable, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isWritable, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isFinished, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, close, arginfo_quic_stream_void, ZEND_ACC_PUBLIC)
  PHP_FE_END
};

void quic_stream_register_classes(void)
{
  zend_class_entry ce;

  INIT_NS_CLASS_ENTRY(ce, "Quic", "Stream", quic_stream_methods);
  quic_stream_ce = zend_register_internal_class(&ce);
}
