#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php_quic.h"
#include "quic_client.h"
#include "quic_server.h"
#include "quic_stream.h"

#include "ext/standard/info.h"

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <ngtcp2/version.h>

zend_class_entry *quic_exception_ce;
zend_class_entry *quic_tls_exception_ce;
zend_class_entry *quic_protocol_exception_ce;

static void quic_touch_dependencies(void)
{
  (void) gnutls_check_version(NULL);
  (void) ngtcp2_conn_get_expiry;
  (void) ngtcp2_crypto_gnutls_configure_client_session;
}

PHP_MINIT_FUNCTION(quic)
{
  zend_class_entry ce;
  int rv;

  rv = gnutls_global_init();
  if (rv != 0) {
    return FAILURE;
  }

  quic_touch_dependencies();

  INIT_NS_CLASS_ENTRY(ce, "Quic", "Exception", NULL);
  quic_exception_ce = zend_register_internal_class_ex(&ce, zend_ce_exception);

  INIT_NS_CLASS_ENTRY(ce, "Quic", "TlsException", NULL);
  quic_tls_exception_ce =
    zend_register_internal_class_ex(&ce, quic_exception_ce);

  INIT_NS_CLASS_ENTRY(ce, "Quic", "ProtocolException", NULL);
  quic_protocol_exception_ce =
    zend_register_internal_class_ex(&ce, quic_exception_ce);

  quic_client_register_classes();
  quic_server_register_classes();
  quic_stream_register_classes();

  return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(quic)
{
  gnutls_global_deinit();

  return SUCCESS;
}

PHP_MINFO_FUNCTION(quic)
{
  php_info_print_table_start();
  php_info_print_table_row(2, "quic support", "enabled");
  php_info_print_table_row(2, "extension version", PHP_QUIC_VERSION);
  php_info_print_table_row(2, "ngtcp2 headers", NGTCP2_VERSION);
  php_info_print_table_row(2, "GnuTLS runtime", gnutls_check_version(NULL));
  php_info_print_table_end();
}

zend_module_entry quic_module_entry = {
  STANDARD_MODULE_HEADER,
  PHP_QUIC_EXTNAME,
  NULL,
  PHP_MINIT(quic),
  PHP_MSHUTDOWN(quic),
  NULL,
  NULL,
  PHP_MINFO(quic),
  PHP_QUIC_VERSION,
  STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_QUIC
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(quic)
#endif
