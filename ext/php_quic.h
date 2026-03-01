#ifndef PHP_QUIC_H
#define PHP_QUIC_H

#include "php.h"
#include "Zend/zend_exceptions.h"

#define PHP_QUIC_EXTNAME "quic"
#define PHP_QUIC_VERSION "0.1.0"

extern zend_module_entry quic_module_entry;
#define phpext_quic_ptr &quic_module_entry

extern zend_class_entry *quic_exception_ce;
extern zend_class_entry *quic_tls_exception_ce;
extern zend_class_entry *quic_protocol_exception_ce;

void quic_client_register_classes(void);
void quic_server_register_classes(void);
void quic_stream_register_classes(void);

#endif
