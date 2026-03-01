#ifndef PHP_QUIC_CLIENT_H
#define PHP_QUIC_CLIENT_H

#include "php_quic.h"
#include "quic_stream.h"

typedef struct _quic_client_connection_object quic_client_connection_object;

extern zend_class_entry *quic_client_connection_ce;

bool quic_client_shutdown_stream(
  quic_client_connection_object *intern,
  quic_stream_state *state,
  uint64_t app_error_code,
  bool stop_read,
  bool stop_write
);

#endif
