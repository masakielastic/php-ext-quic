#ifndef PHP_QUIC_SERVER_H
#define PHP_QUIC_SERVER_H

#include "php_quic.h"
#include "quic_stream.h"

typedef struct _quic_server_connection_object quic_server_connection_object;
typedef struct _quic_server_peer_state quic_server_peer_state;

extern zend_class_entry *quic_server_connection_ce;

bool quic_server_shutdown_stream(
  quic_server_peer_state *peer,
  quic_stream_state *state,
  uint64_t app_error_code,
  bool stop_read,
  bool stop_write
);

#endif
