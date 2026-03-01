#ifndef PHP_QUIC_STREAM_H
#define PHP_QUIC_STREAM_H

#include "php_quic.h"
#include "quic_client.h"

#include <stdbool.h>

typedef struct _quic_stream_state {
  quic_client_connection_object *client;
  int64_t stream_id;
  uint8_t *read_buffer;
  size_t read_buffer_len;
  size_t read_buffer_cap;
  uint8_t *write_buffer;
  size_t write_buffer_len;
  size_t write_buffer_cap;
  size_t write_buffer_off;
  bool fin_requested;
  bool fin_sent;
  bool peer_fin_received;
  bool closed;
  uint32_t refcount;
} quic_stream_state;

extern zend_class_entry *quic_stream_ce;

quic_stream_state *quic_stream_state_create(
  quic_client_connection_object *client,
  int64_t stream_id
);
void quic_stream_state_addref(quic_stream_state *state);
void quic_stream_state_release(quic_stream_state *state);
bool quic_stream_state_append_read(
  quic_stream_state *state,
  const uint8_t *data,
  size_t datalen
);
bool quic_stream_state_append_write(
  quic_stream_state *state,
  const uint8_t *data,
  size_t datalen
);
bool quic_stream_state_has_pending_write(quic_stream_state *state);
void quic_stream_state_mark_write_progress(
  quic_stream_state *state,
  size_t bytes_written,
  bool fin_attempted,
  bool packet_emitted
);
void quic_stream_state_mark_peer_fin(quic_stream_state *state);
void quic_stream_state_mark_closed(quic_stream_state *state);
void quic_stream_state_detach(quic_stream_state *state);
void quic_stream_object_init(zval *zv, quic_stream_state *state);

#endif
