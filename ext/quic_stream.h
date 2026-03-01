#ifndef PHP_QUIC_STREAM_H
#define PHP_QUIC_STREAM_H

#include "php_quic.h"

#include <stdbool.h>

typedef enum _quic_stream_owner_kind {
  QUIC_STREAM_OWNER_NONE = 0,
  QUIC_STREAM_OWNER_CLIENT = 1,
  QUIC_STREAM_OWNER_SERVER = 2,
} quic_stream_owner_kind;

typedef struct _quic_stream_state {
  quic_stream_owner_kind owner_kind;
  void *owner;
  int64_t stream_id;
  uint8_t *read_buffer;
  size_t read_buffer_len;
  size_t read_buffer_cap;
  uint8_t *write_buffer;
  size_t write_buffer_len;
  size_t write_buffer_cap;
  size_t write_buffer_off;
  bool read_stopped;
  bool write_reset;
  bool fin_requested;
  bool fin_sent;
  bool peer_fin_received;
  bool peer_reset_received;
  bool closed;
  uint64_t peer_reset_error_code;
  uint64_t peer_reset_final_size;
  uint32_t refcount;
} quic_stream_state;

extern zend_class_entry *quic_stream_ce;

quic_stream_state *quic_stream_state_create(
  quic_stream_owner_kind owner_kind,
  void *owner,
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
void quic_stream_state_mark_read_stopped(quic_stream_state *state);
void quic_stream_state_mark_write_reset(quic_stream_state *state);
void quic_stream_state_mark_peer_fin(quic_stream_state *state);
void quic_stream_state_mark_peer_reset(
  quic_stream_state *state,
  uint64_t final_size,
  uint64_t app_error_code
);
void quic_stream_state_mark_closed(quic_stream_state *state);
void quic_stream_state_detach(quic_stream_state *state);
void quic_stream_object_init(zval *zv, quic_stream_state *state);

#endif
