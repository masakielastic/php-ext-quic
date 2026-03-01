#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_client.h"
#include "quic_server.h"
#include "quic_stream.h"

#include <string.h>

typedef struct _quic_stream_object {
  quic_stream_state *state;
  zend_object std;
} quic_stream_object;

zend_class_entry *quic_stream_ce;

static zend_object_handlers quic_stream_handlers;

static inline quic_stream_object *quic_stream_from_obj(zend_object *object)
{
  return (quic_stream_object *) ((char *) object - XtOffsetOf(quic_stream_object, std));
}

#define Z_QUIC_STREAM_P(zv) quic_stream_from_obj(Z_OBJ_P((zv)))

static bool quic_stream_buffer_append(
  uint8_t **buffer,
  size_t *buffer_len,
  size_t *buffer_cap,
  const uint8_t *data,
  size_t datalen
)
{
  uint8_t *new_buffer;
  size_t required;
  size_t new_cap;

  if (datalen == 0) {
    return true;
  }

  required = *buffer_len + datalen;
  if (required <= *buffer_cap) {
    memcpy(*buffer + *buffer_len, data, datalen);
    *buffer_len += datalen;
    return true;
  }

  new_cap = *buffer_cap == 0 ? 256 : *buffer_cap;
  while (new_cap < required) {
    new_cap *= 2;
  }

  new_buffer = safe_erealloc(*buffer, new_cap, sizeof(uint8_t), 0);
  *buffer = new_buffer;
  *buffer_cap = new_cap;

  memcpy(*buffer + *buffer_len, data, datalen);
  *buffer_len += datalen;

  return true;
}

quic_stream_state *quic_stream_state_create(
  quic_stream_owner_kind owner_kind,
  void *owner,
  int64_t stream_id
)
{
  quic_stream_state *state;

  state = ecalloc(1, sizeof(quic_stream_state));
  state->owner_kind = owner_kind;
  state->owner = owner;
  state->stream_id = stream_id;
  state->refcount = 1;

  return state;
}

void quic_stream_state_addref(quic_stream_state *state)
{
  state->refcount++;
}

void quic_stream_state_release(quic_stream_state *state)
{
  if (--state->refcount > 0) {
    return;
  }

  if (state->read_buffer != NULL) {
    efree(state->read_buffer);
  }

  if (state->write_buffer != NULL) {
    efree(state->write_buffer);
  }

  efree(state);
}

bool quic_stream_state_append_read(
  quic_stream_state *state,
  const uint8_t *data,
  size_t datalen
)
{
  return quic_stream_buffer_append(
    &state->read_buffer,
    &state->read_buffer_len,
    &state->read_buffer_cap,
    data,
    datalen
  );
}

bool quic_stream_state_append_write(
  quic_stream_state *state,
  const uint8_t *data,
  size_t datalen
)
{
  return quic_stream_buffer_append(
    &state->write_buffer,
    &state->write_buffer_len,
    &state->write_buffer_cap,
    data,
    datalen
  );
}

bool quic_stream_state_has_pending_write(quic_stream_state *state)
{
  return state->write_buffer_off < state->write_buffer_len ||
    (state->fin_requested && !state->fin_sent);
}

void quic_stream_state_mark_write_progress(
  quic_stream_state *state,
  size_t bytes_written,
  bool fin_attempted,
  bool packet_emitted
)
{
  (void) packet_emitted;

  if (bytes_written > 0) {
    state->write_buffer_off += bytes_written;
    if (state->write_buffer_off >= state->write_buffer_len) {
      state->write_buffer_len = 0;
      state->write_buffer_off = 0;
    }
  }

  if (fin_attempted && state->write_buffer_len == 0) {
    state->fin_sent = true;
  }
}

void quic_stream_state_mark_read_stopped(quic_stream_state *state)
{
  state->read_stopped = true;
  state->read_buffer_len = 0;
}

void quic_stream_state_mark_write_reset(quic_stream_state *state)
{
  state->write_reset = true;
  state->write_buffer_len = 0;
  state->write_buffer_off = 0;
  state->fin_requested = true;
  state->fin_sent = true;
}

void quic_stream_state_mark_write_blocked(quic_stream_state *state)
{
  state->write_reset = true;
  state->write_buffer_len = 0;
  state->write_buffer_off = 0;
  state->fin_requested = true;
  state->fin_sent = true;
}

void quic_stream_state_mark_peer_fin(quic_stream_state *state)
{
  state->peer_fin_received = true;
}

void quic_stream_state_mark_peer_reset(
  quic_stream_state *state,
  uint64_t final_size,
  uint64_t app_error_code
)
{
  state->peer_reset_received = true;
  state->peer_reset_final_size = final_size;
  state->peer_reset_error_code = app_error_code;
  state->peer_fin_received = true;
}

void quic_stream_state_mark_peer_write_stopped(
  quic_stream_state *state,
  uint64_t app_error_code,
  bool error_code_known
)
{
  state->peer_write_stopped_received = true;
  state->peer_write_stopped_error_code_known = error_code_known;
  if (error_code_known) {
    state->peer_write_stopped_error_code = app_error_code;
  }
}

void quic_stream_state_mark_closed(quic_stream_state *state)
{
  state->closed = true;
}

void quic_stream_state_detach(quic_stream_state *state)
{
  state->owner = NULL;
  state->owner_kind = QUIC_STREAM_OWNER_NONE;
  state->closed = true;
}

static void quic_stream_free_object(zend_object *object)
{
  quic_stream_object *intern = quic_stream_from_obj(object);

  if (intern->state != NULL) {
    quic_stream_state_release(intern->state);
    intern->state = NULL;
  }

  zend_object_std_dtor(&intern->std);
}

static zend_object *quic_stream_create_object(zend_class_entry *class_type)
{
  quic_stream_object *intern;

  intern = zend_object_alloc(sizeof(quic_stream_object), class_type);
  intern->state = NULL;

  zend_object_std_init(&intern->std, class_type);
  object_properties_init(&intern->std, class_type);
  intern->std.handlers = &quic_stream_handlers;

  return &intern->std;
}

void quic_stream_object_init(zval *zv, quic_stream_state *state)
{
  object_init_ex(zv, quic_stream_ce);
  Z_QUIC_STREAM_P(zv)->state = state;
}

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_quic_stream_error_code, 0, 0, 0)
  ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, errorCode, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_quic_stream_nullable_long, 0, 0, IS_LONG, 1)
ZEND_END_ARG_INFO()

static bool quic_stream_request_shutdown(
  quic_stream_state *state,
  uint64_t app_error_code,
  bool stop_read,
  bool stop_write
)
{
  if (state->owner == NULL || state->closed) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Stream is closed");
    return false;
  }

  switch (state->owner_kind) {
    case QUIC_STREAM_OWNER_CLIENT:
      return quic_client_shutdown_stream(
        (quic_client_connection_object *) state->owner,
        state,
        app_error_code,
        stop_read,
        stop_write
      );
    case QUIC_STREAM_OWNER_SERVER:
      return quic_server_shutdown_stream(
        (quic_server_peer_state *) state->owner,
        state,
        app_error_code,
        stop_read,
        stop_write
      );
    default:
      zend_throw_exception_ex(quic_exception_ce, 0, "Stream is detached");
      return false;
  }
}

PHP_METHOD(Quic_Stream, getId)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  RETURN_LONG((zend_long) intern->state->stream_id);
}

PHP_METHOD(Quic_Stream, write)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);
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

  if (intern->state->closed || intern->state->owner == NULL) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Stream is closed");
    RETURN_THROWS();
  }

  if (intern->state->write_reset) {
    zend_throw_exception_ex(quic_exception_ce, 0, "Stream write side is closed");
    RETURN_THROWS();
  }

  if (intern->state->fin_requested) {
    zend_throw_exception_ex(quic_exception_ce, 0, "FIN has already been requested for this stream");
    RETURN_THROWS();
  }

  if (!quic_stream_state_append_write(
        intern->state,
        (const uint8_t *) ZSTR_VAL(data),
        ZSTR_LEN(data)
      )) {
    RETURN_THROWS();
  }

  if (fin) {
    intern->state->fin_requested = true;
  }

  RETURN_LONG((zend_long) ZSTR_LEN(data));
}

PHP_METHOD(Quic_Stream, read)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  if (intern->state->read_buffer_len == 0) {
    RETURN_EMPTY_STRING();
  }

  RETVAL_STRINGL(
    (const char *) intern->state->read_buffer,
    intern->state->read_buffer_len
  );

  intern->state->read_buffer_len = 0;
}

PHP_METHOD(Quic_Stream, isReadable)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  RETURN_BOOL(intern->state->read_buffer_len > 0);
}

PHP_METHOD(Quic_Stream, isWritable)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  RETURN_BOOL(
    !intern->state->closed &&
    intern->state->owner != NULL &&
    !intern->state->write_reset &&
    !intern->state->fin_requested
  );
}

PHP_METHOD(Quic_Stream, isFinished)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  RETURN_BOOL(intern->state->closed || intern->state->peer_fin_received);
}

PHP_METHOD(Quic_Stream, isPeerReset)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  RETURN_BOOL(intern->state->peer_reset_received);
}

PHP_METHOD(Quic_Stream, getPeerResetErrorCode)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  if (!intern->state->peer_reset_received) {
    RETURN_NULL();
  }

  RETURN_LONG((zend_long) intern->state->peer_reset_error_code);
}

PHP_METHOD(Quic_Stream, getPeerResetFinalSize)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  if (!intern->state->peer_reset_received) {
    RETURN_NULL();
  }

  RETURN_LONG((zend_long) intern->state->peer_reset_final_size);
}

PHP_METHOD(Quic_Stream, isPeerWriteStopped)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  RETURN_BOOL(intern->state->peer_write_stopped_received);
}

PHP_METHOD(Quic_Stream, getPeerWriteStopErrorCode)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  if (
    !intern->state->peer_write_stopped_received ||
    !intern->state->peer_write_stopped_error_code_known
  ) {
    RETURN_NULL();
  }

  RETURN_LONG((zend_long) intern->state->peer_write_stopped_error_code);
}

PHP_METHOD(Quic_Stream, reset)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);
  zend_long error_code = 0;

  ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(error_code)
  ZEND_PARSE_PARAMETERS_END();

  if (error_code < 0) {
    zend_argument_value_error(1, "must be greater than or equal to 0");
    RETURN_THROWS();
  }

  if (intern->state->closed || intern->state->write_reset) {
    return;
  }

  if (!quic_stream_request_shutdown(
        intern->state,
        (uint64_t) error_code,
        true,
        true
      )) {
    RETURN_THROWS();
  }

  quic_stream_state_mark_read_stopped(intern->state);
  quic_stream_state_mark_write_reset(intern->state);
  quic_stream_state_mark_closed(intern->state);
}

PHP_METHOD(Quic_Stream, stop)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);
  zend_long error_code = 0;

  ZEND_PARSE_PARAMETERS_START(0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(error_code)
  ZEND_PARSE_PARAMETERS_END();

  if (error_code < 0) {
    zend_argument_value_error(1, "must be greater than or equal to 0");
    RETURN_THROWS();
  }

  if (intern->state->closed || intern->state->read_stopped) {
    return;
  }

  if (!quic_stream_request_shutdown(
        intern->state,
        (uint64_t) error_code,
        true,
        false
      )) {
    RETURN_THROWS();
  }

  quic_stream_state_mark_read_stopped(intern->state);
}

PHP_METHOD(Quic_Stream, close)
{
  quic_stream_object *intern = Z_QUIC_STREAM_P(ZEND_THIS);

  if (intern->state->closed || intern->state->owner == NULL) {
    return;
  }

  intern->state->fin_requested = true;
}

static const zend_function_entry quic_stream_methods[] = {
  PHP_ME(Quic_Stream, getId, arginfo_quic_stream_get_id, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, write, arginfo_quic_stream_write, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, read, arginfo_quic_stream_read, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isReadable, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isWritable, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isFinished, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isPeerReset, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, getPeerResetErrorCode, arginfo_quic_stream_nullable_long, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, getPeerResetFinalSize, arginfo_quic_stream_nullable_long, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, isPeerWriteStopped, arginfo_quic_stream_bool, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, getPeerWriteStopErrorCode, arginfo_quic_stream_nullable_long, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, reset, arginfo_quic_stream_error_code, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, stop, arginfo_quic_stream_error_code, ZEND_ACC_PUBLIC)
  PHP_ME(Quic_Stream, close, arginfo_quic_stream_void, ZEND_ACC_PUBLIC)
  PHP_FE_END
};

void quic_stream_register_classes(void)
{
  zend_class_entry ce;

  INIT_NS_CLASS_ENTRY(ce, "Quic", "Stream", quic_stream_methods);
  quic_stream_ce = zend_register_internal_class(&ce);
  quic_stream_ce->create_object = quic_stream_create_object;

  memcpy(&quic_stream_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
  quic_stream_handlers.offset = XtOffsetOf(quic_stream_object, std);
  quic_stream_handlers.free_obj = quic_stream_free_object;
  quic_stream_handlers.clone_obj = NULL;
}
