#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "quic_poll_stream.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

typedef struct _quic_poll_stream_data {
  void *inner_abstract;
  const php_stream_ops *inner_ops;
  const char *label;
} quic_poll_stream_data;

static int quic_poll_stream_call_inner(
  php_stream *stream,
  int (*callback)(php_stream *stream, int option, int value, void *ptrparam),
  int option,
  int value,
  void *ptrparam
)
{
  quic_poll_stream_data *data = stream->abstract;
  void *saved_abstract = stream->abstract;
  const php_stream_ops *saved_ops = stream->ops;
  int result;

  stream->abstract = data->inner_abstract;
  stream->ops = data->inner_ops;
  result = callback(stream, option, value, ptrparam);
  stream->abstract = saved_abstract;
  stream->ops = saved_ops;

  return result;
}

static ssize_t quic_poll_stream_write(php_stream *stream, const char *buf, size_t count)
{
  quic_poll_stream_data *data = stream->abstract;

  (void) buf;
  (void) count;

  php_error_docref(
    NULL,
    E_WARNING,
    "%s is a readiness-only QUIC poll stream; use flush() on the connection instead",
    data->label
  );

  errno = EBADF;

  return -1;
}

static ssize_t quic_poll_stream_read(php_stream *stream, char *buf, size_t count)
{
  quic_poll_stream_data *data = stream->abstract;

  (void) buf;
  (void) count;

  php_error_docref(
    NULL,
    E_WARNING,
    "%s is a readiness-only QUIC poll stream; use handleReadable() on the connection instead",
    data->label
  );

  errno = EBADF;

  return -1;
}

static int quic_poll_stream_close(php_stream *stream, int close_handle)
{
  quic_poll_stream_data *data = stream->abstract;
  int result = 0;

  stream->abstract = data->inner_abstract;
  stream->ops = data->inner_ops;

  if (data->inner_ops->close != NULL) {
    result = data->inner_ops->close(stream, close_handle);
  }

  efree(data);

  return result;
}

static int quic_poll_stream_flush(php_stream *stream)
{
  (void) stream;

  return 0;
}

static int quic_poll_stream_seek(
  php_stream *stream,
  zend_off_t offset,
  int whence,
  zend_off_t *newoffset
)
{
  quic_poll_stream_data *data = stream->abstract;

  (void) offset;
  (void) whence;
  (void) newoffset;

  php_error_docref(
    NULL,
    E_WARNING,
    "%s is a readiness-only QUIC poll stream and does not support seeking",
    data->label
  );

  errno = ESPIPE;

  return -1;
}

static int quic_poll_stream_cast(php_stream *stream, int castas, void **ret)
{
  quic_poll_stream_data *data = stream->abstract;
  void *saved_abstract;
  const php_stream_ops *saved_ops;
  int result;

  if (data == NULL || data->inner_ops == NULL || data->inner_ops->cast == NULL) {
    return FAILURE;
  }

  saved_abstract = stream->abstract;
  saved_ops = stream->ops;
  stream->abstract = data->inner_abstract;
  stream->ops = data->inner_ops;
  result = data->inner_ops->cast(stream, castas, ret);
  stream->abstract = saved_abstract;
  stream->ops = saved_ops;

  return result;
}

static int quic_poll_stream_stat(php_stream *stream, php_stream_statbuf *ssb)
{
  quic_poll_stream_data *data = stream->abstract;
  void *saved_abstract;
  const php_stream_ops *saved_ops;
  int result;

  if (data == NULL || data->inner_ops == NULL || data->inner_ops->stat == NULL) {
    memset(ssb, 0, sizeof(*ssb));
    ssb->sb.st_mode = S_IFSOCK;
    return 0;
  }

  saved_abstract = stream->abstract;
  saved_ops = stream->ops;
  stream->abstract = data->inner_abstract;
  stream->ops = data->inner_ops;
  result = data->inner_ops->stat(stream, ssb);
  stream->abstract = saved_abstract;
  stream->ops = saved_ops;

  return result;
}

static int quic_poll_stream_set_option(php_stream *stream, int option, int value, void *ptrparam)
{
  quic_poll_stream_data *data = stream->abstract;

  if (data == NULL || data->inner_ops == NULL || data->inner_ops->set_option == NULL) {
    return PHP_STREAM_OPTION_RETURN_ERR;
  }

  switch (option) {
    case PHP_STREAM_OPTION_READ_BUFFER:
    case PHP_STREAM_OPTION_WRITE_BUFFER:
    case PHP_STREAM_OPTION_BLOCKING:
    case PHP_STREAM_OPTION_READ_TIMEOUT:
    case PHP_STREAM_OPTION_SET_CHUNK_SIZE:
    case PHP_STREAM_OPTION_META_DATA_API:
    case PHP_STREAM_OPTION_CHECK_LIVENESS:
      return quic_poll_stream_call_inner(stream, data->inner_ops->set_option, option, value, ptrparam);

    default:
      return PHP_STREAM_OPTION_RETURN_NOTIMPL;
  }
}

static const php_stream_ops quic_poll_stream_ops = {
  quic_poll_stream_write,
  quic_poll_stream_read,
  quic_poll_stream_close,
  quic_poll_stream_flush,
  "quic-poll",
  quic_poll_stream_seek,
  quic_poll_stream_cast,
  quic_poll_stream_stat,
  quic_poll_stream_set_option,
};

php_stream *quic_poll_stream_open(php_socket_t fd, const char *label)
{
  quic_poll_stream_data *data;
  php_stream *stream;

  stream = php_stream_sock_open_from_socket(fd, NULL);
  if (stream == NULL) {
    close(fd);
    return NULL;
  }

  data = ecalloc(1, sizeof(quic_poll_stream_data));
  data->inner_abstract = stream->abstract;
  data->inner_ops = stream->ops;
  data->label = label;

  stream->flags |= PHP_STREAM_FLAG_AVOID_BLOCKING;
  stream->abstract = data;
  stream->ops = &quic_poll_stream_ops;

  return stream;
}
