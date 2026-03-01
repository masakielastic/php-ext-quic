#ifndef PHP_QUIC_POLL_STREAM_H
#define PHP_QUIC_POLL_STREAM_H

#include "php_quic.h"

#include "main/php_network.h"
#include "main/php_streams.h"

php_stream *quic_poll_stream_open(php_socket_t fd, const char *label);

#endif
