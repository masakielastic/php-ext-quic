# Examples

This repository includes a few small runnable scripts under `examples/`.

All examples assume:

- the extension is built at `ext/modules/quic.so`
- a certificate and key are available, for example:
  - `/tmp/nghttp3-localhost.crt`
  - `/tmp/nghttp3-localhost.key`
- test certificates can be created with:
  - `ext/tests/prepare_test_certs.sh`

## Single client

`examples/client_ping.php`

Purpose:

- connect to one QUIC server
- open one bidirectional stream
- send one message and print the response

Example:

```bash
php -d extension=/home/masakielastic/php-ext-quic/ext/modules/quic.so \
  /home/masakielastic/php-ext-quic/examples/client_ping.php \
  127.0.0.1 18443 "ping\n"
```

## Fiber client

`examples/client_fiber_ping.php`

Purpose:

- connect to one QUIC server
- drive QUIC state from inside a Fiber
- suspend on poll-stream readiness or timeout and print the response

Example:

```bash
php -d extension=/home/masakielastic/php-ext-quic/ext/modules/quic.so \
  /home/masakielastic/php-ext-quic/examples/client_fiber_ping.php \
  127.0.0.1 18443 "ping\n"
```

## Single peer server

`examples/server_loop.php`

Purpose:

- accept one peer
- read one request stream
- write one response
- close the peer and exit

Example:

```bash
php -d extension=/home/masakielastic/php-ext-quic/ext/modules/quic.so \
  /home/masakielastic/php-ext-quic/examples/server_loop.php \
  18443 /tmp/nghttp3-localhost.crt /tmp/nghttp3-localhost.key
```

## Multi-peer server

`examples/server_multi_peer_loop.php`

Purpose:

- accept multiple peers on one listener
- use `ServerPeer` objects for peer-local stream handling
- exit after serving the configured number of peers

Example:

```bash
php -d extension=/home/masakielastic/php-ext-quic/ext/modules/quic.so \
  /home/masakielastic/php-ext-quic/examples/server_multi_peer_loop.php \
  18443 /tmp/nghttp3-localhost.crt /tmp/nghttp3-localhost.key 2
```

## Multi-peer demo

`examples/run_multi_peer_demo.php`

Purpose:

- start `server_multi_peer_loop.php`
- run `client_ping.php` twice
- print both client responses and the server-side received payloads

Example:

```bash
php -d extension=/home/masakielastic/php-ext-quic/ext/modules/quic.so \
  /home/masakielastic/php-ext-quic/examples/run_multi_peer_demo.php \
  /tmp/nghttp3-localhost.crt /tmp/nghttp3-localhost.key
```

## Integration runners

The direct integration scripts under `ext/tests/` are useful when you want the
same logic that backs the PHPT integration tests without going through
`run-tests.php`.

`ext/tests/server_client_integration.php`

- single client and single server peer
- uses the preferred `ServerPeer` acceptance path

`ext/tests/server_multi_client_integration.php`

- one listener serving two clients in sequence
- uses `ServerPeer::popAcceptedStream()`

`ext/tests/server_peer_close_integration.php`

- closes the first accepted peer
- verifies that the listener can still accept and serve the next peer

`ext/tests/server_stream_queue_order_integration.php`

- opens two streams on one peer
- verifies that `ServerPeer::popAcceptedStream()` preserves stream open order

## Notes

- `client_ping.php` is intentionally tolerant of `ERR_CLOSING` and
  `ERR_DRAINING` after the request stream has been opened so short demos can
  exit cleanly.
- For server code, use `popAcceptedPeer()` and `ServerPeer::popAcceptedStream()`
  as the stable acceptance path.
