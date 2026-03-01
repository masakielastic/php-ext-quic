# php-ext-quic

Minimal QUIC client/server PHP extension built on `ngtcp2` and `GnuTLS`.

The extension is designed for userland-driven event loops. It exposes the UDP
socket as a PHP stream for readiness monitoring, while QUIC packet processing
stays inside the extension.

## Status

Current scope:

- QUIC client and server connections
- explicit handshake / readable / expiry / flush loop primitives
- bidirectional stream open / read / write
- server listener split into `Quic\ServerConnection` and `Quic\ServerPeer`
- examples and integration scripts based on `stream_select()`

Current non-goals:

- HTTP/3
- 0-RTT
- migration
- datagrams
- OpenSSL backend

## Requirements

- PHP `>= 8.1`
- `libngtcp2-dev`
- `libngtcp2-crypto-gnutls-dev`
- `gnutls`
- `pkg-config`
- `phpize`

## Build

```bash
cd ext
phpize
./configure --enable-quic
make -j4
```

The extension module is built at `ext/modules/quic.so`.

## PIE metadata

This repository includes PIE metadata in [composer.json](/home/masakielastic/php-ext-quic/composer.json):

- extension name: `quic`
- build path: `ext`

## Core API

Client:

- `Quic\ClientConnection`
- `getPollStream()`
- `startHandshake()`
- `handleReadable()`
- `handleExpiry()`
- `flush()`
- `getTimeout()`
- `isHandshakeComplete()`
- `openBidirectionalStream()`
- `close()`

Server:

- `Quic\ServerConnection`
- `Quic\ServerPeer`
- `popAcceptedPeer()`
- `ServerPeer::popAcceptedStream()`
- listener-driven `handleReadable()`, `handleExpiry()`, `flush()`

Streams:

- `Quic\Stream`
- `getId()`
- `write()`
- `read()`
- `isReadable()`
- `isWritable()`
- `isFinished()`
- `reset()`
- `stop()`
- `close()`

## Core rule

`getPollStream()` is for readiness monitoring only.

Do not call `fread()`, `fwrite()`, `stream_socket_recvfrom()`, or
`stream_socket_sendto()` on that stream. Use it with `stream_select()` or loop
watchers, then call the extension methods:

- `handleReadable()`
- `handleExpiry()`
- `flush()`

## Minimal client loop

```php
<?php

$client = new Quic\ClientConnection('127.0.0.1', 18443, [
    'verify_peer' => false,
]);

$socket = $client->getPollStream();
stream_set_blocking($socket, false);
$client->startHandshake();
$stream = null;

while (true) {
    $client->flush();

    if ($client->isHandshakeComplete() && $stream === null) {
        $stream = $client->openBidirectionalStream();
        $stream->write("ping\n", true);
    }

    if ($stream instanceof Quic\Stream) {
        $chunk = $stream->read();
        if ($chunk !== '') {
            echo $chunk;
            if ($stream->isFinished()) {
                break;
            }
        }
    }

    $timeout = $client->getTimeout() ?? 50;
    $read = [$socket];
    $write = null;
    $except = null;

    $ready = stream_select(
        $read,
        $write,
        $except,
        intdiv($timeout, 1000),
        ($timeout % 1000) * 1000,
    );

    if ($ready === 0) {
        $client->handleExpiry();
        continue;
    }

    $client->handleReadable();
}
```

## Minimal server loop

```php
<?php

$server = new Quic\ServerConnection('127.0.0.1', 18443, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);

$socket = $server->getPollStream();
$peer = null;
$accepted = null;

while (true) {
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $peer = $server->popAcceptedPeer();
    }

    if ($accepted === null && $peer instanceof Quic\ServerPeer) {
        $accepted = $peer->popAcceptedStream();
    }

    if ($accepted instanceof Quic\Stream) {
        $chunk = $accepted->read();
        if ($chunk !== '') {
            fwrite(STDOUT, $chunk);
        }

        if ($accepted->isFinished() && $accepted->isWritable()) {
            $accepted->write("server response\n", true);
            $server->flush();
            $peer->close();
            break;
        }
    }

    $timeout = $peer?->getTimeout() ?? $server->getTimeout() ?? 50;
    $read = [$socket];
    $write = null;
    $except = null;

    $ready = stream_select(
        $read,
        $write,
        $except,
        intdiv($timeout, 1000),
        ($timeout % 1000) * 1000,
    );

    if ($ready === 0) {
        $server->handleExpiry();
        continue;
    }

    $server->handleReadable();
}
```

## Examples

- [examples/client_ping.php](/home/masakielastic/php-ext-quic/examples/client_ping.php)
- [examples/server_loop.php](/home/masakielastic/php-ext-quic/examples/server_loop.php)
- [examples/server_multi_peer_loop.php](/home/masakielastic/php-ext-quic/examples/server_multi_peer_loop.php)
- [examples/run_multi_peer_demo.php](/home/masakielastic/php-ext-quic/examples/run_multi_peer_demo.php)

Test certificates can be created with:

```bash
sh ./ext/tests/prepare_test_certs.sh
```

## Tests

Fast path:

```bash
cd ext
make test
```

Integration example:

```bash
cd ext
env QUIC_RUN_INTEGRATION_TESTS=1 make test TESTS='tests/006_client_stream_integration.phpt'
```

Some integration PHPTs skip in environments where child PHP processes cannot
bind UDP sockets.

CI-style local run:

```bash
sh ./ext/tests/run_ci.sh
```

## Documentation

- [docs/EVENT_LOOP_USAGE.md](/home/masakielastic/php-ext-quic/docs/EVENT_LOOP_USAGE.md)
- [docs/EXAMPLES.md](/home/masakielastic/php-ext-quic/docs/EXAMPLES.md)
- [docs/DEVELOPMENT_PLAN.md](/home/masakielastic/php-ext-quic/docs/DEVELOPMENT_PLAN.md)
