# Event Loop Usage

This extension is designed to be driven from userland.

## Core rule

`getStream()` returns the underlying UDP socket for readiness monitoring only.

Do not call `fread()`, `fwrite()`, `stream_socket_recvfrom()`, or
`stream_socket_sendto()` on that stream from PHP. If userland reads or writes
the socket directly, packet flow will diverge from the extension's internal
QUIC state.

Use the stream only with APIs such as:

- `stream_select()`
- event loop watchers that need a stream resource

All QUIC I/O must still go through:

- `handleReadable()`
- `handleExpiry()`
- `flush()`

## Client loop shape

```php
<?php

$client = new Quic\ClientConnection('127.0.0.1', 4433, [
    'verify_peer' => false,
]);

$socket = $client->getStream();
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

    $read = [$socket];
    $write = null;
    $except = null;
    $timeout = $client->getTimeout() ?? 50;

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

## Server loop shape

```php
<?php

$server = new Quic\ServerConnection('127.0.0.1', 4433, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);

$socket = $server->getStream();
$accepted = null;

while (true) {
    $server->flush();

    if ($accepted === null) {
        $accepted = $server->popAcceptedStream();
    }

    if ($accepted instanceof Quic\Stream) {
        $chunk = $accepted->read();
        if ($chunk !== '') {
            fwrite(STDOUT, $chunk);
        }

        if ($accepted->isFinished() && $accepted->isWritable()) {
            $accepted->write("server response\n", true);
            $server->flush();
        }
    }

    $read = [$socket];
    $write = null;
    $except = null;
    $timeout = $server->getTimeout() ?? 50;

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

## Reference scripts

The repository contains runnable examples:

- `examples/client_ping.php`
- `examples/server_loop.php`
