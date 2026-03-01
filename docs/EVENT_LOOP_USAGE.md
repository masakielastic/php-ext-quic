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

## Server object split

For servers, treat `Quic\ServerConnection` as the listener and
`Quic\ServerPeer` as the per-peer state handle.

Preferred usage:

- use `ServerConnection::getStream()`, `handleReadable()`, `handleExpiry()`,
  and `flush()` to drive the shared UDP listener
- use `ServerConnection::popAcceptedPeer()` to obtain newly accepted peers
- use `ServerPeer` for peer-specific state such as handshake completion or peer
  address

Compatibility helpers on `ServerConnection`, such as `getTimeout()`,
`isHandshakeComplete()`, and `getPeerAddress()`, refer to the most recently
accepted live peer. They are useful for simple single-peer flows, but they are
not the preferred API once multiple peers are active.

If you still use `ServerConnection::popAcceptedStream()`, treat it as the same
kind of compatibility path: acceptable for small single-peer scripts, but not
the preferred shape once you keep peer objects around.

Do not mix `ServerConnection::popAcceptedStream()` and
`ServerPeer::popAcceptedStream()` in the same control flow. They observe the
same accepted stream states through different queues, so mixing them makes
ownership and ordering harder to reason about.

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
$peer = null;
$accepted = null;
$responded = false;

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

        if (!$responded && $accepted->isFinished() && $accepted->isWritable()) {
            $accepted->write("server response\n", true);
            $server->flush();
            $responded = true;
        }

        if ($responded && $accepted->isFinished() && $peer instanceof Quic\ServerPeer) {
            $peer->close();
            $server->flush();
            break;
        }
    }

    $read = [$socket];
    $write = null;
    $except = null;
    $timeout = $peer?->getTimeout() ?? $server->getTimeout() ?? 50;

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
- `examples/server_multi_peer_loop.php`
- `examples/run_multi_peer_demo.php`

`examples/client_ping.php` treats `ERR_CLOSING` and `ERR_DRAINING` as expected
terminal states after the request stream has been opened, so the demo scripts
can exit cleanly when the server closes the peer immediately after replying.
