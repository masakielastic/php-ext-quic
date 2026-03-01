# Event Loop Usage

This extension is designed to be driven from userland.

## Core rule

`getPollStream()` returns the underlying UDP socket for readiness monitoring
only.

Do not call `fread()`, `fwrite()`, `stream_socket_recvfrom()`, or
`stream_socket_sendto()` on that stream from PHP. If userland reads or writes
the socket directly, packet flow will diverge from the extension's internal
QUIC state. The poll stream rejects direct reads and writes so this misuse
fails early.

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

- use `ServerConnection::getPollStream()`, `handleReadable()`, `handleExpiry()`,
  and `flush()` to drive the shared UDP listener
- use `ServerConnection::popAcceptedPeer()` to obtain newly accepted peers
- use `ServerPeer` for peer-specific state such as handshake completion or peer
  address

## Client loop shape

```php
<?php

$client = new Quic\ClientConnection('127.0.0.1', 4433, [
    'verify_peer' => false,
]);

$socket = $client->getPollStream();
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

## Fiber client shape

The same primitives also work with a Fiber-based scheduler. The inner Fiber can
own QUIC state transitions while the outer loop waits on `getPollStream()` and
resumes the Fiber with either a readability or timeout event.

See `examples/fiber_scheduler.php` for the small scheduler adapter and
`examples/client_fiber_ping.php` for a minimal runnable client built on it.

## Server loop shape

```php
<?php

$server = new Quic\ServerConnection('127.0.0.1', 4433, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);

$socket = $server->getPollStream();
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

## Fiber server shape

The same split also works on the server side. The inner Fiber can own
`popAcceptedPeer()`, `popAcceptedStream()`, `flush()`, `handleReadable()`, and
`handleExpiry()`, while the outer loop only waits on `getPollStream()` and
resumes the Fiber with timeout or readability.

See `examples/fiber_scheduler.php` and `examples/server_fiber_loop.php` for the
minimal adapter + server split.

## Reference scripts

The repository contains runnable examples:

- `examples/client_ping.php`
- `examples/fiber_scheduler.php`
- `examples/client_fiber_ping.php`
- `examples/server_loop.php`
- `examples/server_fiber_loop.php`
- `examples/server_multi_peer_loop.php`
- `examples/run_multi_peer_demo.php`
- `docs/EXAMPLES.md` for a quick usage index

`examples/client_ping.php` treats `ERR_CLOSING` and `ERR_DRAINING` as expected
terminal states after the request stream has been opened, so the demo scripts
can exit cleanly when the server closes the peer immediately after replying.
