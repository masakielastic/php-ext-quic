# PHP QUIC Extension Development Plan

## Goal

Provide a PHP extension that exposes minimal QUIC client/server classes built on
`ngtcp2` and `GnuTLS`, while remaining usable from userland event loops based on
PHP streams and Fibers.

The first milestone should stay intentionally small and mirror the behavior in
`sample_client.c` and `sample_server.c`:

- QUIC v1 over UDP
- TLS 1.3 via GnuTLS
- ALPN configuration
- single connection lifecycle
- minimal bidirectional stream send/receive
- timeout handling driven by ngtcp2 expiry
- explicit close with CONNECTION_CLOSE

The extension must not embed its own event loop. Userland should drive I/O by
watching a PHP stream and calling extension methods when readable or when a
timer expires.

## Non-goals for the first milestone

- HTTP/3
- connection migration
- 0-RTT / session resumption
- datagram extension
- multi-path
- congestion-control customization from PHP
- automatic server acceptor for multiple simultaneous peers
- OpenSSL support

## Constraints and assumptions

- Build directory is `ext/`.
- System libraries are Debian packages:
  - `libngtcp2-dev`
  - `libngtcp2-crypto-gnutls-dev`
- Runtime test tools already available:
  - `gtlsclient`
  - `/usr/sbin/gtlsserver`
- Reference behavior comes from:
  - `sample_client.c`
  - `sample_server.c`
- Minimum PHP version should be `8.1` because Fiber-based loops are a target.

## Design principles

### 1. Event loop ownership stays in userland

The extension should expose:

- the underlying UDP socket as a PHP stream resource
- the next timer deadline or timeout in milliseconds
- non-blocking methods to consume inbound packets, flush outbound packets, and
  process ngtcp2 expiry

This allows integration with:

- raw `stream_select()`
- ReactPHP / Amp adapters
- custom Fiber schedulers

### 2. Low-level, explicit API first

The initial API should be close to ngtcp2 concepts instead of trying to hide
QUIC semantics behind a higher-level abstraction. That keeps the extension
small, testable, and aligned with the reference programs.

### 3. Queue data, avoid re-entering PHP from ngtcp2 callbacks

ngtcp2 callbacks should update internal C buffers and state only. PHP-visible
data should be pulled explicitly from methods like `receive()` or
`readStream()`. This reduces re-entrancy risk and keeps the API loop-friendly.

## Proposed minimal PHP API

Register namespaced classes:

- `Quic\ClientConnection`
- `Quic\ServerConnection`
- `Quic\Stream`

### `Quic\ClientConnection`

Purpose: active QUIC client connection on a connected UDP socket.

Initial methods:

- `__construct(string $host, int|string $port, array $options = [])`
- `getStream()`: returns the UDP socket as a PHP stream resource
- `startHandshake(): void`
- `handleReadable(): void`
- `handleExpiry(): void`
- `flush(): void`
- `getTimeout(): ?int`
- `isHandshakeComplete(): bool`
- `openBidirectionalStream(): Quic\Stream`
- `close(?int $errorCode = null, string $reason = ""): void`
- `getPeerAddress(): array`
- `getLocalAddress(): array`

Options for milestone 1:

- `alpn`
- `server_name`
- `verify_peer`
- `cafile`
- `capath`
- `initial_max_data`
- `initial_max_stream_data_bidi_local`
- `initial_max_streams_bidi`

### `Quic\ServerConnection`

Purpose: a single accepted server-side QUIC connection bound to one UDP peer.

Initial methods:

- `__construct(string $host, int|string $port, array $options = [])`
- `getStream()`
- `accept(): void`
- `handleReadable(): void`
- `handleExpiry(): void`
- `flush(): void`
- `getTimeout(): ?int`
- `isHandshakeComplete(): bool`
- `popAcceptedStream(): ?Quic\Stream`
- `close(?int $errorCode = null, string $reason = ""): void`
- `getPeerAddress(): array`
- `getLocalAddress(): array`

Options for milestone 1:

- `alpn`
- `certificate`
- `private_key`
- `verify_peer`
- `response_mode` is not needed in the public API and should stay internal to
  tests/examples

### `Quic\Stream`

Purpose: wrapper around one bidirectional stream ID owned by a connection.

Initial methods:

- `getId(): int`
- `write(string $data, bool $fin = false): int`
- `read(): string`
- `isReadable(): bool`
- `isWritable(): bool`
- `isFinished(): bool`
- `close(): void`

Milestone 1 stream behavior:

- buffer outgoing data in C until `flush()` writes packets
- buffer inbound stream frames in C until `read()` drains them
- support only bidirectional application streams
- no per-stream flow-control API exposed to PHP initially

## Userland integration model

Recommended loop sequence for both client and server:

1. Build connection object.
2. Obtain UDP stream via `getStream()`.
3. Put the stream in non-blocking mode from PHP if needed.
4. Call `startHandshake()` for clients or `accept()` for servers.
5. In the event loop:
   - when stream is readable, call `handleReadable()`
   - when timeout fires, call `handleExpiry()`
   - after either step, call `flush()`
   - use `getTimeout()` to arm the next timer
6. Consume or produce stream data through `Quic\Stream`.

This keeps Fibers viable because the extension never blocks internally after
construction.

## C architecture in `ext/`

Proposed file layout:

- `ext/config.m4`
- `ext/php_quic.h`
- `ext/quic.c`
- `ext/quic_client.c`
- `ext/quic_client.h`
- `ext/quic_server.c`
- `ext/quic_server.h`
- `ext/quic_stream.c`
- `ext/quic_stream.h`
- `ext/quic_socket.c`
- `ext/quic_socket.h`
- `ext/quic_tls.c`
- `ext/quic_tls.h`
- `ext/quic_buffer.c`
- `ext/quic_buffer.h`
- `ext/tests/`
- `ext/examples/`

Internal responsibilities:

- `quic_socket.*`
  - create/bind/connect UDP sockets
  - convert socket fd to PHP stream resource
  - address marshaling helpers
- `quic_tls.*`
  - initialize GnuTLS sessions and credentials
  - ALPN and trust store configuration
  - glue for `ngtcp2_crypto_gnutls_*`
- `quic_client.*`
  - client connection object lifecycle
  - client-specific callbacks and handshake bootstrap
- `quic_server.*`
  - initial packet accept
  - server connection object lifecycle
  - server-specific callbacks
- `quic_stream.*`
  - stream object registration
  - per-stream inbound and outbound buffers
- `quic_buffer.*`
  - small reusable byte queue implementation
- `quic.c`
  - module init
  - class registration
  - shared arginfo

## Mapping from reference samples to extension features

From `sample_client.c`:

- socket creation and `connect()` become client constructor internals
- `ngtcp2_conn_client_new()` maps to `startHandshake()`
- `extend_max_local_streams_bidi` informs `openBidirectionalStream()`
- `client_read()` maps to `handleReadable()`
- `client_handle_expiry()` maps to `handleExpiry()`
- `client_write_streams()` maps to `flush()`

From `sample_server.c`:

- initial `recvfrom()` and CID decode become `accept()`
- `ngtcp2_conn_server_new()` remains server bootstrap internals
- `recv_stream_data_cb` appends to per-stream read buffers
- stream-open and stream-close callbacks update PHP object state queues
- poll loop is removed and replaced by `getTimeout()` + explicit calls

## Memory and object model

Each PHP connection object should own:

- UDP fd / PHP stream wrapper
- `ngtcp2_conn *`
- GnuTLS session and credential handles
- local and remote socket addresses
- connection-close error state
- stream registry keyed by stream ID
- inbound accepted-stream queue
- pending outbound packet state

Each `Quic\Stream` object should hold:

- owning connection object reference
- stream ID
- readable/writable/finished flags
- inbound byte buffer
- outbound byte buffer

Rules:

- stream objects cannot outlive their owning connection state
- connection close marks all streams terminal
- callbacks must never call into Zend user functions

## Error model

Use PHP exceptions for API misuse and fatal protocol/setup failures:

- `Quic\Exception`
- `Quic\TlsException`
- `Quic\ProtocolException`

Operational notes:

- `handleReadable()` and `flush()` should throw on transport failure
- `getTimeout()` returns `null` when no timer is needed or connection is closed
- peer/app close should be observable via object state rather than forced
  warnings

## Build plan

### Phase 0: packaging and scaffold

- add `composer.json` for PIE
- create `ext/config.m4`
- add module skeleton and class registration
- detect `ngtcp2`, `ngtcp2_crypto_gnutls`, and `gnutls` with `pkg-config`

Deliverable:

- `phpize && ./configure && make` succeeds against the installed Debian libs

### Phase 1: client connection core

- implement client socket creation
- implement GnuTLS client session setup
- wire `ngtcp2_conn_client_new()`
- expose `getStream()`, `startHandshake()`, `handleReadable()`, `handleExpiry()`,
  `flush()`, `getTimeout()`, `close()`
- track handshake completion

Deliverable:

- PHP client can complete QUIC handshake against `sample_server.c` server or
  `/usr/sbin/gtlsserver` if configured appropriately

### Phase 2: minimal stream support

- implement `Quic\Stream`
- allow client to open one or more bidi streams
- queue outbound data from `write()`
- append inbound data in `recv_stream_data_cb`
- expose `read()` and terminal flags

Deliverable:

- PHP client can send one request payload and receive one response payload

### Phase 3: server-side single-connection support

- implement `accept()` for first Initial packet
- implement GnuTLS server session and certificate loading
- wire server callbacks and accepted-stream queue
- expose `popAcceptedStream()`

Deliverable:

- PHP server can accept a single client, read a bidi stream, and write a reply

### Phase 4: tests and examples

- PHPT tests for constructors, option validation, and state errors
- integration tests using the shipped sample C binaries or local PHP examples
- examples for `stream_select()`-driven client/server loops

Deliverable:

- reproducible local handshake and echo-style stream tests

## Test strategy

### Unit and API tests

- invalid constructor options
- missing cert/key handling
- handshake state transitions
- stream method behavior before and after FIN
- close semantics and exception classes

### Integration tests

- PHP client -> reference `sample_server.c`
- reference `sample_client.c` -> PHP server
- PHP client -> PHP server
- certificate verification with explicit CA file

### Tool-assisted checks

- use `gtlsclient` and `/usr/sbin/gtlsserver` to validate TLS material and ALPN
  configuration independently from PHP
- use `pkg-config --cflags --libs` in `config.m4` checks

## Key implementation risks

- mapping UDP fd ownership safely into a PHP stream resource
- keeping ngtcp2 callback state synchronized with Zend object lifetime
- exposing stream objects without allowing use-after-close on connection teardown
- handling timeout updates correctly without embedding a poll loop
- ensuring GnuTLS configuration matches ngtcp2 QUIC requirements exactly

## Recommended first coding slice

Implement the smallest end-to-end client first:

1. module scaffold
2. `Quic\ClientConnection`
3. UDP stream exposure
4. explicit handshake/read/write/expiry methods
5. one bidirectional stream with buffered write/read

This minimizes moving parts and validates the event-loop integration model
before server support is added.
