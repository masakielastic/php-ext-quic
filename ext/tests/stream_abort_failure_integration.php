<?php

declare(strict_types=1);

$server = new Quic\ServerConnection('127.0.0.1', 0, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);
$client = new Quic\ClientConnection('127.0.0.1', $server->getLocalAddress()['port'], [
    'verify_peer' => false,
]);

$serverStream = $server->getPollStream();
$clientStream = $client->getPollStream();
stream_set_blocking($serverStream, false);
stream_set_blocking($clientStream, false);

$peer = null;
$clientAbortStream = null;
$serverAbortStream = null;
$flushFailure = null;
$writeFailure = null;
$deadline = microtime(true) + 5.0;

$client->startHandshake();

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $peer = $server->popAcceptedPeer();
    }

    if ($client->isHandshakeComplete() && !$clientAbortStream instanceof Quic\Stream) {
        $clientAbortStream = $client->openBidirectionalStream();
        $clientAbortStream->write("abort-me\n");
    }

    if ($peer instanceof Quic\ServerPeer && !$serverAbortStream instanceof Quic\Stream) {
        $serverAbortStream = $peer->popAcceptedStream();
    }

    if ($serverAbortStream instanceof Quic\Stream && $serverAbortStream->read() === "abort-me\n") {
        $serverAbortStream->reset(55);
    }

    if ($clientAbortStream instanceof Quic\Stream && $clientAbortStream->isPeerReset()) {
        break;
    }

    $read = [$serverStream, $clientStream];
    $write = null;
    $except = null;
    $timeouts = array_values(array_filter([
        $server->getTimeout(),
        $client->getTimeout(),
    ], static fn($value) => $value !== null));

    $timeout = $timeouts ? max(0, min($timeouts)) : 50;
    $ready = @stream_select($read, $write, $except, intdiv($timeout, 1000), ($timeout % 1000) * 1000);
    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        $server->handleExpiry();
        $client->handleExpiry();
        continue;
    }

    foreach ($read as $resource) {
        if ($resource === $serverStream) {
            $server->handleReadable();
        } else {
            $client->handleReadable();
        }
    }
}

if (!$clientAbortStream instanceof Quic\Stream) {
    throw new RuntimeException('client stream was not opened');
}

try {
    $clientAbortStream->write("again\n");
} catch (Throwable $e) {
    $flushFailure = $e;
}

if ($flushFailure === null) {
    try {
        $client->flush();
    } catch (Throwable $e) {
        $flushFailure = $e;
    }
}

try {
    $clientAbortStream->write("after-flush\n");
} catch (Throwable $e) {
    $writeFailure = $e;
}

var_dump($clientAbortStream->isPeerReset());
var_dump($clientAbortStream->getPeerResetErrorCode());
var_dump($clientAbortStream->isFinished());
var_dump($clientAbortStream->isWritable());
var_dump($flushFailure instanceof Quic\ProtocolException);
var_dump(
    $flushFailure instanceof Quic\ProtocolException &&
    str_contains($flushFailure->getMessage(), 'ERR_STREAM_SHUT_WR')
);
var_dump($writeFailure instanceof Quic\Exception);
var_dump(
    $writeFailure instanceof Quic\Exception &&
    $writeFailure->getMessage() === 'Stream write side is closed'
);

fclose($serverStream);
fclose($clientStream);
$server->close();
$client->close();
