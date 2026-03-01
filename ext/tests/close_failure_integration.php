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
$clientQuicStream = null;
$serverQuicStream = null;
$serverReceived = '';
$clientReceived = '';
$deadline = microtime(true) + 5.0;

$client->startHandshake();

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $peer = $server->popAcceptedPeer();
    }

    if ($peer instanceof Quic\ServerPeer && !$serverQuicStream instanceof Quic\Stream) {
        $serverQuicStream = $peer->popAcceptedStream();
    }

    if ($client->isHandshakeComplete() && !$clientQuicStream instanceof Quic\Stream) {
        $clientQuicStream = $client->openBidirectionalStream();
        $clientQuicStream->write("ping\n", true);
    }

    if ($serverQuicStream instanceof Quic\Stream) {
        $chunk = $serverQuicStream->read();
        if ($chunk !== '') {
            $serverReceived .= $chunk;
        }

        if ($serverReceived === "ping\n" && $serverQuicStream->isFinished() && $serverQuicStream->isWritable()) {
            $serverQuicStream->write("ok\n", true);
            $server->flush();
        }
    }

    if ($clientQuicStream instanceof Quic\Stream) {
        $chunk = $clientQuicStream->read();
        if ($chunk !== '') {
            $clientReceived .= $chunk;
        }
    }

    if (
        $peer instanceof Quic\ServerPeer &&
        $clientQuicStream instanceof Quic\Stream &&
        $serverQuicStream instanceof Quic\Stream &&
        $serverReceived === "ping\n" &&
        $clientReceived === "ok\n"
    ) {
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
    $seconds = intdiv($timeout, 1000);
    $microseconds = ($timeout % 1000) * 1000;

    $ready = @stream_select($read, $write, $except, $seconds, $microseconds);
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
        } elseif ($resource === $clientStream) {
            $client->handleReadable();
        }
    }
}

if (
    !$peer instanceof Quic\ServerPeer ||
    !$clientQuicStream instanceof Quic\Stream ||
    !$serverQuicStream instanceof Quic\Stream
) {
    throw new RuntimeException('failed to establish stream exchange');
}

$client->close();

$clientWriteClass = null;
$clientWriteMessage = null;
$clientResetClass = null;
$clientResetMessage = null;

try {
    $clientQuicStream->write("again\n");
} catch (Throwable $e) {
    $clientWriteClass = get_class($e);
    $clientWriteMessage = $e->getMessage();
}

try {
    $clientQuicStream->reset(9);
} catch (Throwable $e) {
    $clientResetClass = get_class($e);
    $clientResetMessage = $e->getMessage();
}

$server->close();

$serverWriteClass = null;
$serverWriteMessage = null;
$serverStopClass = null;
$serverStopMessage = null;

try {
    $serverQuicStream->write("again\n");
} catch (Throwable $e) {
    $serverWriteClass = get_class($e);
    $serverWriteMessage = $e->getMessage();
}

try {
    $serverQuicStream->stop(5);
} catch (Throwable $e) {
    $serverStopClass = get_class($e);
    $serverStopMessage = $e->getMessage();
}

var_dump($clientReceived);
var_dump($serverReceived);
var_dump($clientQuicStream->isFinished());
var_dump($clientQuicStream->isWritable());
var_dump($clientWriteClass);
var_dump($clientWriteMessage);
var_dump($clientResetClass);
var_dump($clientResetMessage);
var_dump($peer->getTimeout());
var_dump($peer->isHandshakeComplete());
var_dump($peer->popAcceptedStream());
var_dump($serverQuicStream->isFinished());
var_dump($serverQuicStream->isWritable());
var_dump($serverWriteClass);
var_dump($serverWriteMessage);
var_dump($serverStopClass);
var_dump($serverStopMessage);

fclose($serverStream);
fclose($clientStream);
