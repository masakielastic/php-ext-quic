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
$clientWriteStream = null;
$serverReadStream = null;
$stopSent = false;
$flushFailure = null;
$deadline = microtime(true) + 5.0;

$client->startHandshake();

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $peer = $server->popAcceptedPeer();
    }

    if ($client->isHandshakeComplete() && !$clientWriteStream instanceof Quic\Stream) {
        $clientWriteStream = $client->openBidirectionalStream();
        $clientWriteStream->write("stop-me\n");
    }

    if ($peer instanceof Quic\ServerPeer && !$serverReadStream instanceof Quic\Stream) {
        $serverReadStream = $peer->popAcceptedStream();
    }

    if (!$stopSent && $serverReadStream instanceof Quic\Stream && $serverReadStream->read() === "stop-me\n") {
        $serverReadStream->stop(33);
        $server->flush();
        $stopSent = true;
    }

    if ($stopSent && $clientWriteStream instanceof Quic\Stream) {
        try {
            $clientWriteStream->write("after-stop\n");
            $client->flush();
        } catch (Throwable $e) {
            $flushFailure = $e;
        }
    }

    if (
        $clientWriteStream instanceof Quic\Stream &&
        (
            $clientWriteStream->isPeerWriteStopped() ||
            $flushFailure instanceof Throwable
        )
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
    $ready = @stream_select($read, $write, $except, intdiv($timeout, 1000), ($timeout % 1000) * 1000);
    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        try {
            $server->handleExpiry();
        } catch (Quic\ProtocolException) {
        }

        try {
            $client->handleExpiry();
        } catch (Throwable $e) {
            $flushFailure = $e;
        }
        continue;
    }

    foreach ($read as $resource) {
        try {
            if ($resource === $serverStream) {
                $server->handleReadable();
            } else {
                $client->handleReadable();
            }
        } catch (Throwable $e) {
            if ($resource === $clientStream) {
                $flushFailure = $e;
            }
        }
    }
}

if (!$clientWriteStream instanceof Quic\Stream) {
    throw new RuntimeException('client write stream was not opened');
}

var_dump($clientWriteStream->isPeerWriteStopped());
var_dump($clientWriteStream->getPeerWriteStopErrorCode());
var_dump($clientWriteStream->isWritable());
var_dump(
    $flushFailure instanceof Quic\ProtocolException &&
    str_contains($flushFailure->getMessage(), 'ERR_STREAM_SHUT_WR')
);

fclose($serverStream);
fclose($clientStream);
$server->close();
$client->close();
