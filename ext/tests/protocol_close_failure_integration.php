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
$deadline = microtime(true) + 5.0;
$client->startHandshake();

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $peer = $server->popAcceptedPeer();
    }

    if (
        $peer instanceof Quic\ServerPeer &&
        $peer->isHandshakeComplete() &&
        $client->isHandshakeComplete()
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

if (!$peer instanceof Quic\ServerPeer) {
    throw new RuntimeException('peer was not accepted');
}

$peer->close(77, 'bye');
$server->flush();

$caught = null;
$deadline = microtime(true) + 2.0;

while (microtime(true) < $deadline) {
    try {
        $client->flush();
    } catch (Throwable $e) {
        $caught = $e;
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
            $caught = $e;
            break;
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
                $caught = $e;
                break 2;
            }
        }
    }
}

var_dump($caught instanceof Quic\ProtocolException);
var_dump(
    $caught instanceof Quic\ProtocolException &&
    (
        str_contains($caught->getMessage(), 'ERR_CLOSING') ||
        str_contains($caught->getMessage(), 'ERR_DRAINING') ||
        str_contains($caught->getMessage(), 'ERR_DROP_CONN')
    )
);

fclose($serverStream);
fclose($clientStream);
$server->close();
$client->close();
