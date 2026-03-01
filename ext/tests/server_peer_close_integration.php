<?php

function pumpOnce(
    Quic\ServerConnection $server,
    $serverStream,
    ?Quic\ClientConnection $client,
    $clientStream,
): void {
    if ($client instanceof Quic\ClientConnection) {
        $client->flush();
    }
    $server->flush();

    $read = [$serverStream];
    if (is_resource($clientStream)) {
        $read[] = $clientStream;
    }
    $write = null;
    $except = null;
    $timeouts = array_values(array_filter([
        $server->getTimeout(),
        $client?->getTimeout(),
    ], static fn($value) => $value !== null));

    $timeout = $timeouts ? max(0, min(min($timeouts), 50)) : 50;
    $seconds = intdiv($timeout, 1000);
    $microseconds = ($timeout % 1000) * 1000;

    $ready = @stream_select($read, $write, $except, $seconds, $microseconds);
    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        $server->handleExpiry();
        if ($client instanceof Quic\ClientConnection) {
            $client->handleExpiry();
        }
        return;
    }

    foreach ($read as $resource) {
        if ($resource === $serverStream) {
            $server->handleReadable();
        } elseif ($client instanceof Quic\ClientConnection && $resource === $clientStream) {
            $client->handleReadable();
        }
    }
}

function drainAfterPeerClose(
    Quic\ServerConnection $server,
    $serverStream,
    Quic\ClientConnection $client,
    $clientStream,
): void {
    $deadline = microtime(true) + 0.5;

    while (microtime(true) < $deadline) {
        try {
            pumpOnce($server, $serverStream, $client, $clientStream);
        } catch (Quic\ProtocolException $e) {
            if (
                !str_contains($e->getMessage(), 'ERR_DROP_CONN') &&
                !str_contains($e->getMessage(), 'ERR_DRAINING')
            ) {
                throw $e;
            }
        }
    }
}

function waitForAcceptedPeer(
    Quic\ServerConnection $server,
    $serverStream,
    Quic\ClientConnection $client,
    $clientStream,
): Quic\ServerPeer {
    $client->startHandshake();
    $peer = null;
    $deadline = microtime(true) + 5.0;

    while (microtime(true) < $deadline) {
        pumpOnce($server, $serverStream, $client, $clientStream);

        if (!$peer instanceof Quic\ServerPeer) {
            $candidate = $server->popAcceptedPeer();
            if ($candidate instanceof Quic\ServerPeer) {
                $peer = $candidate;
            }
        }

        if (
            $peer instanceof Quic\ServerPeer &&
            $peer->isHandshakeComplete() &&
            $client->isHandshakeComplete()
        ) {
            return $peer;
        }
    }

    throw new RuntimeException('peer was not accepted');
}

$server = new Quic\ServerConnection('127.0.0.1', 0, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);
$serverStream = $server->getStream();
$port = $server->getLocalAddress()['port'];

$client1 = new Quic\ClientConnection('127.0.0.1', $port, [
    'verify_peer' => false,
]);
$client1Stream = $client1->getStream();
$peer1 = waitForAcceptedPeer($server, $serverStream, $client1, $client1Stream);
$peer1Address = $peer1->getPeerAddress();
$client1Local = $client1->getLocalAddress();

$peer1->close();
$server->flush();
drainAfterPeerClose($server, $serverStream, $client1, $client1Stream);
fclose($client1Stream);
$client1->close();

$client2 = new Quic\ClientConnection('127.0.0.1', $port, [
    'verify_peer' => false,
]);
$client2Stream = $client2->getStream();
$peer2 = waitForAcceptedPeer($server, $serverStream, $client2, $client2Stream);
$peer2Address = $peer2->getPeerAddress();
$client2Local = $client2->getLocalAddress();

var_dump($peer1Address['port'] === $client1Local['port']);
var_dump($peer1->getPeerAddress() === []);
var_dump($peer2->isHandshakeComplete());
var_dump($client2->isHandshakeComplete());
var_dump($peer2Address['port'] === $client2Local['port']);

fclose($client2Stream);
fclose($serverStream);
$client2->close();
$server->close();
