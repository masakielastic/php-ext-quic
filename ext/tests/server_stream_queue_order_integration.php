<?php

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
$client->startHandshake();

$peer = null;
$opened = false;
$listenerIds = [];
$peerIds = [];
$deadline = microtime(true) + 5.0;

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $candidate = $server->popAcceptedPeer();
        if ($candidate instanceof Quic\ServerPeer) {
            $peer = $candidate;
        }
    }

    if ($client->isHandshakeComplete() && !$opened) {
        $stream1 = $client->openBidirectionalStream();
        $stream1->write("one\n", true);

        $stream2 = $client->openBidirectionalStream();
        $stream2->write("two\n", true);
        $opened = true;
    }

    while (count($listenerIds) < 2) {
        $candidate = $server->popAcceptedStream();
        if (!$candidate instanceof Quic\Stream) {
            break;
        }

        $listenerIds[] = $candidate->getId();
    }

    while ($peer instanceof Quic\ServerPeer && count($peerIds) < 2) {
        $candidate = $peer->popAcceptedStream();
        if (!$candidate instanceof Quic\Stream) {
            break;
        }

        $peerIds[] = $candidate->getId();
    }

    if (count($listenerIds) === 2 && count($peerIds) === 2) {
        break;
    }

    $read = [$serverStream, $clientStream];
    $write = null;
    $except = null;
    $timeouts = array_values(array_filter([
        $server->getTimeout(),
        $peer?->getTimeout(),
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

var_dump($server->isHandshakeComplete());
var_dump($client->isHandshakeComplete());
var_dump($listenerIds);
var_dump($peerIds);
var_dump($listenerIds === $peerIds);

fclose($serverStream);
fclose($clientStream);
$server->close();
$client->close();
