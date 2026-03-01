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
$clientResetStream = null;
$serverObservedReset = null;
$serverResetTarget = null;
$clientObservedReset = null;
$serverDidReset = false;
$deadline = microtime(true) + 5.0;

$clientResetPayload = "client-reset\n";
$serverResetPayload = "server-reset\n";

$client->startHandshake();

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $peer = $server->popAcceptedPeer();
    }

    if ($client->isHandshakeComplete() && !$clientResetStream instanceof Quic\Stream) {
        $clientResetStream = $client->openBidirectionalStream();
        $clientResetStream->write($clientResetPayload);
        $clientResetStream->reset(42);
    }

    if (
        $client->isHandshakeComplete() &&
        $serverObservedReset instanceof Quic\Stream &&
        !$clientObservedReset instanceof Quic\Stream
    ) {
        $clientObservedReset = $client->openBidirectionalStream();
        $clientObservedReset->write($serverResetPayload, true);
    }

    if ($peer instanceof Quic\ServerPeer) {
        while (($candidate = $peer->popAcceptedStream()) instanceof Quic\Stream) {
            if (!$serverObservedReset instanceof Quic\Stream) {
                $serverObservedReset = $candidate;
                continue;
            }

            if (!$serverResetTarget instanceof Quic\Stream) {
                $serverResetTarget = $candidate;
                break;
            }
        }
    }

    if (
        !$serverDidReset &&
        $serverResetTarget instanceof Quic\Stream &&
        $serverResetTarget->read() === $serverResetPayload
    ) {
        $serverResetTarget->reset(9);
        $serverDidReset = true;
    }

    if (
        $serverObservedReset instanceof Quic\Stream &&
        $serverObservedReset->isPeerReset() &&
        $clientObservedReset instanceof Quic\Stream &&
        $clientObservedReset->isPeerReset()
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
    !$serverObservedReset instanceof Quic\Stream ||
    !$clientObservedReset instanceof Quic\Stream
) {
    throw new RuntimeException('peer reset observation did not complete');
}

var_dump($serverObservedReset->isPeerReset());
var_dump($serverObservedReset->getPeerResetErrorCode());
var_dump($serverObservedReset->getPeerResetFinalSize());
var_dump($clientObservedReset->isPeerReset());
var_dump($clientObservedReset->getPeerResetErrorCode());
var_dump($clientObservedReset->getPeerResetFinalSize());

fclose($serverStream);
fclose($clientStream);
$server->close();
$client->close();
