<?php

declare(strict_types=1);

if ($argc < 3) {
    fwrite(STDERR, "Usage: php server_loop.php <port> <certfile> <keyfile> [response]\n");
    exit(1);
}

$port = (int) $argv[1];
$certfile = $argv[2];
$keyfile = $argv[3] ?? '';
$response = $argv[4] ?? "server response\n";

if ($keyfile === '') {
    fwrite(STDERR, "Missing keyfile\n");
    exit(1);
}

$server = new Quic\ServerConnection('127.0.0.1', $port, [
    'certfile' => $certfile,
    'keyfile' => $keyfile,
    'response' => null,
]);

$socket = $server->getStream();
$peer = null;
$accepted = null;
$responded = false;
$requestBody = '';

fwrite(STDERR, "listening on 127.0.0.1:" . $server->getLocalAddress()['port'] . PHP_EOL);

while (true) {
    $server->flush();

    if (!($peer instanceof Quic\ServerPeer)) {
        $peer = $server->popAcceptedPeer();
        if ($peer instanceof Quic\ServerPeer) {
            $peerAddress = $peer->getPeerAddress();
            fwrite(STDERR, "accepted peer " . $peerAddress['address'] . ':' . $peerAddress['port'] . PHP_EOL);
        }
    }

    if ($accepted === null && $peer instanceof Quic\ServerPeer) {
        $accepted = $peer->popAcceptedStream();
    }

    if ($accepted instanceof Quic\Stream) {
        $chunk = $accepted->read();
        if ($chunk !== '') {
            $requestBody .= $chunk;
        }

        if (!$responded && $accepted->isFinished() && $accepted->isWritable()) {
            $accepted->write($response, true);
            $server->flush();
            $responded = true;
        }

        if ($responded && $accepted->isFinished() && $requestBody !== '') {
            if ($peer instanceof Quic\ServerPeer) {
                $peer->close();
                $server->flush();
            }
            fwrite(STDOUT, $requestBody);
            break;
        }
    }

    $read = [$socket];
    $write = null;
    $except = null;
    $timeout = $peer?->getTimeout() ?? $server->getTimeout() ?? 50;
    $ready = stream_select($read, $write, $except, intdiv($timeout, 1000), ($timeout % 1000) * 1000);

    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        $server->handleExpiry();
        continue;
    }

    $server->handleReadable();
}

fclose($socket);
$server->close();
