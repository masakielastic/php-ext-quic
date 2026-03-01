<?php

declare(strict_types=1);

if ($argc < 3) {
    fwrite(STDERR, "Usage: php server_fiber_loop.php <port> <certfile> <keyfile> [response]\n");
    exit(1);
}

if (!class_exists(Fiber::class)) {
    fwrite(STDERR, "This example requires Fiber support.\n");
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

$socket = $server->getPollStream();
stream_set_blocking($socket, false);

fwrite(STDERR, "listening on 127.0.0.1:" . $server->getLocalAddress()['port'] . PHP_EOL);

$fiber = new Fiber(static function () use ($server, $socket, $response): string {
    $peer = null;
    $accepted = null;
    $responded = false;
    $requestBody = '';

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

                return $requestBody;
            }
        }

        $event = Fiber::suspend([
            'stream' => $socket,
            'timeout' => $peer?->getTimeout() ?? $server->getTimeout() ?? 50,
        ]);

        if (($event['timed_out'] ?? false) === true) {
            $server->handleExpiry();
            continue;
        }

        $server->handleReadable();
    }
});

try {
    // The outer loop acts as a tiny scheduler for the suspended Fiber.
    $wait = $fiber->start();

    while (!$fiber->isTerminated()) {
        if (
            !is_array($wait) ||
            !isset($wait['stream']) ||
            !is_resource($wait['stream']) ||
            !isset($wait['timeout']) ||
            !is_int($wait['timeout'])
        ) {
            throw new RuntimeException('Fiber yielded an invalid wait request');
        }

        $read = [$wait['stream']];
        $write = null;
        $except = null;
        $timeout = $wait['timeout'];
        $ready = stream_select(
            $read,
            $write,
            $except,
            intdiv($timeout, 1000),
            ($timeout % 1000) * 1000,
        );

        if ($ready === false) {
            throw new RuntimeException('stream_select failed');
        }

        $wait = $fiber->resume([
            'timed_out' => $ready === 0,
        ]);
    }

    $requestBody = $fiber->getReturn();
    if ($requestBody !== '') {
        fwrite(STDOUT, $requestBody);
    }
} finally {
    fclose($socket);
    $server->close();
}
