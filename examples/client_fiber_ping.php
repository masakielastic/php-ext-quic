<?php

declare(strict_types=1);

if ($argc < 3) {
    fwrite(STDERR, "Usage: php client_fiber_ping.php <host> <port> [message]\n");
    exit(1);
}

if (!class_exists(Fiber::class)) {
    fwrite(STDERR, "This example requires Fiber support.\n");
    exit(1);
}

$host = $argv[1];
$port = (int) $argv[2];
$message = $argv[3] ?? "ping\n";

$client = new Quic\ClientConnection($host, $port, [
    'verify_peer' => false,
]);

$socket = $client->getPollStream();
stream_set_blocking($socket, false);

$isExpectedClose = static function (Throwable $e, bool $streamOpened): bool {
    if (!($e instanceof Quic\ProtocolException)) {
        return false;
    }

    return $streamOpened && (
        str_contains($e->getMessage(), 'ERR_CLOSING') ||
        str_contains($e->getMessage(), 'ERR_DRAINING')
    );
};

$fiber = new Fiber(static function () use ($client, $socket, $message, $isExpectedClose): string {
    $client->startHandshake();

    $stream = null;
    $response = '';
    $deadline = microtime(true) + 5.0;

    while (microtime(true) < $deadline) {
        $client->flush();

        if ($client->isHandshakeComplete() && !($stream instanceof Quic\Stream)) {
            $stream = $client->openBidirectionalStream();
            $stream->write($message, true);
        }

        if ($stream instanceof Quic\Stream) {
            $chunk = $stream->read();
            if ($chunk !== '') {
                $response .= $chunk;
                if ($stream->isFinished()) {
                    return $response;
                }
            }
        }

        $event = Fiber::suspend([
            'stream' => $socket,
            'timeout' => $client->getTimeout() ?? 50,
        ]);

        try {
            if (($event['timed_out'] ?? false) === true) {
                $client->handleExpiry();
                continue;
            }

            $client->handleReadable();
        } catch (Throwable $e) {
            if ($isExpectedClose($e, $stream instanceof Quic\Stream)) {
                if ($stream instanceof Quic\Stream) {
                    $response .= $stream->read();
                }

                return $response;
            }

            throw $e;
        }
    }

    return $response;
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

    $response = $fiber->getReturn();
    if ($response !== '') {
        fwrite(STDOUT, $response);
    }
} finally {
    fclose($socket);
    $client->close();
}
