<?php

$server = dirname(__DIR__, 2) . '/examples/server_loop.php';
$extension = dirname(__DIR__) . '/modules/quic.so';
$cert = '/tmp/nghttp3-localhost.crt';
$key = '/tmp/nghttp3-localhost.key';
$response = 'integration response';

$descriptors = [
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$command = [
    PHP_BINARY,
    '-d',
    'extension=' . $extension,
    $server,
    '0',
    $cert,
    $key,
    $response . "\n",
];

$env = [
    'PATH' => getenv('PATH') ?: '',
    'HOME' => getenv('HOME') ?: '',
    'LANG' => getenv('LANG') ?: 'C',
];

$proc = proc_open($command, $descriptors, $pipes, __DIR__, $env);
if (!is_resource($proc)) {
    throw new RuntimeException('failed to start php server example');
}

stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], true);

$listening = stream_get_line($pipes[2], 4096, PHP_EOL);
if (!is_string($listening) || !preg_match('/:(\d+)$/', trim($listening), $matches)) {
    throw new RuntimeException('failed to read server port');
}

$port = (int) $matches[1];
stream_set_blocking($pipes[2], false);
$serverBody = '';

try {
    $client = new Quic\ClientConnection('127.0.0.1', $port, [
        'verify_peer' => false,
    ]);
    $socket = $client->getPollStream();
    stream_set_blocking($socket, false);
    $client->startHandshake();

    $stream = null;
    $body = '';
    $deadline = microtime(true) + 5.0;
    $isExpectedClose = static function (Throwable $e, bool $streamOpened): bool {
        if (!($e instanceof Quic\ProtocolException)) {
            return false;
        }

        return $streamOpened && (
            str_contains($e->getMessage(), 'ERR_CLOSING') ||
            str_contains($e->getMessage(), 'ERR_DRAINING')
        );
    };

    while (microtime(true) < $deadline) {
        $client->flush();

        $timeout = $client->getTimeout();
        $sec = 0;
        $usec = 20000;
        if ($timeout !== null) {
            $sec = intdiv($timeout, 1000);
            $usec = ($timeout % 1000) * 1000;
        }

        $read = [$socket];
        $write = null;
        $except = null;
        $ready = @stream_select($read, $write, $except, $sec, $usec);
        if ($ready === false) {
            throw new RuntimeException('stream_select failed');
        }

        if ($ready > 0) {
            try {
                $client->handleReadable();
            } catch (Throwable $e) {
                if (!$isExpectedClose($e, $stream instanceof Quic\Stream)) {
                    throw $e;
                }

                if ($stream instanceof Quic\Stream) {
                    $body .= $stream->read();
                }
                break;
            }
        } else {
            try {
                $client->handleExpiry();
            } catch (Throwable $e) {
                if (!$isExpectedClose($e, $stream instanceof Quic\Stream)) {
                    throw $e;
                }

                if ($stream instanceof Quic\Stream) {
                    $body .= $stream->read();
                }
                break;
            }
        }

        if ($client->isHandshakeComplete() && $stream === null) {
            $stream = $client->openBidirectionalStream();
            $stream->write("ping\n", true);
        }

        if ($stream !== null && $stream->isReadable()) {
            $body .= $stream->read();
            if ($stream->isFinished()) {
                break;
            }
        }
    }

    var_dump($client->isHandshakeComplete());
    var_dump($stream instanceof Quic\Stream);
    var_dump(trim($body));
} finally {
    $status = proc_get_status($proc);
    if ($status['running']) {
        proc_terminate($proc);
    }
    $serverBody = trim(stream_get_contents($pipes[1]));
    fclose($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    proc_close($proc);
}

var_dump($serverBody);
