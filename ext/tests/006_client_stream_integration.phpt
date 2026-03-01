--TEST--
Quic\ClientConnection exchanges stream data with the sample server
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
    return;
}

if (getenv('QUIC_RUN_INTEGRATION_TESTS') !== '1') {
    echo 'skip set QUIC_RUN_INTEGRATION_TESTS=1 to run integration tests';
    return;
}

if (!function_exists('proc_open')) {
    echo 'skip proc_open is required';
    return;
}

$server = getenv('QUIC_SAMPLE_SERVER_BIN') ?: '/tmp/quic-sample-server';
$cert = getenv('QUIC_SAMPLE_SERVER_CERT') ?: '/tmp/nghttp3-localhost.crt';
$key = getenv('QUIC_SAMPLE_SERVER_KEY') ?: '/tmp/nghttp3-localhost.key';

if (!is_file($server)) {
    echo 'skip sample server binary not found; run ext/tests/prepare_client_integration.sh';
    return;
}

if (!is_file($cert) || !is_file($key)) {
    echo 'skip sample server certificate files not found; run ext/tests/prepare_client_integration.sh';
    return;
}
?>
--FILE--
<?php
$server = getenv('QUIC_SAMPLE_SERVER_BIN') ?: '/tmp/quic-sample-server';
$cert = getenv('QUIC_SAMPLE_SERVER_CERT') ?: '/tmp/nghttp3-localhost.crt';
$key = getenv('QUIC_SAMPLE_SERVER_KEY') ?: '/tmp/nghttp3-localhost.key';
$port = getenv('QUIC_SAMPLE_SERVER_PORT') ?: '18443';
$response = 'integration response';

$descriptors = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$command = [
    $server,
    '--host', '127.0.0.1',
    '--port', $port,
    '--cert', $cert,
    '--key', $key,
    '--response', $response,
];

$proc = proc_open($command, $descriptors, $pipes);
if (!is_resource($proc)) {
    throw new RuntimeException('failed to start sample server');
}

fclose($pipes[0]);
stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], false);

try {
    usleep(200000);

    $client = new Quic\ClientConnection('127.0.0.1', (int) $port, [
        'verify_peer' => false,
    ]);
    $socket = $client->getStream();
    stream_set_blocking($socket, false);
    $client->startHandshake();

    $stream = null;
    $body = null;
    $deadline = microtime(true) + 5.0;

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
            $client->handleReadable();
        } else {
            $client->handleExpiry();
        }

        if ($client->isHandshakeComplete() && $stream === null) {
            $stream = $client->openBidirectionalStream();
            $stream->write("ping\n", true);
        }

        if ($stream !== null && $stream->isReadable()) {
            $body = trim($stream->read());
            break;
        }
    }

    var_dump($client->isHandshakeComplete());
    var_dump($stream instanceof Quic\Stream);
    var_dump($body);
} finally {
    proc_terminate($proc);
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
}
?>
--EXPECT--
bool(true)
bool(true)
string(20) "integration response"
