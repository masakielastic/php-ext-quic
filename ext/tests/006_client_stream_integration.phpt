--TEST--
Quic\ClientConnection exchanges stream data with the PHP server example
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

if (!is_file('/tmp/nghttp3-localhost.crt') || !is_file('/tmp/nghttp3-localhost.key')) {
    echo 'skip prepare /tmp/nghttp3-localhost.crt and /tmp/nghttp3-localhost.key first';
    return;
}

$probe = [
    PHP_BINARY,
    '-d',
    'extension=' . dirname(__DIR__) . '/modules/quic.so',
    '-r',
    'new Quic\ServerConnection("127.0.0.1", 0);',
];
$descriptors = [
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];
$process = proc_open($probe, $descriptors, $pipes, __DIR__, [
    'PATH' => getenv('PATH') ?: '',
    'HOME' => getenv('HOME') ?: '',
    'LANG' => getenv('LANG') ?: 'C',
]);
if (!is_resource($process)) {
    echo 'skip proc_open probe failed';
    return;
}
fclose($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[2]);
$status = proc_close($process);
if ($status !== 0) {
    echo 'skip child php cannot bind UDP socket in this environment';
}
?>
--FILE--
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
$serverError = '';

try {
    $client = new Quic\ClientConnection('127.0.0.1', $port, [
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
    $status = proc_get_status($proc);
    if ($status['running']) {
        proc_terminate($proc);
    }
    $serverBody = trim(stream_get_contents($pipes[1]));
    $serverError = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
}

var_dump($serverBody);
?>
--EXPECT--
bool(true)
bool(true)
string(20) "integration response"
string(4) "ping"
