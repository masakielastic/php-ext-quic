--TEST--
Quic\ClientConnection verifies server certificates with cafile and capath
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
$command = [
    PHP_BINARY,
    '-d',
    'extension=' . dirname(__DIR__) . '/modules/quic.so',
    __DIR__ . '/client_tls_verify_integration.php',
];

$descriptors = [
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$env = [
    'PATH' => getenv('PATH') ?: '',
    'HOME' => getenv('HOME') ?: '',
    'LANG' => getenv('LANG') ?: 'C',
];

$process = proc_open($command, $descriptors, $pipes, __DIR__, $env);
if (!is_resource($process)) {
    throw new RuntimeException('proc_open failed');
}

$stdout = stream_get_contents($pipes[1]);
fclose($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[2]);

$status = proc_close($process);
if ($status !== 0) {
    echo $stderr;
    exit($status);
}

echo $stdout;
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
string(7) "cafile
"
string(16) "verified cafile
"
bool(true)
bool(true)
bool(true)
string(7) "capath
"
string(16) "verified capath
"
