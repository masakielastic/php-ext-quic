--TEST--
Peer-reset stream enters an abort failure path for further writes
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo "skip extension not loaded";
    return;
}
if (getenv('QUIC_RUN_INTEGRATION_TESTS') !== '1') {
    echo "skip set QUIC_RUN_INTEGRATION_TESTS=1 to run integration tests";
    return;
}
if (!function_exists('proc_open')) {
    echo 'skip proc_open is required';
    return;
}
if (!is_file('/tmp/nghttp3-localhost.crt') || !is_file('/tmp/nghttp3-localhost.key')) {
    echo "skip test certificates not prepared";
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
require __DIR__ . '/stream_abort_failure_integration.php';
?>
--EXPECT--
bool(true)
int(55)
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
