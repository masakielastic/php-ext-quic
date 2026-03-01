<?php

function quic_skip(string $reason): void
{
    echo 'skip ' . $reason;
}

function quic_probe_bindable_server(): bool
{
    try {
        $server = new Quic\ServerConnection('127.0.0.1', 0);
        $server->close();
        return true;
    } catch (Throwable) {
        return false;
    }
}

function quic_probe_child_bindable_server(): bool
{
    if (!function_exists('proc_open')) {
        return false;
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
        return false;
    }

    fclose($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    return proc_close($process) === 0;
}

function quic_integration_skipif(array $options = []): void
{
    if (!extension_loaded('quic')) {
        quic_skip('extension not loaded');
        return;
    }

    if (($options['require_env'] ?? true) && getenv('QUIC_RUN_INTEGRATION_TESTS') !== '1') {
        quic_skip('set QUIC_RUN_INTEGRATION_TESTS=1 to run integration tests');
        return;
    }

    if (($options['require_proc_open'] ?? false) && !function_exists('proc_open')) {
        quic_skip('proc_open is required');
        return;
    }

    if (($options['require_certs'] ?? true)
        && (!is_file('/tmp/nghttp3-localhost.crt') || !is_file('/tmp/nghttp3-localhost.key'))
    ) {
        quic_skip('prepare /tmp/nghttp3-localhost.crt and /tmp/nghttp3-localhost.key first');
        return;
    }

    if (($options['probe_bind'] ?? false) && !quic_probe_bindable_server()) {
        quic_skip('run-tests PHP cannot bind UDP sockets in this environment');
        return;
    }

    if (($options['probe_child_bind'] ?? false) && !quic_probe_child_bindable_server()) {
        quic_skip('child PHP cannot bind UDP sockets in this environment');
    }
}
