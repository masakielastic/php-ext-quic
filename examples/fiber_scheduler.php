<?php

declare(strict_types=1);

function quic_require_fiber_support(): void
{
    if (!class_exists(Fiber::class)) {
        fwrite(STDERR, "This example requires Fiber support.\n");
        exit(1);
    }
}

function quic_fiber_await_poll($stream, int $timeout): array
{
    return Fiber::suspend([
        'stream' => $stream,
        'timeout' => $timeout,
    ]);
}

function quic_run_poll_fiber(Fiber $fiber)
{
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

    return $fiber->getReturn();
}
