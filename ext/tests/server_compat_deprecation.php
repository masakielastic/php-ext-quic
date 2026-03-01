<?php

$messages = [];
set_error_handler(static function (int $severity, string $message) use (&$messages): bool {
    if ($severity === E_DEPRECATED) {
        $messages[] = $message;
        return true;
    }

    return false;
});

$server = new Quic\ServerConnection('127.0.0.1', 0);

var_dump($server->isHandshakeComplete());
var_dump($server->getPeerAddress());
var_dump($server->popAcceptedStream());
var_dump(count($messages));
var_dump(str_contains($messages[0] ?? '', 'Quic\\ServerConnection::isHandshakeComplete'));
var_dump(str_contains($messages[1] ?? '', 'Quic\\ServerConnection::getPeerAddress'));
var_dump(str_contains($messages[2] ?? '', 'Quic\\ServerConnection::popAcceptedStream'));

$stream = $server->getPollStream();
fclose($stream);
$server->close();
restore_error_handler();
