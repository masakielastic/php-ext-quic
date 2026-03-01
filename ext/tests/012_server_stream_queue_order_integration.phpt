--TEST--
Quic server peer queue preserves accepted stream order
--SKIPIF--
<?php
require __DIR__ . '/integration_skipif.inc';
quic_integration_skipif([
    'require_env' => true,
    'require_certs' => true,
    'probe_bind' => true,
]);
?>
--FILE--
<?php
require __DIR__ . '/server_stream_queue_order_integration.php';
?>
--EXPECT--
bool(true)
bool(true)
array(2) {
  [0]=>
  int(0)
  [1]=>
  int(4)
}
bool(true)
