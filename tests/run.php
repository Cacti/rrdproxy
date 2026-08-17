<?php

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/include/global.php';
require dirname(__DIR__) . '/lib/functions.php';

$failures = [];
$checks   = 0;

function check($condition, $message) {
	global $checks, $failures;

	$checks++;

	if (!$condition) {
		$failures[] = $message;
	}
}

$test_root = sys_get_temp_dir() . '/rrdproxy-tests-' . bin2hex(random_bytes(8));
$rra_root  = $test_root . '/rra';
$outside   = $test_root . '/outside';
mkdir($rra_root, 0700, true);
mkdir($outside, 0700, true);
file_put_contents($rra_root . '/sample.rrd', 'rrd');
file_put_contents($outside . '/outside.rrd', 'outside');
symlink($outside, $rra_root . '/escape');

$rrdp_config        = ['path_rra' => $rra_root];
$canonical_rra_root = realpath($rra_root);

check(rrdp_resolve_rra_path('sample.rrd') === realpath($rra_root . '/sample.rrd'), 'A valid RRA path should resolve');
check(rrdp_resolve_rra_path('nested/new', false) === $canonical_rra_root . '/nested/new', 'A future path beneath the RRA root should resolve');
check(rrdp_resolve_rra_path('../outside/outside.rrd') === false, 'Parent traversal must be rejected');
check(rrdp_resolve_rra_path($outside . '/outside.rrd') === false, 'Absolute paths must be rejected');
check(rrdp_resolve_rra_path('escape/outside.rrd') === false, 'Symlink escapes must be rejected');
check(rrdp_command_has_unsafe_path("update foo.rrd\ncreate escaped.rrd"), 'Embedded commands must be rejected');
check(rrdp_command_has_unsafe_path('update ../outside.rrd'), 'RRDtool traversal must be rejected');
check(rrdp_command_has_unsafe_path('graph graph.png DEF:x=../outside.rrd:value:AVERAGE'), 'RRDtool option traversal must be rejected');
check(rrdp_command_has_unsafe_path('update /tmp/outside.rrd'), 'Absolute RRDtool paths must be rejected');
check(rrdp_command_has_unsafe_path('graph graph.png --font TITLE:12:/tmp/font.ttf'), 'Embedded absolute RRDtool paths must be rejected');

$options = rrdp_parse_removespikes_options('-R=sample.rrd --method=stddev --dryrun');
check(is_array($options) && str_starts_with($options[0], '-R=' . $canonical_rra_root), 'Valid removespikes options should be normalized');
check(rrdp_parse_removespikes_options('-R=sample.rrd ;id') === false, 'Shell metacharacter arguments must be rejected');
check(rrdp_parse_removespikes_options('-R=../outside/outside.rrd') === false, 'removespikes traversal must be rejected');
check(rrdp_parse_removespikes_options('--dryrun') === false, 'removespikes must require exactly one RRD file');
check(rrdp_resolve_path_within($outside, 'future.rrd', false) === realpath($outside) . '/future.rrd', 'Generic containment should resolve safe future paths');
check(rrdp_resolve_path_within($outside, '../rra/sample.rrd', false) === false, 'Generic containment must reject traversal');

$process = rrdp_run_process([PHP_BINARY, '-r', 'echo $argv[1];', ';touch-not-executed']);
check($process !== false && $process['stdout'] === ';touch-not-executed', 'Process arguments must not be interpreted by a shell');

$rsa_class = 'phpseclib3\\Crypt\\RSA';
set_error_handler(static function ($severity, $message) {
	return str_contains($message, 'Unable to write random state');
});
$private = $rsa_class::createKey(2048);
restore_error_handler();
$encryption                               = true;
$rrdp_config['encryption']['private_key'] = (string) $private;
$frame                                    = encrypt('round trip', (string) $private->getPublicKey());
check(is_string($frame) && decrypt($frame) === 'round trip', 'phpseclib 3 encryption must round-trip');
check(decrypt('not-a-frame') === false, 'Malformed encrypted frames must fail closed');

$secret = $test_root . '/private.key';
check(rrdp_write_secure_file($secret, 'secret', 0600) !== false, 'Private key writes should succeed');
check((fileperms($secret) & 0777) === 0600, 'Private keys must use mode 0600');
$public_path  = $test_root . '/public.key';
$private_path = $test_root . '/pair-private.key';
check(rrdp_write_key_pair($public_path, (string) $private->getPublicKey(), $private_path, (string) $private), 'Validated key pairs should be written together');
check((fileperms($private_path) & 0777) === 0600, 'Key-pair private keys must use mode 0600');
check(!rrdp_write_key_pair($public_path, 'invalid', $private_path, (string) $private), 'Invalid key pairs must fail closed');

$sockets = [];
check(socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $sockets), 'A socket pair should be available');

if (count($sockets) === 2) {
	check(rrdp_socket_write_all($sockets[0], 'complete') === 8, 'Socket writes should report the complete byte count');
	check(socket_read($sockets[1], 8) === 'complete', 'Socket writes should deliver the complete payload');
	socket_close($sockets[0]);
	socket_close($sockets[1]);
}

function remove_test_tree($path) {
	if (is_link($path) || is_file($path)) {
		unlink($path);

		return;
	}

	foreach (scandir($path) as $entry) {
		if ($entry !== '.' && $entry !== '..') {
			remove_test_tree($path . DIRECTORY_SEPARATOR . $entry);
		}
	}

	rmdir($path);
}

remove_test_tree($test_root);

if ($failures) {
	fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
	exit(1);
}

print "OK ($checks checks)" . PHP_EOL;
