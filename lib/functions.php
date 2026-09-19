<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDTool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

use phpseclib4\Crypt\Rijndael;
use phpseclib4\Crypt\RSA;

/**
 * Starts an RRDtool pipe-mode process and returns its process handle and stdio pipes.
 *
 * @param array<string, mixed> $rrdp_config
 *
 * @return array{0: resource, 1: array<int, resource>}|false
 */
function rrdtool_pipe_init($rrdp_config) {
	$fds = [
		0 => ['pipe', 'r'],				// stdin
		1 => ['pipe', 'w'],				// stdout
		2 => ['file', '/dev/null', 'a']	// stderr
	];
	$process = @proc_open([$rrdp_config['path_rrdtool'], '-', $rrdp_config['path_rra']], $fds, $pipes);

	if ($process === false) {
		return false;
	} else {
		// make stdin/stdout/stderr non-blocking
		stream_set_blocking($pipes[0], 0);
		stream_set_blocking($pipes[1], 0);

		return [$process, $pipes];
	}
}

/**
 * Terminates a previously opened RRDtool pipe-mode process.
 *
 * @param resource $process
 *
 * @return void
 */
function rrdtool_pipe_close($process) {
	proc_close($process);
}

/**
 * Writes a command to an open RRDtool pipe and streams the (optionally compressed,
 * encrypted) response back over the client socket in chunks as it arrives.
 *
 * @param string                $command
 * @param array<int, resource>  $pipes
 * @param resource|\Socket|false $socket
 * @param string                $client_public_key
 * @param bool                  $compression
 * @param bool                  $silent_mode
 * @param string                $terminator
 *
 * @return bool|string|null
 */
function rrdtool_pipe_execute($command, $pipes, $socket, $client_public_key, $compression, $silent_mode = false, $terminator = "_EOT_\r\n") {
	$return_code = fwrite($pipes[0], $command);

	if ($return_code === false) {
		// pipe broken
		__logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL PIPE BROKEN caused by: ' . $command, 'IPC', SEVERITY_LEVEL_ALERT);

		return null;
	}

	$buffer          = '';
	$packets         = 0;
	$max_buffer_size = $compression ? 655360 : 65536;

	while (!feof($pipes[1])) {
		$stdout = fread($pipes[1], 8192);

		if ($stdout) {
			$buffer .= $stdout;
		}

		if (substr_count($buffer, 'OK u')) {
			$buffer = trim($buffer);

			if (!$silent_mode) {
				if ($compression) {
					$buffer_length = strlen($buffer);
					$buffer        = gzencode($buffer,1);

					if ($buffer === false) {
						__logging(LOGGING_LOCATION_BUFFERED, 'COMPRESSION ERROR', 'IPC', SEVERITY_LEVEL_EMERGENCY);

						return true;
					}

					$buffer_length_new = strlen($buffer);

					rrdp_system__socket_write($socket, encrypt($buffer, $client_public_key) . $terminator);
					$packets++;

					__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length_new . ' Bytes, compression: on , ratio: ' . round(($buffer_length / $buffer_length_new),2) . ' , packets: ' . $packets, 'IPC', SEVERITY_LEVEL_DEBUG);
				} else {
					if (rrdp_system__is_resource($socket) === true) {
						$buffer_length = strlen($buffer);

						rrdp_system__socket_write($socket, encrypt($buffer, $client_public_key) . $terminator);
						$packets++;

						__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length . ' Bytes, compression: off' . ' , packets: ' . $packets, 'IPC', SEVERITY_LEVEL_DEBUG);
					} else {
						return $buffer;
					}
				}
			} else {
				__logging(LOGGING_LOCATION_BUFFERED, 'NO RESPONSE (silent_mode=1) ' . 'Status: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
			}

			return true;
		}

		if (substr_count($buffer, 'ERROR')) {
			if (!$silent_mode) {
				if (rrdp_system__is_resource($socket) === true) {
					__logging(LOGGING_LOCATION_BUFFERED, $buffer, 'IPC', SEVERITY_LEVEL_DEBUG);

					rrdp_system__socket_write($socket, encrypt((($compression === true) ? gzencode($buffer,1) : $buffer), $client_public_key) . $terminator);
				}
			} else {
				__logging(LOGGING_LOCATION_BUFFERED, 'NO RESPONSE (silent_mode=1) ' . 'Status: ' . RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
			}

			return false;
		} else {
			if (strlen($buffer) <= $max_buffer_size | rrdp_system__is_resource($socket) === false) {
				continue;
			} else {
				if (!$silent_mode) {
					if ($compression) {
						$buffer_length = strlen($buffer);
						$buffer        = gzencode($buffer,1);

						if ($buffer === false) {
							__logging(LOGGING_LOCATION_BUFFERED, 'COMPRESSION ERROR', 'IPC', SEVERITY_LEVEL_EMERGENCY);

							return true;
						}

						$buffer_length_new = strlen($buffer);

						rrdp_system__socket_write($socket, encrypt($buffer, $client_public_key) . "_EOP_\r\n");
						$packets++;

						__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length_new . ' Bytes, compression: on , ratio: ' . round(($buffer_length / $buffer_length_new),2), 'IPC', SEVERITY_LEVEL_DEBUG);
					} else {
						$buffer_length = strlen($buffer);

						rrdp_system__socket_write($socket, encrypt($buffer, $client_public_key) . "_EOP_\r\n");
						$packets++;

						__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length . ' Bytes, compression: off', 'IPC', SEVERITY_LEVEL_DEBUG);
					}
				}

				$buffer = '';
			}
		}
	}

	return null;
}

/**
 * Encrypts $output for the holder of $rsa_key: a random AES-256-CBC session key
 * encrypts the payload, and that session key is itself RSA-encrypted and prepended.
 *
 * @param string $output
 * @param string $rsa_key
 *
 * @return string|false
 */
function encrypt($output, $rsa_key) {
	global $encryption;

	if (!$encryption) {
		return $output;
	}

	try {
		$public  = RSA::loadPublicKey($rsa_key);

		if (!$public instanceof phpseclib4\Crypt\RSA\PublicKey) {
			return false;
		}

		$aes     = new Rijndael('cbc');
		$aes_key = random_bytes(32);

		$aes->setKey($aes_key);
		$aes->setIV(str_repeat("\0", 16));
		$ciphertext     = base64_encode($aes->encrypt($output));
		$aes_key        = base64_encode($public->encrypt($aes_key));
		$aes_key_length = str_pad(dechex(strlen($aes_key)), 3, '0', STR_PAD_LEFT);

		return $aes_key_length . $aes_key . $ciphertext;
	} catch (Throwable $e) {
		return false;
	}
}

/**
 * Reverses encrypt(): RSA-decrypts the embedded AES session key with this proxy's
 * private key, then AES-256-CBC decrypts the remaining ciphertext.
 *
 * @param string $input
 *
 * @return string|false
 */
function decrypt($input) {
	global $rrdp_config, $encryption;

	if (!$encryption) {
		return $input;
	}

	if (strlen($input) < 4 || !ctype_xdigit(substr($input, 0, 3))) {
		return false;
	}

	$aes_key_length = hexdec(substr($input, 0, 3));

	if ($aes_key_length < 1 || strlen($input) <= 3 + $aes_key_length) {
		return false;
	}

	$aes_key    = base64_decode(substr($input, 3, $aes_key_length), true);
	$ciphertext = base64_decode(substr($input, 3 + $aes_key_length), true);

	if ($aes_key === false || $aes_key === '' || $ciphertext === false) {
		return false;
	}

	try {
		$private = RSA::loadPrivateKey($rrdp_config['encryption']['private_key']);

		if (!$private instanceof phpseclib4\Crypt\RSA\PrivateKey) {
			return false;
		}

		$aes     = new Rijndael('cbc');
		$aes_key = $private->decrypt($aes_key);

		if (!is_string($aes_key) || $aes_key === '') {
			return false;
		}

		// phpseclib 2 truncated oversized Rijndael keys to 256 bits.
		if (strlen($aes_key) > 32) {
			$aes_key = substr($aes_key, 0, 32);
		}

		$aes->setKey($aes_key);
		$aes->setIV(str_repeat("\0", 16));

		return $aes->decrypt($ciphertext);
	} catch (Throwable $e) {
		return false;
	}
}

/**
 * Determines whether a path is absolute (POSIX-rooted, UNC/backslash-rooted, or
 * Windows drive-letter-rooted).
 *
 * @param string $path
 *
 * @return bool
 */
function rrdp_path_is_absolute($path) {
	return str_starts_with($path, '/') || str_starts_with($path, '\\') || preg_match('/^[A-Za-z]:[\\\\\/]/', $path) === 1;
}

/**
 * Resolves a client-supplied path against the configured RRA root, rejecting it
 * if it would escape that root.
 *
 * @param string $path
 * @param bool   $must_exist
 *
 * @return string|false
 */
function rrdp_resolve_rra_path($path, $must_exist = true) {
	global $rrdp_config;

	return rrdp_resolve_path_within($rrdp_config['path_rra'], $path, $must_exist);
}

/**
 * Resolves $path relative to $base_path and confirms the result (or, for paths that
 * don't need to exist yet, its nearest existing ancestor) stays within $base_path,
 * rejecting traversal, absolute paths, null bytes, and symlink escapes.
 *
 * @param string $base_path
 * @param mixed  $path
 * @param bool   $must_exist
 *
 * @return string|false
 */
function rrdp_resolve_path_within($base_path, $path, $must_exist = true) {
	if (!is_string($path) || $path === '' || str_contains($path, "\0") || rrdp_path_is_absolute($path)) {
		return false;
	}

	$segments = preg_split('~[\\\\/]+~', $path, -1, PREG_SPLIT_NO_EMPTY);

	if ($segments === false || in_array('..', $segments, true)) {
		return false;
	}

	$base = realpath($base_path);

	if ($base === false) {
		return false;
	}

	if ($must_exist) {
		$resolved = realpath($base . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $segments));

		return $resolved !== false && rrdp_path_is_within($resolved, $base) ? $resolved : false;
	}

	// Walk the path one segment at a time (instead of only checking the nearest
	// existing ancestor) so that a symlink anywhere along a not-yet-fully-existing
	// path is resolved and confined, even if the symlink itself is dangling.
	$walked = $base;

	for ($i = 0; $i < count($segments); $i++) {
		$next = $walked . DIRECTORY_SEPARATOR . $segments[$i];

		if (is_link($next)) {
			$resolved_link = realpath($next);

			if ($resolved_link === false || !rrdp_path_is_within($resolved_link, $base)) {
				return false;
			}

			$walked = $resolved_link;

			continue;
		}

		if (!file_exists($next)) {
			// the remaining segments are the not-yet-created portion of the path
			return $walked . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, array_slice($segments, $i));
		}

		$walked = $next;
	}

	// the full path already exists; confirm its canonical form is still confined
	$resolved = realpath($walked);

	return $resolved !== false && rrdp_path_is_within($resolved, $base) ? $resolved : false;
}

/**
 * Checks whether a canonical path is equal to, or nested under, a canonical base path.
 *
 * @param string $path
 * @param string $base
 *
 * @return bool
 */
function rrdp_path_is_within($path, $base) {
	return $path === $base || str_starts_with($path, $base . DIRECTORY_SEPARATOR);
}

/**
 * Detects RRDtool command arguments that attempt path traversal, absolute paths, or
 * embedded command framing (via null bytes/newlines) so such commands can be rejected.
 * This is a lexical, framing-level check only: it does not resolve operands against
 * the filesystem, so it cannot by itself catch a symlink placed inside the RRA root
 * that points outside it. Callers must also pass the command through
 * rrdp_resolve_command_paths() before dispatching it to RRDtool.
 *
 * @param string $command
 *
 * @return bool
 */
function rrdp_command_has_unsafe_path($command) {
	return str_contains($command, "\0")
		|| str_contains($command, "\r")
		|| str_contains($command, "\n")
		|| preg_match('~(^|[[:space:]=:,\\\\/])\.\.([\\\\/]|$)~', $command)        === 1
		|| preg_match('~(^|[[:space:]=:,])(?:/|\\\\|[A-Za-z]:[\\\\/])~', $command) === 1;
}

/**
 * Resolves every RRD file path operand referenced by an RRDtool command (the
 * leading bare file argument(s), e.g. for update/fetch/dump/restore, and any
 * DEF:/SDEF: clauses used by graph/graphv/xport) against the RRA root, and
 * rewrites the command to use the canonical resolved paths. This closes the gap
 * left by rrdp_command_has_unsafe_path(): resolving through realpath() follows
 * (and thereby confines) symlinks instead of only rejecting lexical traversal.
 *
 * @param string $cmd
 * @param string $cmd_options
 *
 * @return string|false
 */
function rrdp_resolve_command_paths($cmd, $cmd_options) {
	static $leading_file_operands = [
		'create'      => [false],
		'update'      => [true],
		'updatev'     => [true],
		'dump'        => [true],
		'restore'     => [true, false],
		'last'        => [true],
		'lastupdate'  => [true],
		'first'       => [true],
		'info'        => [true],
		'fetch'       => [true],
		'tune'        => [true],
		'resize'      => [true],
		'graph'       => [false],
		'graphv'      => [false],
		'flushcached' => [true],
	];

	$tokens = preg_split('/\s+/', trim((string) $cmd_options), -1, PREG_SPLIT_NO_EMPTY);

	if ($tokens === false) {
		return false;
	}

	$must_exist_list = $leading_file_operands[$cmd] ?? [];
	$operand_index    = 0;

	foreach ($tokens as $index => $token) {
		if (preg_match('/^((?:DEF|SDEF):[^=]+=)([^:]+)(:.*)$/i', $token, $matches) === 1) {
			$resolved = rrdp_resolve_rra_path($matches[2]);

			if ($resolved === false) {
				return false;
			}

			$tokens[$index] = $matches[1] . $resolved . $matches[3];

			continue;
		}

		if ($token[0] === '-' || preg_match('/^(?:CDEF|VDEF):/i', $token) === 1) {
			continue;
		}

		if ($operand_index < count($must_exist_list)) {
			$resolved = rrdp_resolve_rra_path($token, $must_exist_list[$operand_index]);

			if ($resolved === false) {
				return false;
			}

			$tokens[$index] = $resolved;
			$operand_index++;
		}
	}

	return implode(' ', $tokens);
}

/**
 * Parses and whitelists removespikes CLI options from a client request, resolving
 * the RRD file argument against the RRA root and rejecting anything unrecognized,
 * malformed, or containing more than one RRD file argument.
 *
 * @param string $input
 *
 * @return array<int, string>|false
 */
function rrdp_parse_removespikes_options($input) {
	$options     = str_getcsv($input, ' ', '"', '\\');
	$result      = [];
	$has_rrdfile = false;

	foreach ($options as $option) {
		if ($option === '') {
			continue;
		}

		if (in_array($option, ['--backup', '--html', '--debug', '-d', '--dryrun', '-D'], true)) {
			$result[] = $option;

			continue;
		}

		if (preg_match('/^(?:-M|--method)=(?:stddev|variance)$/', $option)
			|| preg_match('/^(?:-A|--avgnan)=(?:avg|nan)$/', $option)
			|| preg_match('/^(?:-S|--stddev|-P|--percent|-N|--number|-n|-O|--outliers)=[0-9]+(?:\.[0-9]+)?$/', $option)) {
			$result[] = $option;

			continue;
		}

		if (preg_match('/^(?:-R|--rrdfile)=(.+)$/', $option, $matches)) {
			if ($has_rrdfile) {
				return false;
			}

			$path = rrdp_resolve_rra_path($matches[1]);

			if ($path === false || !str_ends_with(strtolower($path), '.rrd')) {
				return false;
			}

			$result[]    = $option[1] === 'R' ? '-R=' . $path : '--rrdfile=' . $path;
			$has_rrdfile = true;

			continue;
		}

		return false;
	}

	return $has_rrdfile ? $result : false;
}

/**
 * Runs an argv-style child process (no shell interpolation) and captures its
 * combined stdout/stderr and exit status.
 *
 * @param array<int, string>        $command
 * @param array<string, string>|null $environment
 *
 * @return array{status: int, stdout: string, stderr: string}|false
 */
function rrdp_run_process($command, $environment = null) {
	$descriptors = [
		1 => ['pipe', 'w'],
		2 => ['redirect', 1],
	];
	$process = proc_open($command, $descriptors, $pipes, null, $environment);

	if (!is_resource($process)) {
		return false;
	}

	$stdout = stream_get_contents($pipes[1]);
	fclose($pipes[1]);
	$status = proc_close($process);

	return ['status' => $status, 'stdout' => $stdout, 'stderr' => ''];
}

/**
 * Atomically writes $contents to $path (via a temp file in the same directory,
 * chmod'd before the rename) so the file never appears with the wrong permissions.
 *
 * @param string $path
 * @param string $contents
 * @param int    $mode
 *
 * @return int|false
 */
function rrdp_write_secure_file($path, $contents, $mode = 0600) {
	$directory = dirname($path);
	$temporary = tempnam($directory, '.rrdp-');

	if ($temporary === false) {
		return false;
	}

	@chmod($temporary, $mode);
	$written = file_put_contents($temporary, $contents, LOCK_EX);

	if ($written === false || !@rename($temporary, $path)) {
		@unlink($temporary);

		return false;
	}

	@chmod($path, $mode);

	return $written;
}

/**
 * Validates that a public/private key pair actually match (by comparing
 * fingerprints) and then atomically writes both files, restoring the previous
 * private key if the public key write fails partway through.
 *
 * @param string $public_path
 * @param string $public_key
 * @param string $private_path
 * @param string $private_key
 *
 * @return bool
 */
function rrdp_write_key_pair($public_path, $public_key, $private_path, $private_key) {
	try {
		$public_fingerprint  = RSA::loadPublicKey($public_key)->getFingerprint('sha256');
		$private_fingerprint = RSA::loadPrivateKey($private_key)->getPublicKey()->getFingerprint('sha256');
	} catch (Throwable $e) {
		return false;
	}

	if (!hash_equals($public_fingerprint, $private_fingerprint)) {
		return false;
	}

	$public_temporary  = tempnam(dirname($public_path), '.rrdp-public-');
	$private_temporary = tempnam(dirname($private_path), '.rrdp-private-');

	if ($public_temporary === false || $private_temporary === false) {
		if ($public_temporary !== false) {
			@unlink($public_temporary);
		}

		if ($private_temporary !== false) {
			@unlink($private_temporary);
		}

		return false;
	}

	@chmod($public_temporary, 0644);
	@chmod($private_temporary, 0600);

	if (file_put_contents($public_temporary, $public_key, LOCK_EX)   === false
		|| file_put_contents($private_temporary, $private_key, LOCK_EX) === false) {
		@unlink($public_temporary);
		@unlink($private_temporary);

		return false;
	}

	$previous_private = file_exists($private_path) ? file_get_contents($private_path) : false;

	if (!@rename($private_temporary, $private_path)) {
		@unlink($public_temporary);
		@unlink($private_temporary);

		return false;
	}

	if (!@rename($public_temporary, $public_path)) {
		@unlink($public_temporary);

		if ($previous_private === false) {
			@unlink($private_path);
		} else {
			rrdp_write_secure_file($private_path, $previous_private, 0600);
		}

		return false;
	}

	@chmod($public_path, 0644);
	@chmod($private_path, 0600);

	return true;
}

/**
 * Writes $output to a socket in a loop, retrying until every byte has been sent
 * (socket_write() may perform a short write).
 *
 * @param resource|\Socket $socket
 * @param string           $output
 *
 * @return int|false
 */
function rrdp_socket_write_all($socket, $output) {
	$length  = strlen($output);
	$written = 0;

	while ($written < $length) {
		$result = @socket_write($socket, substr($output, $written), $length - $written);

		if ($result === false || $result === 0) {
			return false;
		}

		$written += $result;
	}

	return $written;
}

/**
 * Forwards a log message to the parent process over the IPC socket if it meets
 * the configured severity/category thresholds for its logging location.
 *
 * @param int    $location
 * @param string $msg
 * @param string $category
 * @param int    $severity
 *
 * @return void
 */
function __logging($location, $msg, $category, $severity) {
	global $rrdp_config, $ipc_socket_parent, $ipc_global_resource_id, $c_pid;

	if (($location === LOGGING_LOCATION_BUFFERED && $rrdp_config['logging_severity_buffered'] && $severity <= $rrdp_config['logging_severity_buffered'])
		|| ($location === LOGGING_LOCATION_SNMP && $rrdp_config['logging_severity_snmp'] && $severity <= $rrdp_config['logging_severity_snmp'])
		|| ($rrdp_config['logging_severity_console'] && $severity <= $rrdp_config['logging_severity_console'] && ($rrdp_config['logging_category_console'] == 'all' || stripos($rrdp_config['logging_category_console'], $category) !== false))) {
		@socket_write($ipc_socket_parent, serialize(['type' => 'debug', 'status' => 'debugging', 'debug' => ['msg' => '#' . $ipc_global_resource_id . ' [' . $c_pid . '] ' . $msg, 'category' => $category, 'severity' => $severity, 'location' => $location ] ]) . "\r\n");
		usleep(10000);
	}
}

/**
 * Null/false-safe wrapper around sizeof().
 *
 * @param mixed $array
 *
 * @return int
 */
function __sizeof($array) {
	return ($array === false || !is_array($array)) ? 0 : sizeof($array);
}

/**
 * Null/false-safe wrapper around count().
 *
 * @param mixed $array
 *
 * @return int
 */
function __count($array) {
	return ($array === false || !is_array($array)) ? 0 : count($array);
}

/**
 * Custom error handler: logs PHP user-level errors/warnings/notices via __logging()
 * and terminates the process on E_USER_ERROR.
 *
 * @param int    $code
 * @param string $text
 * @param string $file
 * @param int    $line
 *
 * @return bool|null
 */
function __errorHandler($code, $text, $file, $line) {
	if (!($code & error_reporting())) {
		return null;
	}

	switch ($code) {
		case E_USER_ERROR:
			__logging(LOGGING_LOCATION_BUFFERED, "ERROR [$code] $text, file: $file ,line: $line", 'SYS', SEVERITY_LEVEL_ERROR);
			exit(1);

			break;
		case E_USER_WARNING:
			__logging(LOGGING_LOCATION_BUFFERED, "WARNING [$code] $text", 'SYS', SEVERITY_LEVEL_WARNING);

			break;
		case E_USER_NOTICE:
			__logging(LOGGING_LOCATION_BUFFERED, "NOTICE [$code] $text", 'SYS', SEVERITY_LEVEL_NOTIFICATION);

			break;
		default:
			__logging(LOGGING_LOCATION_BUFFERED, "UNKNOWN ERROR TYPE [$code] $text, file: $file ,line: $line", 'SYS', SEVERITY_LEVEL_EMERGENCY);

			break;
	}

	return true;
}

// signal handler for master, slave and client processes
/**
 * Exits cleanly on SIGTERM; ignores SIGUSR1/SIGHUP and any other signal.
 *
 * @param int $signo
 *
 * @return void
 */
function __sig_handler($signo) {
	switch ($signo) {
		case SIGTERM:
			exit;

			break;
		case SIGUSR1:
		case SIGHUP:
			break;
		default:
	}
}

/**
 * Checks (via `ps`) whether another rrdtool-proxy.php process is already running.
 *
 * @return bool
 */
function is_rrdtool_proxy_running() {
	exec('ps -ef | grep -v grep | grep -E "php .*rrdtool-proxy.php"', $output);

	return (__sizeof($output) >= 2) ? false : true;
}

/**
 * Checks (via `ps`) whether an rrdcached process is already running, unless
 * $force is set.
 *
 * @return bool
 */
function is_rrdcached_running() {
	global $force;

	exec('ps -ef | grep -v grep | grep -v "sh -c" | grep rrdcached', $output);

	return (__sizeof($output) >= 2 && !$force) ? false : true;
}
