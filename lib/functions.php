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

use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\Rijndael;
use phpseclib3\Crypt\RSA;

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

function rrdtool_pipe_close($process) {
	proc_close($process);
}

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

function encrypt($output, $rsa_key) {
	global $encryption;

	if (!$encryption) {
		return $output;
	}

	try {
		$public  = RSA::loadPublicKey($rsa_key);

		if (!$public instanceof phpseclib3\Crypt\RSA\PublicKey) {
			return false;
		}

		$aes     = new Rijndael('cbc');
		$aes_key = Random::string(32);

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

		if (!$private instanceof phpseclib3\Crypt\RSA\PrivateKey) {
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

function rrdp_path_is_absolute($path) {
	return str_starts_with($path, '/') || str_starts_with($path, '\\') || preg_match('/^[A-Za-z]:[\\\\\/]/', $path) === 1;
}

function rrdp_resolve_rra_path($path, $must_exist = true) {
	global $rrdp_config;

	return rrdp_resolve_path_within($rrdp_config['path_rra'], $path, $must_exist);
}

function rrdp_resolve_path_within($base_path, $path, $must_exist = true) {
	if (!is_string($path) || $path === '' || str_contains($path, "\0") || rrdp_path_is_absolute($path)) {
		return false;
	}

	$segments = preg_split('~[\\\\/]+~', $path);

	if ($segments === false || in_array('..', $segments, true)) {
		return false;
	}

	$base = realpath($base_path);

	if ($base === false) {
		return false;
	}

	$candidate = $base . DIRECTORY_SEPARATOR . ltrim($path, '/\\');
	$resolved  = realpath($candidate);

	if ($resolved === false && !$must_exist) {
		$ancestor = dirname($candidate);

		while (!file_exists($ancestor) && $ancestor !== dirname($ancestor)) {
			$ancestor = dirname($ancestor);
		}

		$resolved_ancestor = realpath($ancestor);

		if ($resolved_ancestor === false || !rrdp_path_is_within($resolved_ancestor, $base)) {
			return false;
		}

		return $candidate;
	}

	return $resolved !== false && rrdp_path_is_within($resolved, $base) ? $resolved : false;
}

function rrdp_path_is_within($path, $base) {
	return $path === $base || str_starts_with($path, $base . DIRECTORY_SEPARATOR);
}

function rrdp_command_has_unsafe_path($command) {
	return str_contains($command, "\0")
		|| str_contains($command, "\r")
		|| str_contains($command, "\n")
		|| preg_match('~(^|[[:space:]=:,\\\\/])\.\.([\\\\/]|$)~', $command)        === 1
		|| preg_match('~(^|[[:space:]=:,])(?:/|\\\\|[A-Za-z]:[\\\\/])~', $command) === 1;
}

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

function __logging($location, $msg, $category, $severity) {
	global $rrdp_config, $ipc_socket_parent, $ipc_global_resource_id, $c_pid;

	if (($location === LOGGING_LOCATION_BUFFERED && $rrdp_config['logging_severity_buffered'] && $severity <= $rrdp_config['logging_severity_buffered'])
		|| ($location === LOGGING_LOCATION_SNMP && $rrdp_config['logging_severity_snmp'] && $severity <= $rrdp_config['logging_severity_snmp'])
		|| ($rrdp_config['logging_severity_console'] && $severity <= $rrdp_config['logging_severity_console'] && ($rrdp_config['logging_category_console'] == 'all' || stripos($rrdp_config['logging_category_console'], $category) !== false))) {
		@socket_write($ipc_socket_parent, serialize(['type' => 'debug', 'status' => 'debugging', 'debug' => ['msg' => '#' . $ipc_global_resource_id . ' [' . $c_pid . '] ' . $msg, 'category' => $category, 'severity' => $severity, 'location' => $location ] ]) . "\r\n");
		usleep(10000);
	}
}

function __sizeof($array) {
	return ($array === false || !is_array($array)) ? 0 : sizeof($array);
}

function __count($array) {
	return ($array === false || !is_array($array)) ? 0 : count($array);
}

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

function is_rrdtool_proxy_running() {
	exec('ps -ef | grep -v grep | grep -E "php .*rrdtool-proxy.php"', $output);

	return (__sizeof($output) >= 2) ? false : true;
}

function is_rrdcached_running() {
	global $force;

	exec('ps -ef | grep -v grep | grep -v "sh -c" | grep rrdcached', $output);

	return (__sizeof($output) >= 2 && !$force) ? false : true;
}
