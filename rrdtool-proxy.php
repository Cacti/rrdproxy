<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2019 The Cacti Group                                 |
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

/* do NOT run this script through a web browser */
if (!isset($_SERVER["argv"][0]) || isset($_SERVER['REQUEST_METHOD']) || isset($_SERVER['REMOTE_ADDR'])) {
	die("<br><strong>This script is only meant to run at the command line.</strong>");
}

chdir(dirname(__FILE__));
require_once ('./include/global.php');
require_once ('./lib/functions.php');

/* process calling arguments */
$parms = $_SERVER["argv"];
array_shift($parms);

$microtime_start	= microtime(true);
$systemd			= false;
$wizard 			= false;
$force 				= false;

if (__sizeof($parms) != 0) {
	foreach ($parms as $parameter) {
		@list($arg, $value) = @explode("=", $parameter);

		switch ($arg) {
			case '-s' :
			case '-systemd' :
				$systemd = true;
				break;
			case '-w' :
			case '--wizard' :
				$wizard = true;
				break;
			case '--force' :
			case '-f' :
				$force = true;
				break;
			case '-v' :
			case '--version' :
				display_version();
				exit;
			case '-h' :
			case '--help' :
				display_help();
				exit ;
			default :
				print 'ERROR: Invalid Parameter ' . $parameter . "\n\n";
				display_help();
				exit ;
		}
	}
}

/* ---------------------------- SYSTEM SETUP ROUTINE -------------------------------------- */

if ( !file_exists('./include/config') ) {
	if( $wizard === true ) {
		/* unconfigured system */
		init_wizard();
	}elseif ( $systemd === true ) {
		rrd_system__system_die('Configuration file missing. Please run "rrdtool-proxy.php -w" to start the proxy wizard.');
	}
} else {
	include_once ('./include/config');
	if( empty($rrdp_config) || !array_key_exists('version', $rrdp_config) || version_compare($rrdp_config['version'], RRDP_VERSION, '<')) {
		/* invalid configuration or version upgrade */
		if( $systemd === true ) {
			rrd_system__system_die('Proxy has not been configured properly. Please re-run "rrdtool-proxy.php -w" to start the proxy wizard.');
		}
		init_wizard();
	}

	/* regular system start */
	define('SYSTEM_LOGGING', TRUE);
	if($systemd === false) {
		rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'Initiate system startup', 'SYS', SEVERITY_LEVEL_INFORMATIONAL);
		fwrite(STDOUT, "\e[8;50;80t");
		fwrite(STDOUT, ANSI_ERASE_SCREEN . ANSI_ERASE_BUFFER . ANSI_POS_TOP_LEFT . ANSI_BOLD . ANSI_YELLOW_FG . ANSI_BLUE_BG);
		fwrite(STDOUT, "   RRDtool Proxy Server Startup                                                 " . ANSI_RESET . "\r\n");
	}

	/* No Windows, please ;) */
	$support_os = strstr(PHP_OS, "WIN") ? false : true;
	rrd_system__system_boolean_message('test: operation system supported', $support_os, true);

	/* RRDtool Proxy has already been started ? */
	$not_running = is_rrdtool_proxy_running();
	rrd_system__system_boolean_message('test: no proxy instance running', $not_running, true, $force);

	/* RRDtool Cache Daemon has already been started ? */
	unset($output);
	$not_running = is_rrdcached_running();
	rrd_system__system_boolean_message('test: no cache instance running', $not_running, true);

	/* check state of required and optional php modules */
	rrd_system__system_boolean_message('test: php module \'sockets\'', extension_loaded('sockets'), true);
	rrd_system__system_boolean_message('test: php module \'posix\'', extension_loaded('posix'), true);
	rrd_system__system_boolean_message('test: php module \'pcntl\'', extension_loaded('pcntl'), true);
	rrd_system__system_boolean_message('test: php module \'gmp\'', extension_loaded('gmp'), true);
	rrd_system__system_boolean_message('test: php module \'openssl\'', extension_loaded('openssl'), true);
	rrd_system__system_boolean_message('test: php module \'zlib\'', extension_loaded('zlib'), true);

	exec("ulimit -n", $max_open_files);
	$pid_of_php = getmypid();
	exec("ls -l /proc/$pid_of_php/fd/ | wc -l", $open_files);
	if ($max_open_files[0] == 'unlimited')
		$max_open_files[0] = 1048576;

	rrd_system__system_boolean_message('test: max. number of open files [' . $max_open_files[0] . ']', $max_open_files[0], true);
	rrd_system__system_boolean_message('test: max. number of connections in backlog [' . SOMAXCONN . ']', SOMAXCONN, true);

}

/* ---------------------------- BEGIN - SYSTEM STARTUP ROUTINE -------------------------------------- */

/* fork the current process to initiate RRDproxy's master process */
$ppid = posix_getpid();
$pid = pcntl_fork();
if ($pid == -1) {
	/* oops ... something went wrong :/ */
	rrd_system__system_boolean_message('init: proxy master process', false, true);
	return false;
} elseif ($pid == 0) {
	/* the child should do nothing as long as the parent is still alive */
	$sid = posix_setsid();
	rrd_system__system_boolean_message('init: detach master process', $sid, true);
} else {
	/* kill the parent not before the child signals being up */
	$info = array();
	$rrdp_state = pcntl_sigwaitinfo(array(SIGUSR1, SIGTERM), $info);
	exit ;
}

/* load configuration and config arrays */
chdir(dirname(__FILE__));
require_once ('./include/global.php');
require_once ('./include/config');
@include_once ('./include/clients');
@include_once ('./include/proxies');

/* include external libraries */
set_include_path("./include/phpseclib/");
require_once ('Math/BigInteger.php');
require_once ('Crypt/Base.php');
require_once ('Crypt/Hash.php');
require_once ('Crypt/Random.php');
require_once ('Crypt/RSA.php');
require_once ('Crypt/Rijndael.php');

/* install signal handler */
pcntl_signal(SIGHUP, "rrdp_sig_handler");
pcntl_signal(SIGTERM, "rrdp_sig_handler");
pcntl_signal(SIGUSR1, "rrdp_sig_handler");
pcntl_signal(SIGUSR2, "rrdp_sig_handler");

/* setup running config */
rrdp_system__encryption_init();
$rrdp_config['path_base']      = dirname(__FILE__);
$rrdp_config['path_cli']       = $rrdp_config['path_base'] . '/cli';
$rrdp_config['path_include']   = $rrdp_config['path_base'] . '/include';
$rrdp_config['path_library']   = $rrdp_config['path_base'] . '/lib';

$rrdp_config['start']          = microtime(true);
$rrdp_config['last_sync']      = true;
$rrdp_config['remote_clients'] = isset($rrdp_remote_clients) ? $rrdp_remote_clients : array();
$rrdp_config['remote_proxies'] = isset($rrdp_remote_proxies) ? $rrdp_remote_proxies : array();
$rrdp_config['address']        = ($rrdp_config['ip_version'] == 4) ? $rrdp_config['address_4'] : $rrdp_config['address_6'];

/* configure socket server presets */
declare(ticks = 10);
ini_set("default_socket_timeout", "10");
ini_set("max_execution_time", "0");
ini_set("memory_limit", "1024M");
error_reporting(E_ALL ^ E_NOTICE);

$__server_listening = true;
$rrdp_msr_buffer = array();
$rrdp_buffers = array('logging_buffered' => array(), 'logging_snmp' => array() );

/* create a Service TCP Stream socket supporting IPv6 and 4 */
$rrdp_admin = @socket_create( ($rrdp_config['ip_version'] == 4) ? AF_INET : AF_INET6 , SOCK_STREAM, SOL_TCP);

/* define a socket for proxy administration */
if (!$rrdp_admin) {
	rrd_system__system_die("\r\n" . "Unable to create socket. Error: " . socket_strerror(socket_last_error()) . "\r\n");
}
@socket_set_option($rrdp_admin, SOL_SOCKET, SO_REUSEADDR, 1);
if (!@socket_bind($rrdp_admin, (($rrdp_config['ipv6']) ? '::1' : '127.0.0.1'), $rrdp_config['port_admin'])) {
	rrd_system__system_die("\r\n" . "Unable to bind socket to '" . $rrdp_config['address'] . ":" . $rrdp_config['port_admin'] . "'" . "\r\n" . "Error: " . socket_strerror(socket_last_error()) . "\r\n");
};
socket_set_nonblock($rrdp_admin);
socket_listen($rrdp_admin);
rrd_system__system_boolean_message('init: tcp admin socket', $rrdp_admin, true);
rrdp_system__logging(LOGGING_LOCATION_BUFFERED, "Start listening to port " . $rrdp_config['address'] . ":" . $rrdp_config['port_admin'], 'SYS', SEVERITY_LEVEL_NOTIFICATION);

/* set up a client socket request against RRDtool */
$rrdp_client = @socket_create( (($rrdp_config['ip_version'] == 4) ? AF_INET : AF_INET6 ), SOCK_STREAM, SOL_TCP);
if (!$rrdp_client) {
	rrd_system__system_die("\r\n" . "Unable to create socket. Error: " . socket_strerror(socket_last_error()) . "\r\n");
}
@socket_set_option($rrdp_client, SOL_SOCKET, SO_REUSEADDR, 1);
if (!@socket_bind($rrdp_client, $rrdp_config['address'], $rrdp_config['port_client'])) {
	rrd_system__system_die("\r\n" . "Unable to bind socket to '" . $rrdp_config['address'] . ":" . $rrdp_config['port_client'] . "'" . "\r\n" . "Error: " . socket_strerror(socket_last_error()) . "\r\n");
};
socket_set_nonblock($rrdp_client);

rrd_system__system_boolean_message('init: tcp client socket', $rrdp_client, true);

socket_listen($rrdp_client);
#TODO: This line needs to be removed once replicator is ready
rrdp_system__logging(LOGGING_LOCATION_BUFFERED, "Start listening to port " . $rrdp_config['address'] . ":" . $rrdp_config['port_client'], 'SYS', SEVERITY_LEVEL_NOTIFICATION);

$rrdp_clients = array();
$rrdp_ipc_sockets = array();
$rrdp_admin_sockets = array();
$rrdp_admin_clients = array();
$rrdp_ipc_server_sockets = array();

/* start RRDCached if configued */
if ($rrdp_config['path_rrdcached']) {

	$current_working_directory = realpath('');
	$rrdcached_cmd = $rrdp_config['path_rrdcached'] . ' -l unix:' . $current_working_directory . '/run/rrdcached.sock' . ' -w ' . $rrdp_config['rrdcache_update_cycle'] . ($rrdp_config['rrdcache_update_delay'] ? ' -z ' . $rrdp_config['rrdcache_update_delay'] : '') . ' -f ' . $rrdp_config['rrdcache_life_cycle'] . ' -p ' . $current_working_directory . '/run/rrdcached.pid' . ' -t ' . $rrdp_config['rrdcache_write_threads'] . ' -j ' . $current_working_directory . '/run/journal' . ' -B ' . $rrdp_config['path_rra'] . ' -O';

	rrdp_system__logging(LOGGING_LOCATION_BUFFERED, "Initiate RRDcached daemon system startup - " . $rrdcached_cmd, 'SYS', SEVERITY_LEVEL_INFORMATIONAL);
	$rrdcached = proc_open($rrdcached_cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);

	$stdout = stream_get_contents($pipes[1]);
	fclose($pipes[1]);
	$stderr = stream_get_contents($pipes[2]);
	fclose($pipes[2]);
	proc_close($rrdcached);

	/* Feedback from replicator required - let's wait for a sec */
	usleep(1000000);
	$rrdcached_pid = trim(file_get_contents($current_working_directory . '/run/rrdcached.pid'));
	rrd_system__system_boolean_message('init: rrdcached daemon [PID: ' . $rrdcached_pid . ']', $rrdcached_pid, false);

	if ($stderr)
		rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'ERROR: RRDcached daemon - ' . $stderr, 'SYS', SEVERITY_LEVEL_ALERT);
	if ($rrdcached_pid)
		rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'STATUS: RRDcached daemon [PID: ' . $rrdcached_pid . '] running.', 'SYS', SEVERITY_LEVEL_NOTIFICATION);
} else {
	$rrdcached_pid = 0;
}

/* start replication master */
#socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $ipc_sockets);
#list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
#$key = intval($ipc_socket_child);
#$rrdp_repl_master_pid = handle_child_processes($ipc_sockets, 1, false);
#$rrdp_clients[$rrdp_repl_master_pid]['ip'] = '127.0.0.1';
#$rrdp_clients[$rrdp_repl_master_pid]['ipc'] = $key;
#$rrdp_clients[$rrdp_repl_master_pid]['type'] = 'M';
#$rrdp_ipc_sockets[$key] = $ipc_sockets;

/* start replication slaves */
#foreach($rrdp_config['remote_proxies'] as $proxy_ip => $proxy_settings) {
#	socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $ipc_sockets);
#	list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
#	$key = intval($ipc_socket_child);
#	$rrdp_repl_slave_pid = handle_child_processes($ipc_sockets, 2, false, $proxy_ip);
#	$rrdp_clients[$rrdp_repl_slave_pid]['ip'] = '127.0.0.1';
#	$rrdp_clients[$rrdp_repl_slave_pid]['ipc'] = $key;
#	$rrdp_clients[$rrdp_repl_slave_pid]['type'] = 'S';
#	$rrdp_ipc_sockets[$key] = $ipc_sockets;
#}

/* Feedback from replicator required - let's wait for another sec */
usleep(1000000);

/* limit the number max. connections in relation to the number of open files this system supports */
exec("ulimit -n", $max_open_files);
$pid_of_php = getmypid();
exec("ls -l /proc/$pid_of_php/fd/ | wc -l", $open_files);
if ($max_open_files[0] == 'unlimited')
	$max_open_files[0] = 1048576;
$rrdp_config['max_cnn'] = intval(($max_open_files[0] - $open_files[0]) / 2 - $rrdp_config['max_admin_cnn'] * 2 - 100); #use a buffer of 100 open files

/* return system info */
fwrite(STDOUT, rrdp_cmd__show_version($systemd) . "\r\n");

/* signal the parent to exit - now we are up and ready */
@posix_kill($ppid, SIGUSR1);

/* create PID file for systemd */
if($systemd) {
	file_put_contents('./run/rrdtool-proxy.pid', posix_getpid());
}
/* ---------------------------- END - SYSTEM STARTUP ROUTINE ---------------------------- */

while ($__server_listening) {

	$write = array();
	$except = array();

	$tv_sec = 2;

	rrdp_msr__block_write();
	rrdp_system__check();

	/* setup clients listening to socket for reading */
	$read = array();

	/* do not listen to client connection requests as long as the system is not in state fully-synced */
	if ($rrdp_config['last_sync'] !== false) {
		$read[0] = $rrdp_client;
	}
	$read[1] = $rrdp_admin;

	/* and then check child processes */
	foreach ($rrdp_clients as $child_pid => $client) {
		$child_status = pcntl_waitpid($child_pid, $status, WNOHANG);
		if ($child_status == -1 || $child_status > 0) {
			rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'REMOVAL OF PID [' . $child_pid . ']', 'SYS', SEVERITY_LEVEL_NOTIFICATION);
			unset($rrdp_ipc_sockets[intval($rrdp_clients[$child_pid]['ipc'])]);
			unset($rrdp_clients[$child_pid]);
		} else {
			$key = $rrdp_clients[$child_pid]['ipc'];
			//rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'WAITING FOR ' . $child_pid, 'SYS', SEVERITY_LEVEL_ALERT);
			if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
				$read[] = $rrdp_ipc_sockets[$key][1];
			}
		}
	}

	/* all admin connections need to be monitored for changes, too */
	foreach ($rrdp_admin_clients as $rrdp_admin_client) {
		$read[] = $rrdp_admin_client['socket'];
	}

	$ready = @socket_select($read, $write, $except, $tv_sec);

	pcntl_signal_dispatch();

	if ($ready) {
		foreach ($read as $read_socket_index => $read_socket) {
			if ($read_socket == $rrdp_client) {
				/* a default client is trying to connect */
				if ($rrdp_config['max_cnn'] > __sizeof($rrdp_clients)) {
					$socket_descriptor = socket_accept($read_socket);
					socket_getpeername($socket_descriptor, $ip);
					/* verify authorization */
					if (array_key_exists($ip, $rrdp_config['remote_clients']) === true) {

						/* setup IPC */
						socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $ipc_sockets);
						list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
						$key = intval($ipc_socket_child);

						/* fork a child process for that connection */
						$pid = handle_child_processes($ipc_sockets, 3, $rrdp_client, $socket_descriptor);
						$rrdp_clients[$pid]['ip'] = $ip;
						$rrdp_clients[$pid]['ipc'] = $key;
						$rrdp_clients[$pid]['type'] = 'C';
						$rrdp_clients[$pid]['client_socket'] = $socket_descriptor;
						$rrdp_ipc_sockets[$key] = $ipc_sockets;

						rrdp_system__update('max_client_connections');
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, '#' . $key . ' Default connection request [IP: ' . $ip . '] granted.', 'ACL', SEVERITY_LEVEL_DEBUG);
					} else {
						@socket_write($socket_descriptor, "ERROR: Access denied.\r\n");
						@socket_close($socket_descriptor);
						rrdp_system__count('connections_refused');
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, '#' . $key . ' Default connection request [IP: ' . $ip . '] rejected.', 'ACL', SEVERITY_LEVEL_WARNING);
					}
				} else {
					rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'Critical: Maximum number of client connections has been exhausted. Check system setup ("ulimit -n")!', 'SYS', SEVERITY_LEVEL_ALERT);
					$socket_descriptor = socket_accept($read_socket);
					@socket_write($socket_descriptor, "ERROR: Too many open connections.\r\n");
					@socket_close($socket_descriptor);
				}
			} else if ($read_socket == $rrdp_admin) {

				/* check if this is a new service client is trying to connect */
				if ($rrdp_config['max_admin_cnn'] > __sizeof($rrdp_admin_clients)) {

					$socket_descriptor = socket_accept($read_socket);

					/* check if the new client has the permission to connect */
					socket_getpeername($socket_descriptor, $ip);

					/* take care of IPv6, IPv4 and embedded IPv4 addresses */
					if (in_array($ip, array('127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1'))) {
						if (!in_array($socket_descriptor, $rrdp_admin_sockets)) {
							$key = intval($socket_descriptor);
							$rrdp_admin_sockets[$key] = $socket_descriptor;
							$rrdp_admin_clients[$key] = array('socket' => $socket_descriptor, 'ip' => $ip, 'privileged' => false, 'logging_severity_console' => $rrdp_config['logging_severity_terminal'], 'logging_category_console' => $rrdp_config['logging_category_terminal'], 'debug' => false, 'type' => 'srv');

							socket_write($socket_descriptor, rrdp_get_cacti_proxy_logo() . "\r\n\r\n");
							socket_Write($socket_descriptor, RRDP_VERSION_FULL);
							socket_write($socket_descriptor, ANSI_RESET . ANSI_GREEN_FG . $rrdp_config['name'] . ">" . ANSI_RESET . " ");

							rrdp_system__update('max_admin_connections');
							rrdp_system__logging(LOGGING_LOCATION_BUFFERED, '#' . $key . ' Service connection request [IP: ' . $ip . '] granted.', 'ACL', SEVERITY_LEVEL_DEBUG);
						}

					} elseif ($ip == $rrdp_config['slave']) {
						$key = intval($socket_descriptor);
						$rrdp_admin_sockets[$key] = $socket_descriptor;
						$rrdp_admin_clients[$key] = array('socket' => $socket_descriptor, 'ip' => $ip, 'privileged' => false, 'debug' => false, 'type' => 'msr');
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, '#' . $key . ' RRDtool-Proxy slave connection request [IP: ' . $ip . '] granted.', 'ACL', SEVERITY_LEVEL_INFORMATIONAL);
					} else {
						@socket_write($socket_descriptor, "ERROR: Access denied.\r\n");
						@socket_close($socket_descriptor);
						rrdp_system__count('connections_refused');
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, '#' . $key . ' Service connection request [IP: ' . $ip . '] rejected.', 'ACL', SEVERITY_LEVEL_WARNING);
						break;
					}
				} else {
					/* 	we are out of resources - keep these clients in our backlog -
					 !!! Vulnerability !!! How to avoid a denial of service?
					 */
				}
			} else if (intval($read_socket) == $rrdp_clients[$rrdp_replicator_pid]['ipc']) {

				/* === REPLICATOR IPC message === */
				$input = '';

				/* handle IPC with the replicator separately */
				while (1) {
					$recv = socket_read($read_socket, 100000, PHP_BINARY_READ);
					if ($recv === false) {
						/* replicator connection timeout  */
						rrdp_system__count('connections_timeout');
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'IPC connection timeout to REPLICATOR detected.', 'IPC', SEVERITY_LEVEL_CRITICAL);
						/* close IPC child socket */

						break;
					} else if ($recv == '') {
						/* session closed by replicator */
						if ($input) {
							rrdp_system__replicator($input);
							rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'IPC connection closed by REPLICATOR', 'IPC', SEVERITY_LEVEL_WARNING);
						}
						break;
					} else {
						$input .= $recv;
						if (substr($input, -1) == "\n") {
							rrdp_system__replicator($input);
							continue 2;
						} else {
							continue;
						}
					}
				}

			} else {

				/* handle established connections */
				$index = intval($read_socket);
				if (isset($rrdp_ipc_sockets[$index])) {
					/* === CLIENT IPC message === */
					$input = '';
					while (1) {
						$recv = socket_read($read_socket, 100000, PHP_BINARY_READ);
						if ($recv === false) {
							/* timeout  */
							rrdp_system__count('connections_timeout');
							rrdp_system__logging(LOGGING_LOCATION_BUFFERED, '#' . $index . ' IPC connection timeout detected.', 'IPC', SEVERITY_LEVEL_CRITICAL);
							/* close IPC child socket */
							break;
						} else if ($recv == '') {
							/* session closed by child process */
							if ($input) {
								rrdp_system__client($input);
								rrdp_system__logging(LOGGING_LOCATION_BUFFERED, '#' . $index . ' IPC connection closed by child process', 'IPC', SEVERITY_LEVEL_DEBUG);
							}
							@socket_close($read_socket);
							break;
						} else {
							$input .= $recv;
							if (substr($input, -1) == "\n") {
								rrdp_system__client($input);
								continue 2;
							} else {
								continue;
							}
						}
					}
					unset($rrdp_ipc_sockets[$index]);
					continue;

				} else if (isset($rrdp_admin_sockets[$index])) {

					/* === this is a service connection - means default or master-slave === */
					$i = intval($read_socket);

					$recv = @socket_read($read_socket, 100000, PHP_BINARY_READ);
					rrdp_system__count('srv_bytes_received', rrdp_system__calc_bytes($recv));

					if ($recv === false) {
						/* connection lost :( */
						socket_shutdown($read_socket);
						socket_close($read_socket);
						rrdp_system__count('srv_connection_broken');
						unset($rrdp_admin_clients[$index]);
						continue;
					} else if ($recv == "\n") {
						/* end of transmission */
					} else if ($recv) {

						if (isset($options))
							unset($options);
						$recv = trim($recv);

						if (strpos($recv, " ") !== false) {
							/* correct multiple blanks in sequence automatically as well as tabs */
							$recv = preg_replace("/[[:blank:]]+/", " ", $recv);
							$recv = str_replace("\t", '', $recv);
							$options = explode(" ", $recv, 2);
							$cmd = $options[0];
							$cmd_options = explode(" ", $options[1]);
						} else {
							$cmd = $recv;
							$cmd_options = array();
						}

						/* this is a standard service client */
						if ($cmd) {

							rrdp_system__count('queries_system');
							$root = $rrdp_help_messages["?"][(($rrdp_admin_clients[$index]['privileged']) ? 1 : 0)];

							if (isset($rrdp_aliases[$cmd])) {
								/* replace aliases */
								$cmd = $rrdp_aliases[$cmd];
							}else {
								/* try auto-completion if necessary */
								if(!isset($root[$cmd]) && strlen($cmd)>=2) {
									$found = false;
									foreach($root as $root_key => $root_value ){
										if( strpos($root_key, $cmd) === 0) {
											if($found === false) {
												$found = $root_key;
											}else {
												/* two or more candidates available */
												rrdp_system__socket_write($read_socket, "% Unspecific command \"$cmd\" - use \"?\" for a list of valid commands.\r\n");
												rrdp_system__return_prompt($read_socket);
												continue 2;
											}
										}
									}
									$cmd = ($found === false ) ? $cmd : $found;
								}
							}

							if($cmd != 'list') {

								/* verify if permissions are ok before going on*/
								if( !isset($root[$cmd] )) {
									rrdp_system__socket_write($read_socket, "% Unrecognized command\r\n");
									rrdp_system__return_prompt($read_socket);
									continue;
								}

								if(is_array($cmd_options)) {

									$root = $root[$cmd];
									/* Use auto-completion for parameters if possible */
									foreach ($cmd_options as $cmd_option_index => $cmd_option_value) {
										if($cmd_option_value == '?') {
											if(isset($root['?'])) {
												rrdp_cmd__list($read_socket, array_slice( $cmd_options, $cmd_option_index+1), $root );
											}else {
												rrdp_system__socket_write($read_socket, ' | Output modifiers' . "\r\n");
											}
											rrdp_system__return_prompt($read_socket);
											break 2;
										}elseif (isset($root['?'])) {

											if(strlen($cmd_option_value) >= 2) {
												$found = false;
												foreach($root['?'] as $root_key => $root_value ){
													if( strpos($root_key, $cmd_option_value) === 0) {
														if($found === false) {
															$found = $root_key;
														}else {
															/* two or more candidates available */
															rrdp_system__socket_write($read_socket, "% Unspecific argument \"$cmd_option_value\" - use \"?\" for a list of valid commands.\r\n");
															continue 2;
														}
													}
												}

												if($found) {
													$cmd_options[$cmd_option_index] = $found;
													$root = $root['?'][$found];
													continue;
												}

											}else {
												if (isset($root['?'][$cmd_option_value])) {
													$root = $root['?'][$cmd_option_value];
													continue;
												}
											}
										}else {
											/* output filter flags */
										}
									}
								}
							}

							if (function_exists('rrdp_cmd__' . $cmd) ) {
								/* valid main function call */
								$rrdp_function = 'rrdp_cmd__' . $cmd;
								$rrdp_function($read_socket, $cmd_options);
							}else {
								/* unknown command */
								rrdp_system__socket_write($read_socket, "% Unrecognized command\r\n");
							}

						}
						/* return prompt */
						rrdp_system__return_prompt($read_socket);

					} else {
						/* look for error messages */
						$errorcode = socket_last_error();
						socket_close($rrdp_admin_client['socket']);
						unset($rrdp_admin_clients[$index]);
						rrdp_system__count('aborted_clients');
						continue;
					}
				}
			}
		}
	} else {
		continue;
	}
}

/* ####################################   MSR FUNCTIONS   #################################### */

function rrdp_msr__block_write() {
	global $rrdp_config, $rrdp_msr_buffer;

	$current_time = time();
	$current_timeframe = $current_time + $current_time % 10;

	if (__sizeof($rrdp_config['remote_proxies']) > 0) {
		if (__sizeof($rrdp_msr_buffer) > 0) {
			foreach ($rrdp_msr_buffer as $timeframe => $msr_commands) {
				if ($timeframe < $current_timeframe) {

					$buffer = '';
					foreach ($msr_commands as $id => $cmd) {
						$buffer .= $id . "\t" . $cmd . "\r\n";
					}
					//$buffer = gzencode($buffer,1);

					foreach ($rrdp_config['remote_proxies'] as $ip => $fingerprint) {
						$msr_sub_folder = './msr/' . $ip;
						if (!is_dir($msr_sub_folder))
							mkdir($msr_sub_folder);
						$fp = fopen($msr_sub_folder . '/' . $timeframe, 'a');
						fwrite($fp, $buffer);
					}
					unset($rrdp_msr_buffer[$timeframe]);
				}
			}
		}
	} else {
		/* clear msr buffer */
		$rrdp_msr_buffer = array();
	}
	return;
}

/* ####################################   INTERNAL FUNCTIONS   #################################### */

function rrdp_system__check() {
	global $rrdp_config, $rrdp_status;

	$current_time = time();
	$first_run = false;

	if (!isset($rrdp_config['last_system_check'])) {
		$rrdp_config['last_system_check'] = $current_time;
		$first_run = true;
	}

	if ($first_run || $rrdp_config['last_system_check'] < ($current_time - 30)) {

		/* Status - Filesystem RRA */
		if (is_dir($rrdp_config['path_rra'])) {

			$rra_disk_status = shell_exec("df --block-size=1048576 " . $rrdp_config['path_rra'] . " | sed 1d | awk '{printf \"size:\" $2 \" used:\" $3 \" avail:\" $4}'");
			$disk_states = explode(' ', $rra_disk_status);
			if (is_array($disk_states) && __sizeof($disk_states) > 0) {
				foreach ($disk_states as $disk_state) {
					list($type, $value) = explode(':', $disk_state);
					if (isset($rrdp_status['rra_disk_' . $type])) {
						$rrdp_status['rra_disk_' . $type] = $value;
					}
				}

				if( $rrdp_status['rra_disk_size'] && $rrdp_status['rra_disk_avail'] ) {
					$ratio = $rrdp_status['rra_disk_avail']/$rrdp_status['rra_disk_size'];
					if( $ratio <= 0.1 ) {
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'RRA disk usage threshold of 90% with '. intval($ratio*100) . '% exceeded', 'SYS', SEVERITY_LEVEL_CRITICAL);
						#TODO - SNMPTrap
					}elseif ($ratio <= 0.15 ) {
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'RRA disk usage threshold of 85% with '. intval($ratio*100) . '% exceeded', 'SYS', SEVERITY_LEVEL_ALERT);
						#TODO - SNMPTrap
					}elseif ($ratio <= 0.25 ) {
						rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'RRA disk usage threshold of 75% with '. intval($ratio*100) . '% exceeded', 'SYS', SEVERITY_LEVEL_WARNING);
						#TODO - SNMPTrap
					}
				}
			}
		}

		/* Status - Filesystem MSR */
		$msr_disk_status = shell_exec("df --block-size=1048576 ./msr | sed 1d | awk '{printf \"size:\" $2 \" used:\" $3 \" avail:\" $4}'");
		$disk_states = explode(' ', $msr_disk_status);
		if (is_array($disk_states) && __sizeof($disk_states) > 0) {
			foreach ($disk_states as $disk_state) {
				list($type, $value) = explode(':', $disk_state);
				if (isset($rrdp_status['msr_disk_' . $type])) {
					$rrdp_status['msr_disk_' . $type] = $value;
				}
			}
		}

		if( $rrdp_status['msr_disk_size'] && $rrdp_status['msr_disk_avail'] ) {
			$ratio = $rrdp_status['msr_disk_avail']/$rrdp_status['msr_disk_size'];
			if( $ratio <= 0.1 ) {
				rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'MSR disk usage threshold of 90% with '. intval($ratio*100) . '% exceeded', 'SYS', SEVERITY_LEVEL_CRITICAL);
				#TODO - SNMPTrap
			}elseif ($ratio <= 0.15 ) {
				rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'MSR disk usage threshold of 85% with '. intval($ratio*100) . '% exceeded', 'SYS', SEVERITY_LEVEL_ALERT);
				#TODO - SNMPTrap
			}elseif ($ratio <= 0.25 ) {
				rrdp_system__logging(LOGGING_LOCATION_BUFFERED, 'MSR disk usage threshold of 75% with '. intval($ratio*100) . '% exceeded', 'SYS', SEVERITY_LEVEL_WARNING);
				#TODO - SNMPTrap
			}
		}

		$rrdp_config['last_system_check'] = $current_time;
	}
	return;
}

function rrdp_system__encryption_init() {
	global $rrdp_config;

	$rsa = new \phpseclib\Crypt\RSA();

	if (!file_exists('./include/public.key') || !file_exists('./include/private.key')) {
		$keys = $rsa -> createKey(2048);
		$rrdp_config['encryption']['public_key'] = $keys['publickey'];
		$rrdp_config['encryption']['private_key'] = $keys['privatekey'];

		file_put_contents('./include/public.key', $rrdp_config['encryption']['public_key']);
		file_put_contents('./include/private.key', $rrdp_config['encryption']['private_key']);
	}
	$rrdp_config['encryption']['public_key'] = file_get_contents('./include/public.key');
	rrd_system__system_boolean_message('init: RSA public key', $rrdp_config['encryption']['public_key'], true);

	$rrdp_config['encryption']['private_key'] = file_get_contents('./include/private.key');
	rrd_system__system_boolean_message('init: RSA private key', $rrdp_config['encryption']['private_key'], true);

	$rsa -> loadKey($rrdp_config['encryption']['public_key']);
	$rrdp_config['encryption']['public_key_fingerprint'] = $rsa -> getPublicKeyFingerprint();
}

function rrdp_system__replicator(&$input) {
	global $rrdp_client, $rrd_config;

	$status = @unserialize($input);

	if ($status !== false && $status['type']) {

		switch($status['type']) {
			case 'debug' :
				rrdp_system__logging($status['debug']['location'], $status['debug']['msg'], $status['debug']['category'], $status['debug']['severity']);
				break;
			case 'status' :
				if ($status['status'] == 'running') {
					@socket_listen($rrdp_client);
				} elseif ($status['status'] == 'synchronizing') {
					@socket_shutdown($rrdp_client);
				}
				break;
			default :
				#TODO undefined state
				break;
		}
	} else {
		/* internal IPC error */
		#TODO
	}
}

function rrdp_system__client(&$input) {

	global $rrdp_msr_buffer;

	$status = @unserialize($input);

	if ($status !== false && $status['type']) {

		if($status['type'] == 'debug') {
			rrdp_system__logging($status['debug']['location'], $status['debug']['msg'], $status['debug']['category'], $status['debug']['severity']);
		}

		if(isset($status['msr_commands'])) {
			foreach ($status['msr_commands'] as $timeframe => $msr_commands) {
				if (!isset($rrdp_msr_buffer[$timeframe])) {
					$rrdp_msr_buffer[$timeframe] = array();
				}
				$rrdp_msr_buffer[$timeframe] += $msr_commands;
			}
		}

		foreach ($status as $status_variable => $status_value) {
			rrdp_system__count($status_variable, $status_value);
		}

		switch($status['status']) {
			case 'CLOSEDOWN_BY_SIGNAL' :
			case 'CLOSEDOWN_BY_TIMEOUT' :
			case 'CLOSEDOWN_BY_VIOLATION' :
			case 'CLOSEDOWN_BY_CLIENT_CMD' :
			case 'CLOSEDOWN_BY_CLIENT_DROP' :
			case 'CLOSEDOWN_BY_CLIENT_AUTH' :
			case 'CLOSEDOWN_BY_ENCRYPTION' :
				rrdp_system__count('proc_' . strtolower($status['status']));
				break;
			default :
				/* process is still running */
				break;
		}
	}
}

function rrd_system__system_die($msg = '') {
	global $ppid;

	if (!trim($msg))
		rrdp_system__logging(LOGGING_LOCATION_BUFFERED, $msg, 'SYS', SEVERITY_LEVEL_EMERGENCY);

	if ($ppid)
		@posix_kill($ppid, SIGTERM);
	die($msg);
}

function rrd_system__system_boolean_message($msg, $boolean_state, $exit = false, $skip = false) {
	global $colors, $microtime_start, $systemd;

	$microtime_end = microtime(true);
	$color = $skip ? $colors['warning'] : ($boolean_state ? $colors['normal'] : (($exit == true) ? $colors['error'] : $colors['warning']));
	$status = $skip ? '[SKIPPED]' : ($boolean_state ? '[OK]' : '[FAILED]');

	$max_msg_length = 80 - 10 - strlen($status) - 1;

	if (strlen($msg) > $max_msg_length)
		$msg = substr($msg, 0, $max_msg_length - 3) . '...';

	if($systemd === false) {
		fwrite(STDOUT, sprintf("\r\n[%.5f] %-{$max_msg_length}s " . ANSI_RESET . "{$color}%s" . ANSI_RESET, ($microtime_end - $microtime_start), $msg, $status));
	}

	if ($skip == false && $boolean_state == false && $exit == true ) {
		rrdp_system__logging(LOGGING_LOCATION_BUFFERED, $msg, 'SYS', SEVERITY_LEVEL_CRITICAL);
		if($systemd === true) {
			fwrite(STDOUT, sprintf("\r\n[%.5f] %-{$max_msg_length}s " . ANSI_RESET . "{$color}%s" . ANSI_RESET, ($microtime_end - $microtime_start), $msg, $status));
		}
		rrd_system__system_die("\r\n");
	}else {
		rrdp_system__logging(LOGGING_LOCATION_BUFFERED, $status . ' ' . $msg, 'SYS', SEVERITY_LEVEL_INFORMATIONAL);
	}
}

function rrd_system__system_message($microtime_start, $msg, $level = 'normal', $exit = false) {
	global $colors;

	$microtime_end = microtime(true);
	fwrite(STDOUT, sprintf("\r\n[%.5f] " . ANSI_RESET . "{$colors[$level]}%s" . ANSI_RESET, ($microtime_end - $microtime_start), $msg));
	if ($exit)
		die("\r\n");
}

function rrd_system__progressbar( $current, $max ) {
	global $process_start;

	if(empty($process_start)) $process_start = time();
	$progress = round( $current / ( $max / 100 ), 2);
	$progress_points = floor(40*$progress/100);
	$timediff = time() - $process_start;
	$estimated = ceil( ( ( 100 / $progress *  $timediff ) - $timediff ) );

	$hours   = floor($estimated / 3600);
	$minutes = floor(($estimated - $hours * 3600) / 60);
	$seconds = floor($estimated - $hours * 3600 - $minutes * 60);

	fwrite(STDOUT, "\0338");
	fwrite(STDOUT, str_pad( "[" . ANSI_RESET . ANSI_GREEN_FG . str_repeat( "#", $progress_points ), 48, " ", STR_PAD_RIGHT) . ANSI_RESET . "] " . sprintf( "%6.2f", $progress ) . str_pad( "% ( ". sprintf( "%02dh %02dm %02ds", $hours, $minutes, $seconds ) . " left )", 20, " ", STR_PAD_RIGHT) );
	if ($current == $max) {
		unset($process_start);
		print "\r\n";
	}
}

function rrd_system__read_config_option($param = false) {
	global $rrdp_config;
	if ($param && array_key_exists($param, $rrdp_config)) {
		return $rrdp_config[$param];
	} else {
		return false;
	}
}

function rrdp_system__calc_bytes(&$str) {
	return (ini_get('mbstring.func_overload') ? mb_strlen($str, '8bit') : strlen($str));
}

function rrdp_system__count($variable, $value = 1) {
	global $rrdp_status;
	if (isset($rrdp_status[$variable])) {
		/* use 32 bit counters only */
		$rrdp_status[$variable] = (($rrdp_status[$variable] + $value) >= 2147483647) ? $rrdp_status[$variable] - 2147483647 + $value : $rrdp_status[$variable] + $value;
		return;
	}
	return false;
}

function rrdp_system__update($variable) {
	global $rrdp_admin_clients, $rrdp_clients, $rrdp_status;
	switch($variable) {
		case 'max_admin_connections' :
			if (__sizeof($rrdp_admin_clients) > $rrdp_status[$variable]) {
				$rrdp_status[$variable] = __sizeof($rrdp_admin_clients);
			}
			break;
		case 'max_client_connections' :
			if (__sizeof($rrdp_clients) > $rrdp_status[$variable]) {
				$rrdp_status[$variable] = __sizeof($rrdp_clients);
			}
			break;
	}
	return;
};

function rrdp_system__debug($msg, $category, $severity, $environment = 'proxy') {
	global $rrdp_config, $rrdp_admin_clients, $rrdp_admin_sockets, $colors, $severity_levels;

#TODO


	if (isset($rrdp_config['debug'][$environment]) && $rrdp_config['debug'][$environment] === true) {
		foreach ($rrdp_admin_clients as $key => $rrdp_admin_client) {
			if (isset($rrdp_admin_client['debug'][$environment]) && $rrdp_admin_client['debug'][$environment] === true) {
				/* write debug message to socket and return default prompt for proviledge mode */
				rrdp_system__socket_write($rrdp_admin_sockets[$key], "\r\n" . ANSI_RESET . "{$colors[$severity_levels[$severity]]}[" . $category . "] " . $msg);
			}
		}
	}
}

function rrdp_system__return_prompt($socket) {
	global $rrdp_admin_clients, $rrdp_config, $colors;

	$i = intval($socket);

	$prompt = ANSI_RESET . (($rrdp_admin_clients[$i]['debug']) ? $colors['debug'] : $colors['prompt']) . $rrdp_config['name'] . (($rrdp_admin_clients[$i]['privileged']) ? '#' : '>') . ANSI_RESET . " ";
	rrdp_system__socket_write($socket, $prompt);
}

function rrdp_system__socket_write($socket, $output, $counter = '') {
	if ($return = @socket_write($socket, $output, strlen($output))) {
		if($counter) {
			rrdp_system__count($counter, rrdp_system__calc_bytes($output));
		}
	}
	return $return;
}

function rrdp_system__socket_close($socket, $msg = false, $force = false) {

	if ($msg) {
		rrdp_system__socket_write($socket, $msg);
	}

	if ($force) {
		$return = @socket_close($socket);
	} else {
		@socket_shutdown($socket, 2);
		$return = @socket_close($socket);
	}
	return $return;
}

function rrdp_system__status_live($variable) {
	global $rrdp_admin_clients, $rrdp_ipc_sockets, $rrdp_config;

	$status = 'n/a';
	switch($variable) {
		case 'threads_connected' :
			$status = __sizeof($rrdp_admin_clients);
			break;
		case 'uptime' :
			$status = microtime(true) - $rrdp_config['start'];
			break;
		case 'memory_usage' :
			$status = memory_get_usage();
			break;
		case 'memory_peak_usage' :
			$status = memory_get_peak_usage();
			break;
		case 'connections_open' :
			$status = __sizeof($rrdp_ipc_sockets);
			break;
	}
	return $status;
}

function rrdp_system__convert2bytes($val) {

	$val = trim($val);
	$last = strtolower($val[strlen($val) - 1]);
	switch($last) {
		case 'g' :
			$val *= 1024;
		case 'm' :
			$val *= 1024;
		case 'k' :
			$val *= 1024;
	}
	return $val;
}

function rrdp_system__errorlog($msg, $severity=SEVERITY_LEVEL_NOTIFICATION) {
	global $severity_levels;

	if(SYSTEM_LOGGING && array_key_exists($severity, $severity_levels))
		@file_put_contents('./log/rrdp.' . date("mdY") . '.log', '['.date(DATE_RFC822).'] [' . $severity_levels[$severity] . '] ' . trim($msg) . "\r\n", FILE_APPEND);
	return;
}

function rrdp_system__logging($location, $msg, $category, $severity) {
	global $rrdp_config, $rrdp_admin_clients, $rrdp_admin_sockets, $colors, $rrdp_buffers, $severity_levels;

	if(SYSTEM_LOGGING) {
		/* keep an eye on the number of rows we are allowed to keep in memory */

		if ($severity < SEVERITY_LEVEL_DEBUG) {
			if ($location === LOGGING_LOCATION_BUFFERED && $rrdp_config['logging_severity_buffered'] && $severity <= $rrdp_config['logging_severity_buffered']) {
				if (!isset($rrdp_buffers['logging_buffered'])) {
					$rrdp_buffers['logging_buffered'] = array();
				}

				if (__count($rrdp_buffers['logging_buffered']) == $rrdp_config['logging_size_buffered']) {
					$drop = array_shift($rrdp_buffers['logging_buffered']);
					unset($drop);
				}
				$rrdp_buffers['logging_buffered'][] = '['.date(DATE_RFC822).'] [' . $severity_levels[$severity] . '] [' . $category . '] ' . trim($msg);
			}else if ($location === LOGGING_LOCATION_SNMP && $rrdp_config[logging_severity_snmp] && $severity <= $rrdp_config[logging_severity_snmp]) {
				if (!isset($rrdp_buffers['logging_snmp'])) {
					$rrdp_buffers['logging_snmp'] = array();
				}

				if (__count($rrdp_buffers['logging_snmp']) == $rrdp_config['logging_size_snmp']) {
					$drop = array_shift($rrdp_buffers['logging_snmp']);
					unset($drop);
				}
				$rrdp_buffers['logging_snmp'][] = '['.date(DATE_RFC822).'] [' . $severity_levels[$severity] . '] [' . $category . '] ' . trim($msg);
			}
		}

		if (__count($rrdp_admin_clients)>0 && $rrdp_config['logging_severity_console']>0) {
			foreach ($rrdp_admin_clients as $key => $rrdp_admin_client) {
				#if ( $rrdp_admin_clients[$key]['logging_severity_console'] && $severity <= $rrdp_admin_clients[$key]['logging_severity_console'] ) {
				#	if($rrdp_admin_clients[$key]['logging_category_console'] == 'all' || stripos($rrdp_admin_clients[$key]['logging_category_console'], $category) !== false) {
				/* write debug message to socket and return default prompt for proviledge mode */
				rrdp_system__socket_write($rrdp_admin_sockets[$key], "\r\n" . ANSI_RESET . "{$colors[$severity_levels[$severity]]}[" . $category . "] " . $msg);
				#	}
				#}
			}
		}
	}
	return;
}

function rrdp_system__filter($output, $args) {

	if(!$output || !$args) return $output;

	$return = "% Unrecognized arguments: '" . implode(' ', $args) . "'\r\n";

	if(__count($args) >= 3 && $args[0] == '|' && in_array($args[1], array('i','e','b', 'I', 'E', 'B', 'exp') ) ) {

		$args[2] = trim(implode(' ', array_slice($args, 2)), '"\'');
		$output_rows = explode("\r\n", $output);

		if(!is_array($output_rows)) return;
		$total_matches = 0;
		$output = '';
		foreach($output_rows as $row_id => $row_value) {
			if($args[1] == 'i' && stripos($row_value, $args[2]) !== false) {
				$output .= $row_value . "\r\n";
				$total_matches++;
			}else if($args[1] == 'e' && stripos($row_value, $args[2]) === false) {
				$output .= $row_value . "\r\n";
				$total_matches++;
			}else if($args[1] == 'b' && stripos($row_value, $args[2]) !== false) {
				$output = implode("\r\n", array_slice( $output_rows, $row_id) );
				$total_matches++;
				break;
			}else if($args[1] == 'I' && strpos($row_value, $args[2]) !== false) {
				$output .= $row_value . "\r\n";
				$total_matches++;
			}else if($args[1] == 'E' && strpos($row_value, $args[2]) === false) {
				$output .= $row_value . "\r\n";
				$total_matches++;
			}else if($args[1] == 'B' && strpos($row_value, $args[2]) !== false) {
				$output = implode("\r\n", array_slice( $output_rows, $row_id) );
				$total_matches++;
				break;
			}else if($args[1] == 'exp' ) {
				$match = @preg_match($args[2], $row_value);

				if($match === FALSE) {
					return "% Invalid regular expression '" . $args[2] . "'\r\n";
				}else if( $match === 1) {
					$output .= $row_value . "\r\n";
					$total_matches++;
				}
			}
		}
		$output .= "\r\n" . "Matches: " . $total_matches . "\r\n";
		return $output;
	}

	return $return;
}

function rrdp_system__global_console_logging_update() {
	global $rrdp_config, $rrdp_admin_clients, $rrdp_clients, $rrdp_ipc_sockets, $rrdp_repl_master_pid, $rrdp_repl_slave_pid;


	/* represent the highest global console logging level being active */
	$logging_severity_console = $rrdp_config['logging_severity_terminal'];
	foreach($rrdp_admin_clients as $rrdp_admin_clients_settings) {
		if($rrdp_admin_clients_settings['privileged'] === true && $rrdp_admin_clients_settings['logging_severity_console'] > $logging_severity_console) {
			$logging_severity_console = $rrdp_admin_clients_settings['logging_severity_console'];
		}
	}
	$rrdp_config['logging_severity_console'] = $logging_severity_console;

	/* represent the summary of global console logging categories being activated */
	$logging_category_console = $rrdp_config['logging_category_console'];
	$selected_categories = array();
	foreach($rrdp_admin_clients as $rrdp_admin_clients_settings) {
		if($rrdp_admin_clients_settings['privileged'] === true) {
			if($rrdp_admin_clients_settings['logging_category_console'] == 'all') {
				$logging_category_console = 'all';
				$selected_categories = false;
				break;
			}else {
				$categories = explode(',', $rrdp_admin_clients_settings['logging_category_console']);
				if(__count($categories)>0) {
					foreach($categories as $category) {
						$selected_categories[$category] = $category;
					}
				}
			}
		}
	}

	if(__count($selected_categories)>0) {
		if(__count($selected_categories)>1 && in_array('none', $selected_categories)) {
			unset($selected_categories['none']);
		}
		$logging_category_console = implode(',', $selected_categories);
	}
	$rrdp_config['logging_category_console'] = $logging_category_console;

	/* replication master and slave processes */
	if ($rrdp_repl_master_pid) {
		$key = $rrdp_clients[$rrdp_repl_master_pid]['ipc'];
		if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
			@socket_write($rrdp_ipc_sockets[$key][1], serialize( array('type' => 'reload_running_config', 'rrdp_config' => $rrdp_config)) . "\r\n");
		}
	}
	if ($rrdp_repl_slave_pid) {
		$key = $rrdp_clients[$rrdp_repl_slave_pid]['ipc'];
		if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
			@socket_write($rrdp_ipc_sockets[$key][1], serialize( array('type' => 'reload_running_config', 'rrdp_config' => $rrdp_config)) . "\r\n");
		}
	}
	return;
}

/* ####################################   SYSTEM COMMANDS   #################################### */

function rrdp_cmd__clear($socket, $args) {
	$arg = array_shift($args);
	if ( !is_null($arg) ) {
		$rrdp_function = 'rrdp_cmd__clear_' . $arg;
		if (function_exists($rrdp_function)) {
			$rrdp_function($socket, $args);
			return;
		}
	}
	rrdp_system__socket_write($socket, '% Incomplete command. Type "clear ?" for a list of subcommands' . "\r\n");
}

function rrdp_cmd__clear_counters($socket) {
	global $rrdp_admin_clients, $rrdp_status;
	/* only privileged users are allowed to shut down the proxy from remote */
	foreach ($rrdp_status as $variable => $value) {
		if ($value !== 'live') {
			$rrdp_status[$variable] = 0;
		}
	}
	rrdp_system__logging(LOGGING_LOCATION_BUFFERED, "Counters have been cleared", 'SYS', SEVERITY_LEVEL_NOTIFICATION);
	return;
}

function rrdp_cmd__clear_logging($socket, $args) {
	global $rrdp_config, $rrdp_buffers;

	$arg = array_shift($args);
	if ( !is_null($arg) ) {
		switch($arg) {
			case 'buffered':
				$rrdp_buffers['logging_buffered'] = array();
				rrdp_system__logging(LOGGING_LOCATION_BUFFERED, "Logging buffer has been cleared", 'SYS', SEVERITY_LEVEL_NOTIFICATION);
				break;

			case 'snmp':
				$rrdp_buffers['logging_snmp'] = array();
				rrdp_system__logging(LOGGING_LOCATION_BUFFERED, "Logging SNMP has been cleared", 'SYS', SEVERITY_LEVEL_NOTIFICATION);
				break;

			default :
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
				break;
		}
	} else {
		rrdp_system__socket_write($socket, '% Type "clear logging ?" for a list of subcommands' . "\r\n");
	}
	return;
}

function rrdp_cmd__reset($socket, $args) {
	/* client would like to regularly clear and reset terminal screen */
	rrdp_system__socket_write($socket, ANSI_ERASE_SCREEN . ANSI_ERASE_BUFFER . ANSI_POS_TOP_LEFT);
	return;
}

function rrdp_cmd__enable($socket, $args) {
	global $rrdp_admin_clients, $rrdp_config;
	$arg = array_shift($args);

	// If we have a password, assume we are already invalid
	$invalid = isset($rrdp_config['enable_password']);
	if ($invalid && !is_null($arg) ) {
		// If we are invalid and have an argument passed then we
		// are still invalid if the passwords do not match
		$invalid = !password_verify($arg,$rrdp_config['enable_password']);
	}

	if (!$invalid) {
		$i = intval($socket);
		/* only a local connected user is allowed to switch to enhanced mode */
		if (in_array($rrdp_admin_clients[$i]['ip'], array('127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1'))) {
			$rrdp_admin_clients[$i]['privileged'] = true;
			rrdp_system__global_console_logging_update();
			return;
		} else {
			rrdp_system__socket_write($socket, "% Privileged mode is restricted to localhost only\r\n");
		}
	} else {
		rrdp_system__socket_write($socket, "% Invalid privileged mode password passed\r\n");
	}

	/* permission denied */
	return;
}

function rrdp_cmd__disable($socket, $args) {
	global $rrdp_admin_clients;
	if (!$args) {
		$i = intval($socket);
		/* client would like to return to unprivileged mode */
		$rrdp_admin_clients[$i]['privileged'] = false;
		rrdp_system__global_console_logging_update();
		return;
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	return;
}

function rrdp_cmd__quit($socket, $args) {
	global $rrdp_admin_clients, $rrdp_admin_sockets;

	/* ignore arguments */
	$i = intval($socket);

	/* leave privileged mode if enabled */
	rrdp_cmd__disable($socket, $args);

	/* update global console logging level */
	rrdp_system__global_console_logging_update();

	/* goodbye message - forces terminal color reset */
	rrdp_system__socket_write($socket, "Bye!\r\n");

	/* client would like to regularly close the connection */
	socket_shutdown($rrdp_admin_clients[$i]['socket'], 2);
	socket_close($rrdp_admin_clients[$i]['socket']);
	unset($rrdp_admin_clients[$i]);
	unset($rrdp_admin_sockets[$i]);

	return;
}

function rrdp_cmd__shutdown($socket, $args) {
	global $rrdp_clients, $rrdp_admin_clients, $rrdp_ipc_sockets, $rrdp_client, $rrdp_admin, $rrdcached_pid, $microtime_start, $rrdp_process_types, $systemd;

	if (!$args) {
		if ($socket === 'SIGTERM' || (isset($rrdp_admin_clients[intval($socket)]) && $rrdp_admin_clients[intval($socket)]['privileged'] === true)) {

			$microtime_start = microtime(true);

			if($systemd === false) {
				fwrite(STDOUT, ANSI_ERASE_SCREEN . ANSI_POS_TOP_LEFT . ANSI_BOLD . ANSI_YELLOW_FG . ANSI_BLUE_BG . "   RRDtool Proxy Server Shutdown                                                 " . ANSI_RESET . "\r\n");
			}

			/* stop accepting client updates */
			socket_close($rrdp_client);
			rrd_system__system_boolean_message('close: Client socket', true, false);


			/* stop RRDCached daemon after flushing all updates out to disk */
			if ($rrdcached_pid) {
				rrd_system__system_boolean_message(' stop: RRDCached daemon', true, false);
				posix_kill($rrdcached_pid, SIGUSR1);
				while (1) {
					$child_status = pcntl_waitpid($rrdcached_pid, $status);
					if ($child_status == -1 || $child_status > 0) {
						rrd_system__system_boolean_message(" stop: [PID:$rrdcached_pid] RRDCached daemon stopped", 1, false);
						break;
					} else {
						sleep(1);
					}
				}
			}

			/* shutdown Replicator:
			 * Stop triggering incremental syncronisation while we are waiting for other proxies picking up outstanding DIFFs.
			 * We have to ensure that other nodes are up-to-date before we leave the cluster temporarily.
			 *
			 * BUT we are forced to shutdown then we have to shutdown asap.
			 * */
			foreach ($rrdp_clients as $child_pid => $client) {
				if($socket === 'SIGTERM') {
					posix_kill($child_pid, SIGTERM);
				}else {
					$key = $rrdp_clients[$child_pid]['ipc'];
					if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
						posix_kill($child_pid, SIGTERM);
						@socket_write($rrdp_ipc_sockets[$key][1], serialize(array('type' => 'shutdown')) . "\r\n");
					}
				}

				$child_status = pcntl_waitpid($child_pid, $status);
				if ($child_status == -1 || $child_status > 0) {
					unset($rrdp_clients[$child_pid]);

					rrd_system__system_boolean_message(" stop: [PID:$child_pid] " . $rrdp_process_types[$client['type']] . " stopped", 1, false);
				} else {
					posix_kill($child_pid, SIGTERM);
				}
			}

			socket_close($rrdp_admin);
			rrd_system__system_boolean_message('close: Service socket', true, false);

			foreach ($rrdp_admin_clients as $index => $rrdp_admin_client) {
				if ($socket === 'SIGTERM') {
					@socket_write($rrdp_admin_client['socket'], "SIGTERM received. Proxy server is shutting down.\r\n");
				}elseif($index != intval($socket)) {
					@socket_write($rrdp_admin_client['socket'], "SHUTDOWN command received by admin instance #" . intval($socket) . ". Proxy server is shutting down.\r\n");
				}
				@socket_close($rrdp_admin_clients['socket']);
				rrd_system__system_boolean_message(" stop: [SOCKET:" . intval($rrdp_admin_client['socket']) . "] Service connection closed", 1, false);
			}

			if ($systemd === false) {
				fwrite(STDOUT, "\r\n" . rrdp_get_cacti_proxy_logo() . "\r\n\r\n" . '  Bye! :)' . "\r\n" . "\r\n" . '________________________________________________________________________________' . "\r\n");
			}
			exit ;
		}
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	return;
}

function rrdp_cmd__list($socket, $args=false, $root=false) {
	global $rrdp_admin_clients, $rrdp_help_messages;

	if (!$root) {
		$i = intval($socket);
		$output = '';
		foreach ($rrdp_help_messages['?'][ intval($rrdp_admin_clients[$i]['privileged']) ] as $cmd => $description) {
			$output .= sprintf("  %-15s %s\r\n", $cmd, ( is_array($description) ? $description['info'] : $description ) );
		}
		$output .= "\r\n";
		rrdp_system__socket_write($socket, rrdp_system__filter($output, $args));
	}else {
		$output = '';
		foreach ($root['?'] as $cmd => $description) {
			$output .= sprintf("  %-15s %s\r\n", $cmd, ( is_array($description) ? $description['info'] : $description ) );
		}
		$output .= "\r\n";
		rrdp_system__socket_write($socket, rrdp_system__filter($output, $args));
	}
	return;
}

function rrdp_cmd__show($socket, $args) {
	global $rrdp_admin_clients, $rrdp_config, $rrdp_status, $rrdp_clients, $rrdp_process_types;

	$arg = array_shift($args);

	if ( !is_null($arg) ) {

		$output = false;

		switch ($arg){
			case 'threads':
				$output = "\r\n" . sprintf(" %-10s %-15s %-3s\r\n", 'ID', 'IP', 'Privileged Mode');
				foreach ($rrdp_admin_clients as $client) {
					$output .= sprintf(" %-10s %-15s %-3s\r\n", '#' . strval(intval($client['socket'])), $client['ip'], ($client['privileged'] ? 'yes' : 'no'));
				}
				break;

			case 'processes':
				$output = "\r\n" . sprintf(" %-10s %-15s %-20s\r\n", 'PID', 'IP', 'Type');
				foreach ($rrdp_clients as $child_pid => $client) {
					$output .= sprintf(" %-10s %-15s %-20s\r\n", '#' . $child_pid, $client['ip'], $rrdp_process_types[$client['type']]);
				}
				break;

			case 'counters':
				$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'Variable', 'Value');
				foreach ($rrdp_status as $variable => $value) {
					$output .= sprintf(" %-35s %-12s \r\n", ucfirst(str_replace('rrdproxyStats', '', $variable)), (($value === 'live') ? rrdp_system__status_live($variable) : $value));
				}
				break;

			case 'variables':
				ksort($rrdp_config);
				$output = "\r\n" . sprintf(" %-35s %s \r\n\r\n", 'Name', 'Value');
				foreach ($rrdp_config as $variable => $value) {
					if ($variable == 'encryption') continue;
					$output .= sprintf(" %-35s %s \r\n", str_replace('rrdproxyAppl', '', $variable), is_array($value) ? implode(', ', $value) : (($value === false || $value === null) ? 'disabled' : $value));
				}
				break;

			case 'clients':
				$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'IP Address', 'Fingerprint');
				foreach ($rrdp_config['remote_clients'] as $ip => $fingerprint) {
					$output .= sprintf(" %-35s %s \r\n", $ip, $fingerprint);
				}
				break;
			case 'cluster':
				$output = "\r\n" . sprintf(" %-35s %-6s %-12s \r\n\r\n", 'IP Address', 'Port', 'Fingerprint');
				foreach ($rrdp_config['remote_proxies'] as $ip => $peer) {
					$output .= sprintf(" %-35s %-6s %-12s \r\n", $ip, $peer['port'], $peer['fingerprint']);
				}
				break;

			case 'rsa':
				$arg_second = array_shift($args);
				if($arg_second == 'publickey') {
					$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'Variable', 'Value');
					$output .= sprintf(" %-35s %s \r\n", 'Public Key', str_replace("\r\n", "\r\n                                     ", $rrdp_config['encryption']['public_key']));
					$output .= sprintf(" %-35s %s \r\n", 'Fingerprint', $rrdp_config['encryption']['public_key_fingerprint']);
				}else {
					rrdp_system__socket_write($socket, "% Incomplete command. Type \"show rsa ?\" for a list of subcommands\r\n");
					return;
				}
				break;

			case 'version':
				$output = rrdp_cmd__show_version();
				break;

			case 'logging':
				$output = rrdp_cmd__show_logging( array_shift($args) );
				break;

			case 'msr':
				$output = rrdp_cmd__show_msr( array_shift($args) );
				break;
		}

		rrdp_system__socket_write($socket, ((!$output) ? "% Unrecognized argument\r\n" : rrdp_system__filter($output, $args) . "\r\n" ));

	}else  {
		rrdp_system__socket_write($socket, "% Incomplete command. Type \"show ?\" for a list of subcommands\r\n");
	}
	return;
}


function rrdp_cmd__show_logging($arg) {
	global $rrdp_buffers;

	$output = "\r\n";
	if ($arg) {
		switch($arg) {
			case 'status' :
				if (__sizeof($rrdp_msr_buffer) > 0) {
					foreach ($rrdp_msr_buffer as $timeframe => $msr_commands) {
						$output .= "$timeframe:\r\n";
						foreach ($msr_commands as $timestamp => $msr_command) {
							$output .= sprintf(" %-25s %s \r\n", $timestamp, $msr_command);
						}
						rrdp_system__socket_write($socket, $output . "\r\n");
					}
				} else {
					rrdp_system__socket_write($socket, "no entries found\r\n");
				}
				break;
			case 'buffered' :
			case 'snmp' :
				if (__sizeof($rrdp_buffers['logging_' . $arg]) > 0) {
					foreach ($rrdp_buffers['logging_' . $arg] as $index => $row) {
						//rrdp_system__socket_write($socket, "row\r\n");
						$output .= $row . "\r\n";
					}
				} else {
					$output = "no entries found\r\n";
				}
				break;
			default :
				$output = "% Unrecognized command" . $args . "\r\n";
				break;
		}
	} else {
		$output = '% Type "show ?" for a list of subcommands' . "\r\n";
	}

	return $output;
}

function rrdp_cmd__show_msr($arg) {
	global $rrdp_msr_buffer;

	$output = '';
	if (isset($arg)) {
		switch($arg) {
			case 'buffer' :
				if (__sizeof($rrdp_msr_buffer) > 0) {
					foreach ($rrdp_msr_buffer as $timeframe => $msr_commands) {
						$output .= "$timeframe:\r\n";
						foreach ($msr_commands as $timestamp => $msr_command) {
							$output .= sprintf(" %-25s %s \r\n", $timestamp, $msr_command);
						}
					}
				} else {
					$output .= "no entries found\r\n";
				}
				break;
			case 'health' :
				break;
			case 'status' :
				break;
			default :
				$output = "% Unrecognized command" . $args . "\r\n";
				break;
		}
	} else {
		$output = '% Type "show msr ?" for a list of subcommands' . "\r\n";
	}

	return $output;
}

function rrdp_cmd__show_version($systemd = false) {
	global $rrdp_config, $rrdp_clients, $rrdp_repl_master_pid, $rrdp_repl_slave_pid;

	$output = '';
	$runtime = microtime(true) - $rrdp_config['start'];
	$days = floor($runtime / 86400);
	$hours = floor(($runtime - $days * 86400) / 3600);
	$minutes = floor(($runtime - $days * 86400 - $hours * 3600) / 60);
	$seconds = floor($runtime - $days * 86400 - $hours * 3600 - $minutes * 60);

	$memory_limit = rrdp_system__convert2bytes(ini_get('memory_limit'));
	$memory_used = memory_get_usage();
	$memory_usage = round(($memory_used / $memory_limit) * 100, 8);

	$rrdp_address = (($rrdp_config['address'] != '0.0.0.0' & $rrdp_config['address'] != '::') ? $rrdp_config['address'] : 'any');

	$sockets = " Open Sockets: "
		. "\r\n" . sprintf(" Administration: [ %-20s :%-5s ]", 'localhost', $rrdp_config['port_admin'])
		. "\r\n" . sprintf(" Replication:    [ %-20s :%-5s ]", $rrdp_address, $rrdp_config['port_server'])
		. "\r\n" . sprintf(" Clients:        [ %-20s :%-5s ]", $rrdp_address, $rrdp_config['port_client']);

	if($systemd === false ) {
		$output = rrdp_get_cacti_proxy_logo()
			. "\r\n" . " RRDtool Proxy Server v" . RRDP_VERSION
			. "\r\n" . " " . COPYRIGHT_YEARS
			. "\r\n" . " {$rrdp_config['name']} uptime is $days days, $hours hours, $minutes minutes, $seconds seconds"
			. "\r\n" . " Server IP " . gethostbyname(php_uname('n'))
			. "\r\n" . " Memory usage " . $memory_usage . " % (" . $memory_used . " of " . $memory_limit . " bytes)"
			. "\r\n" . " Fingerprint " . $rrdp_config['encryption']['public_key_fingerprint']
			. "\r\n" . " Processes: rrdp (" . posix_getpid() . ")"
			. "\r\n" . "              |_ replication master ($rrdp_repl_master_pid)"
			. "\r\n" . "              |_ replication slave  ($rrdp_repl_slave_pid)"
			. "\r\n"
			. "\r\n" . " Session usage (" . __sizeof($rrdp_clients) . '/' . $rrdp_config['max_cnn'] . ")"
			. "\r\n"
			. "\r\n" . $sockets
			. "\r\n";
	} else {
		$output = $sockets;
	}

	return $output;
}

function rrdp_cmd__debug($socket, $args) {
	global $rrdp_replicator_pid, $rrdp_admin_clients, $rrdp_help_messages, $rrdp_config, $rrdp_clients, $rrdp_ipc_sockets;

	if (__sizeof($args) == 2) {
		$i = intval($socket);
		if (isset($rrdp_help_messages['debug']['?'][intval($rrdp_admin_clients[$i]['privileged'])][$args[0]])) {
			$process = $args[0];
			switch($args[1]) {
				case 'on' :
					$rrdp_admin_clients[$i]['debug'][$process] = true;
					$orginal_state = (isset($rrdp_config['debug'][$process]) && $rrdp_config['debug'][$process] === true) ? true : false;
					$rrdp_config['debug'][$process] = true;

					if ($process == 'replicator') {
						if ($rrdp_replicator_pid) {
							$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
							if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
								@socket_write($rrdp_ipc_sockets[$key][1], "debug_on\r\n");
							}
						}
					}

					if ($orginal_state === false) {
						rrdp_system__socket_write($socket, "GLOBAL DEBUG mode for $process process started.\r\n");
					}
					break;
				case 'off' :
					unset($rrdp_admin_clients[$i]['debug'][$process]);
					$orginal_state = (isset($rrdp_config['debug'][$process]) && $rrdp_config['debug'][$process] === true) ? true : false;

					$debug_sessions_running = false;
					foreach ($rrdp_admin_clients as $rrdp_admin_client) {
						if (isset($rrdp_admin_client['debug'][$process])) {
							$debug_sessions_running = true;
							break;
						}
					}

					if ($process == 'replicator') {
						if ($rrdp_replicator_pid) {
							$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
							if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
								@socket_write($rrdp_ipc_sockets[$key][1], "debug_off\r\n");
							}
						}
					}

					if ($orginal_state === true && $debug_sessions_running === false) {
						$rrdp_config['debug'][$process] = false;
						rrdp_system__socket_write($socket, "GLOBAL DEBUG mode for $process process stopped.\r\n");
					}

					break;
				default :
					print $args[1];
					rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
					break;
			}
		} else {
			rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
		}
	} else {
		rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	}
	return;
}

function rrdp_cmd__set($socket, $args) {
	global $rrdp_admin_clients, $rrdp_help_messages;

	$arg = array_shift($args);
	if ( !is_null($arg) ) {
		$rrdp_function = 'rrdp_cmd__set_' . $arg;
		if (function_exists($rrdp_function)) {
			$rrdp_function($socket, $args);
			return;
		}
	}
	rrdp_system__socket_write($socket, '% Incomplete command. Type "set ?" for a list of subcommands' . "\r\n");
}

function rrdp_cmd__set_cluster($socket, $args) {
	global $rrdp_config, $rrdp_clients, $rrdp_repl_master_pid, $rrdp_repl_slave_pid, $rrdp_ipc_sockets;

	$arg = array_shift($args);
	if ( !is_null($arg) ) {
		switch($arg) {
			case 'add' :
				if (__sizeof($args) == 3) {

					/* Verify IP address */
					if (filter_var($args[0], FILTER_VALIDATE_IP) === false) {
						rrdp_system__socket_write($socket, "% Invalid IP adress\r\n");
						break;
					}

					if (filter_var($args[1], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => '/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/'))) === false) {
						rrdp_system__socket_write($socket, "% Invalid PORT. Range: [1024-65535]\r\n");
						break;
					}

					if (filter_var($args[2], FILTER_VALIDATE_REGEXP, array("options" => array("regexp" => "/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/"))) === false) {
						rrdp_system__socket_write($socket, "% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]\r\n");
						break;
					}

					/* if the server IP has already been defined, then we overwrite its settings */
					$rrdp_config['remote_proxies'][$args[0]] = array('port' => $args[1], 'fingerprint' => $args[2]);

					/* update local list of servers */
					file_put_contents('./include/proxies', '<?php $rrdp_remote_proxies = ' . var_export($rrdp_config['remote_proxies'], true) . ';');

					/* create a new subfolder for this peer (if not already existing) to support data replication */
					if (!is_dir('./msr/' . $args[0])) {
						mkdir('./msr/' . $args[0]);
					}

					/* inform replication processes */
					$key = $rrdp_clients[$rrdp_repl_master_pid]['ipc'];
					if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
						@socket_write($rrdp_ipc_sockets[$key][1], serialize(array('type' => 'reload_proxy_list')) . "\r\n");
					}
					$key = $rrdp_clients[$rrdp_repl_slave_pid]['ipc'];
					if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
						@socket_write($rrdp_ipc_sockets[$key][1], serialize(array('type' => 'reload_proxy_list')) . "\r\n");
					}

				} else {
					rrdp_system__socket_write($socket, "% set cluster add <IP> <Port> <Fingerprint>\r\n");
				}

				break;
			case 'remove' :
				if (isset($args[0])) {

					if (isset($rrdp_config['remote_proxies'][$args[0]])) {
						unset($rrdp_config['remote_proxies'][$args[0]]);
						/* update local list of clients */
						file_put_contents('./include/proxies', '<?php $rrdp_remote_proxies = ' . var_export($rrdp_config['remote_proxies'], true) . ';');

						/* inform replication processes */
						$key = $rrdp_clients[$rrdp_repl_master_pid]['ipc'];
						if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
							@socket_write($rrdp_ipc_sockets[$key][1], serialize(array('type' => 'reload_proxy_list')) . "\r\n");
						}
						$key = $rrdp_clients[$rrdp_repl_slave_pid]['ipc'];
						if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
							@socket_write($rrdp_ipc_sockets[$key][1], serialize(array('type' => 'reload_proxy_list')) . "\r\n");
						}

						/* destroy replication data */
						if (is_dir('./msr/' . $args[0])) {
							$files = array_diff(scandir('./msr/' . $args[0]), array('.','..'));
							foreach($files as $file) {
								unlink('./msr/' . $args[0] . '/' . $file);
							}
							rmdir('./msr/' . $args[0]);
						}
					} else {
						rrdp_system__socket_write($socket, "% Unknown server IP address\r\n");
					}
				} else {
					rrdp_system__socket_write($socket, "% set server remove <IPv4|IPv6>\r\n");
				}
				break;
			case 'update' :
				if (isset($args[0])) {

					if (isset($rrdp_config['remote_proxies'][$args[0]])) {
						unset($rrdp_config['remote_proxies'][$args[0]]);
						/* update local list of clients */
						file_put_contents('./include/proxies', '<?php $rrdp_remote_proxies = ' . var_export($rrdp_config['remote_proxies'], true) . ';');

						/* inform replication processes */
						$key = $rrdp_clients[$rrdp_repl_master_pid]['ipc'];
						if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
							@socket_write($rrdp_ipc_sockets[$key][1], serialize(array('type' => 'reload_proxy_list')) . "\r\n");
						}
						$key = $rrdp_clients[$rrdp_repl_slave_pid]['ipc'];
						if (isset($rrdp_ipc_sockets[$key]) && is_resource($rrdp_ipc_sockets[$key][1])) {
							@socket_write($rrdp_ipc_sockets[$key][1], serialize(array('type' => 'reload_proxy_list')) . "\r\n");
						}

						/* destroy replication data */
						if (is_dir('./msr/' . $args[0])) {
							rmdir('./msr/' . $args[0]);
						}

					} else {
						rrdp_system__socket_write($socket, "% Unknown server IP address\r\n");
					}
				} else {
					rrdp_system__socket_write($socket, "% set server remove <IPv4|IPv6>\r\n");
				}
				break;
			default :
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
				break;
		}
	} else {
		rrdp_system__socket_write($socket, '% Type "set cluster ?" for a list of subcommands' . "\r\n");
	}
	return;
}

function rrdp_cmd__set_client($socket, $args) {
	global $rrdp_config;

	$arg = array_shift($args);
	if ( !is_null($arg) ) {
		switch($arg) {
			case 'add' :
				if (isset($args[0]) && isset($args[1])) {

					/* Verify IP address */
					if (filter_var($args[0], FILTER_VALIDATE_IP) === false) {
						rrdp_system__socket_write($socket, "% Invalid IP adress\r\n");
						break;
					}

					/* Verify Fingerprint Format */
					$fingerprint = trim($args[1]);
					preg_match_all("/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/", $args[1], $output_array);

					if (isset($output_array[0][0]) && $output_array[0][0] == $args[1]) {
						/* if the client IP has already been defined, then overwrite its fingerprint */
						$rrdp_config['remote_clients'][$args[0]] = $args[1];
						/* update local list of clients */
						file_put_contents('./include/clients', '<?php $rrdp_remote_clients = ' . var_export($rrdp_config['remote_clients'], true) . ';');
						rrdp_cmd__show($socket, array('clients') );
					} else {
						rrdp_system__socket_write($socket, "% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]\r\n");
					}
				} else {
					rrdp_system__socket_write($socket, "% set client add <IP> <Fingerprint>\r\n");
				}

				break;
			case 'remove' :
				if (isset($args[0])) {

					if (isset($rrdp_config['remote_clients'][$args[0]])) {
						unset($rrdp_config['remote_clients'][$args[0]]);
						/* update local list of clients */
						file_put_contents('./include/clients', '<?php $rrdp_remote_clients = ' . var_export($rrdp_config['remote_clients'], true) . ';');
						rrdp_cmd__show($socket, array('clients') );
					} else {
						rrdp_system__socket_write($socket, "% Unknown client IP address\r\n");
					}
				} else {
					rrdp_system__socket_write($socket, "% set client remove <IPv4|IPv6>\r\n");
				}

				break;
			default :
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
				break;
		}
	} else {
		rrdp_system__socket_write($socket, '% Type "set client ?" for a list of subcommands' . "\r\n");
	}
	return;
}

function rrdp_cmd__set_rsa($socket, $args) {

	global $rrdp_config;

	$arg = array_shift($args);
	if ( !is_null($arg) ) {
		switch($arg) {
			case 'keys' :
				$rsa = new \phpseclib\Crypt\RSA();
				$keys = $rsa -> createKey(2048);
				$rrdp_config['encryption']['public_key'] = $keys['publickey'];
				$rrdp_config['encryption']['private_key'] = $keys['privatekey'];

				file_put_contents('./include/public.key', $rrdp_config['encryption']['public_key']);
				file_put_contents('./include/private.key', $rrdp_config['encryption']['private_key']);

				$rsa -> loadKey($rrdp_config['encryption']['public_key']);
				$rrdp_config['encryption']['public_key_fingerprint'] = $rsa -> getPublicKeyFingerprint();

				rrdp_cmd__show($socket, array( 0=>'rsa', 1=>'publickey'));

				break;
			default :
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
				break;
		}
	} else {
		rrdp_system__socket_write($socket, '% Type "set rsa ?" for a list of subcommands' . "\r\n");
	}
	return;
}

function rrdp_cmd__set_logging($socket, $args) {
	global $rrdp_config, $rrdp_admin_clients, $logging_categories;

	$arg = array_shift($args);
	if ( !is_null($arg) ) {
		switch($arg) {
			case 'buffered':
			case 'snmp':
				$level = array_shift($args);
				if(is_numeric($level) && in_array($level, range(0,7))) {
					$rrdp_config['logging_severity_' . $arg] = $level;
					/* TODO update config file */
				}else {
					rrdp_system__socket_write($socket, '% Type "set logging ' . $arg . ' ?" for a list of arguments' . "\r\n");
				}
				break;
			case 'terminal':
			case 'console':
				$argument = array_shift($args);
				if($argument == 'level') {
					$level = array_shift($args);
					if(is_numeric($level) && in_array($level, (($arg == 'terminal' | $arg == 'console') ? range(0,8) : range(0,7)) ) ) {
						if($arg == 'console') {
							$rrdp_admin_clients[intval($socket)]['logging_severity_console'] = $level;
							rrdp_system__global_console_logging_update();
						}else {
							$rrdp_config['logging_severity_' . $arg] = $level;
							/* TODO update config file */
						}
					}else {
						rrdp_system__socket_write($socket, '% Type "set logging ' . $arg . ' level ?" for a list of arguments' . "\r\n");
					}
				}elseif($argument == 'category') {
					$categories = explode(',', array_shift($args));

					if(__count($categories)>0) {
						$selected_categories = array();
						foreach($categories as $category) {
							if ($category == 'none') {
								$selected_categories = 'none';
								break;
							}else if ($category == 'all') {
								$selected_categories = 'all';
								break;
							}else if(array_key_exists($category, $logging_categories)) {
								$selected_categories[] = $category;
							}else {
								rrdp_system__socket_write($socket, "% Unrecognized argument\r\n");
								break 2;
							}
						}

						if(is_array($selected_categories)) {
							$selected_categories = implode(',', $selected_categories);
						}
						if($arg == 'console') {
							$rrdp_admin_clients[intval($socket)]['logging_category_console'] = $selected_categories;
							rrdp_system__global_console_logging_update();
						}else {
							$rrdp_config['logging_category_terminal'] = $selected_categories;
							/* TODO update config file */
						}
					}else {
						rrdp_system__socket_write($socket, '% Type "set logging ' . $arg . ' category ?" for a list of arguments' . "\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, '% Type "set logging ' . $arg . ' ?" for a list of arguments' . "\r\n");
				}
				break;

			default :
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
				break;
		}
	} else {
		rrdp_system__socket_write($socket, '% Type "set logging ?" for a list of subcommands' . "\r\n");
	}
	return;
}




/**
 * Handle master, slave as well as client processes
 */
function handle_child_processes($ipc_sockets, $type, $ssock=false, $arg1=false) {
	GLOBAL $__server_listening, $rrdp_status, $rrdcached_pid, $ipc_global_resource_id, $debug_category, $c_pid;

	list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
	$ipc_global_resource_id = intval($ipc_socket_child);

	$pid = pcntl_fork();

	if ($pid == -1) {

		/* === fork failed === */
		die ;
		//TODO: handling missing

	} elseif ($pid === 0) {

		/* === child === */
		declare(ticks = 10);

		switch($type) {
			case 1:
				include ('./lib/master.php');
				break;
			case 2:
				include ('./lib/slave.php');
				break;
			case 3:
				include ('./lib/client.php');
				break;
		}

		/* install signal handler */
		pcntl_signal(SIGHUP,  '__sig_handler');
		pcntl_signal(SIGTERM, '__sig_handler');
		pcntl_signal(SIGUSR1, '__sig_handler');
		pcntl_signal(SIGUSR2, '__sig_handler');

		set_error_handler("__errorHandler");

		/* stop main loop, because we have to reuse the same code base */
		$__server_listening = false;

		/* free up unused resources */
		if(is_resource($ssock)) socket_close($ssock);
		socket_close($ipc_socket_child);

		/* get my own process id */
		$c_pid = posix_getpid();

		/* return reference message */
		__logging(LOGGING_LOCATION_BUFFERED, 'Child Process established', 'SYS', SEVERITY_LEVEL_NOTIFICATION);

		/* overwrite array $rrdp_status to do our own calculations */
		$rrdp_status = array('type' => 'status', 'bytes_received' => 0, 'bytes_sent' => 0, 'queries_rrdtool_total' => 0, 'queries_rrdtool_valid' => 0, 'queries_rrdtool_invalid' => 0, 'rrd_pipe_broken' => 0, 'status' => 'RUNNING');

		/* handle client parent and child communication */
		interact($arg1);

		/* close client connection if existing*/
		if(is_resource($arg1)) {
			socket_shutdown($arg1); ####check
			socket_close($arg1);
		}

		/* send IPC update message to parent */
		socket_write($ipc_socket_parent, serialize($rrdp_status));

		/* shutdown connection to parent */
		socket_shutdown($ipc_socket_parent);
		socket_close($ipc_socket_parent);

		/* kill the process itself */
		exit(0);

	} else {
		/* === parent === */

		/* free up unused resources */
		socket_close($ipc_socket_parent);
		if(is_resource($arg1)) socket_close($arg1);

		/* return child's process identifier */
		return $pid;
	}
}

/*	display_version - displays the version of the RRDproxy */
function display_version() {
	$output = RRDP_VERSION_FULL;
	fwrite(STDOUT, $output);
}

/*	display_help - displays the usage of the RRDproxy */
function display_help() {
	display_version();
	$output = "\r\n" . "Usage: rrdtool-proxy.php [-w|--wizard] [-v|--version] [-h|--help] [-f|--force] [-s|--systemd]\r\n"
		. "\r\n" . "Optional:"
		. "\r\n" . "    -v --version   - Display the version of RRDtool Proxy Server"
		. "\r\n" . "    -h --help      - Display this help"
		. "\r\n" . "    -w --wizard    - Start Configuration Wizard"
		. "\r\n" . "    -f --force     - Allow multiple proxy instances running on a single server"
		. "\r\n" . "    -s --systemd   - Adjust output messages for systemd"
		. "\r\n" . "\r\n";
	fwrite(STDOUT, $output);
}

/*	wizard - starts the wizard for system setup */
function init_wizard() {
	define('SYSTEM_LOGGING', FALSE);
	include_once ('./lib/wizard.php');
	exit;
}

/*  signal handler  */
function rrdp_sig_handler($signo) {
	switch ($signo) {
		case SIGTERM :
			rrdp_cmd__shutdown('SIGTERM', false);
			exit ;
			break;
		case SIGHUP :
			break;
		case SIGUSR1 :
			break;
		default :
	}
}

function rrdp_get_cacti_proxy_logo() {
	return
		  "\r\n" . "# " . ANSI_BOLD . ANSI_GREEN_FG . "    ___           _   _  " . ANSI_RESET . "   __    __    ___     ___                     "
		. "\r\n" . "# " . ANSI_BOLD . ANSI_GREEN_FG . "   / __\__ _  ___| |_(_) " . ANSI_RESET . "  /__\  /__\  /   \   / _ \_ __ _____  ___   _ "
		. "\r\n" . "# " . ANSI_BOLD . ANSI_GREEN_FG . "  / /  / _` |/ __| __| | " . ANSI_RESET . " / \// / \// / /\ /  / /_)/ '__/ _ \ \/ / | | |"
		. "\r\n" . "# " . ANSI_BOLD . ANSI_GREEN_FG . " / /__| (_| | (__| |_| | " . ANSI_RESET . "/ _  \/ _  \/ /_//  / ___/| | | (_) >  <| |_| |"
		. "\r\n" . "# " . ANSI_BOLD . ANSI_GREEN_FG . " \____/\__,_|\___|\__|_| " . ANSI_RESET . "\/ \_/\/ \_/___,'   \/    |_|  \___/_/\_\\___, |"
		. "\r\n" . "# " . ANSI_BOLD . ANSI_GREEN_FG . "                         " . ANSI_RESET . "                                         |___/ ";
}
