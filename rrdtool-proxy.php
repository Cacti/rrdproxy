<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2017 The Cacti Group                                 |
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
if (!isset($_SERVER["argv"][0]) || isset($_SERVER['REQUEST_METHOD'])  || isset($_SERVER['REMOTE_ADDR'])) {
	die("<br><strong>This script is only meant to run at the command line.</strong>");
}

$microtime_start = microtime(true);
chdir( dirname( __FILE__ ) );
require_once('./include/global.php');

/* process calling arguments */
$parms = $_SERVER["argv"];
array_shift($parms);

$wizard = FALSE;

if (sizeof($parms) != 0) {
	foreach($parms as $parameter) {
		@list($arg, $value) = @explode("=", $parameter);

		switch ($arg) {
		case "-w":
		case "--wizard":
			$wizard = true;
			break;
		case "-h":
		case "-v":
		case "--version":
		case "--help":
			display_help();
			exit;
		default:
			print "ERROR: Invalid Parameter " . $parameter . "\n\n";
			display_help();
			exit;
		}
	}
}



/* ---------------------------- SYSTEM SETUP ROUTINE -------------------------------------- */

if( !file_exists('./include/config') || $wizard === true ) {
	include_once('./lib/wizard.php');
	exit;
}else {
	fwrite(STDOUT, "\033[2J\033[;H\033[1;33;44m   RRDtool Proxy Server Startup                                                  \033[0m" . PHP_EOL);

	/* No Windows! Please ;) */
	$support_os = strstr(PHP_OS, "WIN") ? false : true;
	rrd_system__system_boolean_message( 'test: operation system supported', $support_os, true );

	/* RRDtool Proxy has already been started ? */
	exec('ps -ef | grep -v grep | grep -v "sh -c" | grep rrdtool-proxy.php', $output);
	$not_running = (sizeof($output)>=2) ? false : true;
	rrd_system__system_boolean_message( 'test: no proxy instance running', $not_running, true );

	/* RRDtool Cache Daemon has already been started ? */
	exec('ps -ef | grep -v grep | grep -v "sh -c" | grep rrdcached', $output);
	$not_running = (sizeof($output)>=2) ? false : true;
	rrd_system__system_boolean_message( 'test: no cache instance running', $not_running, true );

	/* check state of required and optional php modules */
	rrd_system__system_boolean_message( 'test: php module \'sockets\'', extension_loaded('sockets'), true );
	rrd_system__system_boolean_message( 'test: php module \'posix\'', extension_loaded('posix'), true );
	rrd_system__system_boolean_message( 'test: php module \'pcntl\'', extension_loaded('pcntl'), true );
	rrd_system__system_boolean_message( 'test: php module \'gmp\'', extension_loaded('gmp'), true );
	rrd_system__system_boolean_message( 'test: php module \'openssl\'', extension_loaded('openssl'), true );
	rrd_system__system_boolean_message( 'test: php module \'zlib\'',  extension_loaded('zlib'), true );
	#rrd_system__system_boolean_message( 'test: php module \'readline\'', extension_loaded('readline'), true );

	exec("ulimit -n", $max_open_files);
	$pid_of_php = getmypid();		
	exec("ls -l /proc/$pid_of_php/fd/ | wc -l", $open_files);
	if($max_open_files[0] == 'unlimited') $max_open_files[0] = 1048576;
	
	rrd_system__system_boolean_message( 'test: max. number of open files [' . $max_open_files[0] . ']', $max_open_files[0], true );
	rrd_system__system_boolean_message( 'test: max. number of connections in backlog [' . SOMAXCONN . ']', SOMAXCONN, true );

}

/* ---------------------------- BEGIN - SYSTEM STARTUP ROUTINE -------------------------------------- */

/* fork the current process to initiate RRDproxy's master process */
$ppid = posix_getpid();
$pid = pcntl_fork();
if($pid == -1) {
	/* oops ... something went wrong :/ */
	rrd_system__system_boolean_message( 'init: proxy master process', false, true );	
	return false;
}elseif($pid == 0) {
	/* the child should do nothing as long as the parent is still alive */
	$sid = posix_setsid();
	rrd_system__system_boolean_message( 'init: detach master process', $sid, true );
}else {
	/* kill the parent not before the child signals being up */
	$info = array();
	$rrdp_state = pcntl_sigwaitinfo( array(SIGUSR1, SIGTERM), $info);
	exit;
}

/* load configuration and config arrays */
chdir( dirname( __FILE__ ) );
require_once('./include/global.php');
require_once('./include/config');
@include_once('./include/clients');
@include_once('./include/proxies');

/* include external libraries */
set_include_path("./include/phpseclib/");
require_once('Math/BigInteger.php');
require_once('Crypt/Base.php');
require_once('Crypt/Hash.php');
require_once('Crypt/Random.php');
require_once('Crypt/RSA.php');
require_once('Crypt/Rijndael.php');

/* install signal handler */
pcntl_signal(SIGHUP, "rrdp_sig_handler");
pcntl_signal(SIGTERM, "rrdp_sig_handler");
pcntl_signal(SIGUSR1, "rrdp_sig_handler");
pcntl_signal(SIGUSR2, "rrdp_sig_handler");

/* initiate RSA encryption */
rrdp_system__encryption_init();

/* keep start-up time in mind ... */
$rrdp_config['start'] = time();
/* ... as well as its sync state */
$rrdp_config['last_sync'] = true;	# TODO: Has to false once replicator is working faultlessly

declare(ticks = 100);

/* Socket Server Presets */
ini_set("max_execution_time", "0");
ini_set("memory_limit", "1024M");
error_reporting(E_ALL ^ E_NOTICE);

$__server_listening = true; 
$rrdp_msr_buffer = array();
$rrdp_logging_buffer = array();


/* create a Service TCP Stream socket supporting IPv6 and 4 */
$rrdp_admin = @socket_create(AF_INET6 , SOCK_STREAM, SOL_TCP);
if(socket_last_error() == 97) {
	$rrdp_config['ipv6'] = false;
	socket_clear_error();
	$rrdp_admin = @socket_create(AF_INET , SOCK_STREAM, SOL_TCP);
}else {
	$rrdp_config['ipv6'] = true;
}
rrd_system__system_boolean_message( 'test: ipv6 supported', $rrdp_config['ipv6']);


/* define a socket for proxy administration */
if(!$rrdp_admin) { 
	rrd_system__system_die( PHP_EOL . "Unable to create socket. Error: " . socket_strerror(socket_last_error()) . PHP_EOL);
}
@socket_set_option($rrdp_admin, SOL_SOCKET, SO_REUSEADDR, 1);
if(!@socket_bind($rrdp_admin, (($rrdp_config['ipv6']) ? '::1' : '127.0.0.1'), $rrdp_config['port_admin'])) {
	rrd_system__system_die( PHP_EOL . "Unable to bind socket to '" . $rrdp_config['address'] . ":" . $rrdp_config['port_admin'] ."'" . PHP_EOL . "Error: " . socket_strerror(socket_last_error()) . PHP_EOL );
};
socket_set_nonblock($rrdp_admin);
socket_listen($rrdp_admin);
rrd_system__system_boolean_message( 'init: tcp admin socket', $rrdp_admin, true);
rrdp_system__logging("Start listening to port " . $rrdp_config['address'] . ":" . $rrdp_config['port_admin']);

/* set up a client socket request against RRDtool */
$rrdp_client = @socket_create( (($rrdp_config['ipv6']) ? AF_INET6 : AF_INET ), SOCK_STREAM, SOL_TCP);
if(!$rrdp_client) { 
	rrd_system__system_die( PHP_EOL . "Unable to create socket. Error: " . socket_strerror(socket_last_error()) . PHP_EOL); 
}
@socket_set_option($rrdp_client, SOL_SOCKET, SO_REUSEADDR, 1);
if(!@socket_bind($rrdp_client, $rrdp_config['address'], $rrdp_config['port_client'])) {
    rrd_system__system_die( PHP_EOL . "Unable to bind socket to '" . $rrdp_config['address'] . ":" . $rrdp_config['port_client'] ."'" . PHP_EOL . "Error: " . socket_strerror(socket_last_error()) . PHP_EOL );
};
socket_set_nonblock($rrdp_client);

rrd_system__system_boolean_message( 'init: tcp client socket', $rrdp_client, true);

socket_listen($rrdp_client); #TODO: This line needs to be removed once replicator is ready
rrdp_system__logging("Start listening to port " . $rrdp_config['address'] . ":" . $rrdp_config['port_client']);

$rrdp_clients = array();
$rrdp_ipc_sockets = array();
$rrdp_admin_sockets = array();
$rrdp_admin_clients = array();
$rrdp_ipc_server_sockets = array();

/* start RRDCached if configued */
if($rrdp_config['path_rrdcached']) {

	$current_working_directory = realpath('');
	$rrdcached_cmd = $rrdp_config['path_rrdcached']
					. ' -l unix:' . $current_working_directory . '/run/rrdcached.sock'
					. ' -w ' . $rrdp_config['rrdcache_update_cycle']
					. ($rrdp_config['rrdcache_update_delay'] ? ' -z ' . $rrdp_config['rrdcache_update_delay'] : '')
					. ' -f ' . $rrdp_config['rrdcache_life_cycle']
					. ' -p ' . $current_working_directory . '/run/rrdcached.pid'
					. ' -t ' . $rrdp_config['rrdcache_write_threads']
					. ' -j ' . $current_working_directory . '/run/journal'
					. ' -b ' . $rrdp_config['path_rra']
					. ' -O';

	rrdp_system__logging("INIT: RRDcached daemon - " . $rrdcached_cmd);
	$rrdcached = proc_open($rrdcached_cmd,[1 => ['pipe','w'],2 => ['pipe','w']],$pipes);

	$stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    proc_close($rrdcached);

	/* Feedback from replicator required - let's wait for a sec */
	usleep(1000000);
	$rrdcached_pid = file_exists($current_working_directory .'/run/rrdcached.pid')  ? trim(file_get_contents($current_working_directory .'/run/rrdcached.pid')) : 0;
	rrd_system__system_boolean_message( 'init: rrdcached daemon [PID: ' . $rrdcached_pid .']', $rrdcached_pid, false);

	if( $stderr ) rrdp_system__logging('ERROR: RRDcached daemon - ' . $stderr);
	if( $rrdcached_pid ) rrdp_system__logging('STATUS: RRDcached daemon [PID: ' . $rrdcached_pid .'] running.');
}else {
	$rrdcached_pid = 0;
}

/* start replicator */
socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $ipc_sockets);
list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
$key = intval($ipc_socket_child);
$rrdp_replicator_pid = handle_replicator($ipc_sockets);
$rrdp_clients[$rrdp_replicator_pid]['ip'] = '127.0.0.1';
$rrdp_clients[$rrdp_replicator_pid]['ipc'] = $key;
$rrdp_ipc_sockets[$key] = $ipc_sockets;

/* Feedback from replicator required - let's wait for a sec */
usleep(1000000);

/* limit the number max. connections in relation to the number of open files this system supports */
exec("ulimit -n", $max_open_files);
$pid_of_php = getmypid();
exec("ls -l /proc/$pid_of_php/fd/ | wc -l", $open_files);
if($max_open_files[0] == 'unlimited') $max_open_files[0] = 1048576;
$rrdp_config['max_cnn'] = intval(($max_open_files[0]-$open_files[0])/2-$rrdp_config['max_admin_cnn']*2-100);	#buffer of 100 open files

/* return version info to give admins a summary of our setup */
fwrite(STDOUT, PHP_EOL);
rrdp_cmd__show_version();
fwrite(STDOUT, '________________________________________________________________________________' . PHP_EOL);

/* signal the parent to exit - now we are up and ready */
@posix_kill( $ppid , SIGUSR1);

/* ---------------------------- END - SYSTEM STARTUP ROUTINE ---------------------------- */

while($__server_listening) {

	$write = array();
	$except= array();

	$tv_sec = 10;
	
	rrdp_msr__block_write();
	rrdp_system__check();

    /* setup clients listening to socket for reading */
    $read = array();

	/* do not listen to client connection requests as long as the system is not in state fully-synced */
	if($rrdp_config['last_sync'] !== false) {
		$read[0] = $rrdp_client;
	}
	$read[1] = $rrdp_admin;
	
	/* and then check child processes */
	foreach($rrdp_clients as $child_pid => $client) {
		$child_status = pcntl_waitpid($child_pid, $status, WNOHANG);
		if($child_status == -1 || $child_status > 0) {
			unset($rrdp_ipc_sockets[ intval($rrdp_clients[$child_pid]['ipc']) ]);
			unset($rrdp_clients[$child_pid]);
		}else {
			$key = $rrdp_clients[$child_pid]['ipc'];
			if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
				$read[] = $rrdp_ipc_sockets[ $key ][1];
			}
		}
	}
	
	/* all admin connections need to be monitored for changes, too */
	foreach($rrdp_admin_clients as $rrdp_admin_client) {
        $read[] = $rrdp_admin_client['socket'];
	}
	
    $ready = socket_select($read, $write, $except, $tv_sec);
	pcntl_signal_dispatch();
	if($ready) {
		foreach($read as $read_socket_index => $read_socket) {
			if($read_socket == $rrdp_client) {
				/* a default client is trying to connect */
				if($rrdp_config['max_cnn'] > sizeof($rrdp_clients)) {
					$socket_descriptor = socket_accept($read_socket);
					socket_getpeername($socket_descriptor, $ip);
					/* verify authorization */
					if( array_key_exists($ip, $rrdp_remote_clients) === true ) {
						
						/* setup IPC */
						socket_create_pair(AF_UNIX, SOCK_STREAM, 0, $ipc_sockets);
						list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
						$key = intval($ipc_socket_child);
						
						/* fork a child process for that connection */
						$pid = handle_client($rrdp_client, $socket_descriptor, $ipc_sockets);
						$rrdp_clients[$pid]['ip'] = $ip;
						$rrdp_clients[$pid]['ipc'] = $key;
						$rrdp_ipc_sockets[$key] = $ipc_sockets;
						rrdp_system__debug('Default connection request #' . $key . '[IP: ' . $ip . '] granted.', 'ACL', 'debug_notice');

					}else {
						@socket_write($socket_descriptor, "ERROR: Access denied.\r\n");
						@socket_close($socket_descriptor);
						rrdp_system__count('aborted_connects');
						rrdp_system__debug('Default connection request #' . $key . '[IP: ' . $ip . '] rejected.', 'ACL', 'debug_warning');
					}
				}else {
					rrdp_system__logging('Critical: Maximum number of client connections has been exhausted. Check system setup ("ulimit -n")!');
					$socket_descriptor = socket_accept($read_socket);
					@socket_write($socket_descriptor, "ERROR: Too many open connections.\r\n");
					@socket_close($socket_descriptor);
				}
			}else if($read_socket == $rrdp_admin) {
			
				/* check if this is a new service client is trying to connect */
				if($rrdp_config['max_admin_cnn'] > sizeof($rrdp_admin_clients)) {
				
					$socket_descriptor = socket_accept($read_socket);

					/* check if the new client has the permission to connect */
					socket_getpeername($socket_descriptor, $ip);
					
					/* take care of IPv6, IPv4 and embedded IPv4 addresses */
					if( in_array($ip, array('127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1') ) ) {
						if(!in_array($socket_descriptor, $rrdp_admin_sockets)) {
							$key = intval($socket_descriptor);
							$rrdp_admin_sockets[$key] = $socket_descriptor;
							$rrdp_admin_clients[$key] = array( 'socket' => $socket_descriptor, 'ip' => $ip, 'privileged' => false, 'debug' => false, 'type' => 'srv' );
							socket_write($socket_descriptor, "\033[0;32m" . $rrdp_config['name'] . ">\033[0m");
							
							rrdp_system__debug('Service connection request #' . $key . '[IP: ' . $ip . '] granted.', 'ACL', 'debug_notice');
						}
				
					}elseif( $ip == $rrdp_config['slave'] ) {
						$key = intval($socket_descriptor);
						$rrdp_admin_sockets[$key] = $socket_descriptor;
						$rrdp_admin_clients[$key] = array( 'socket' => $socket_descriptor, 'ip' => $ip, 'privileged' => false, 'debug' => false, 'type' => 'msr' );
						rrdp_system__debug('RRDtool-Proxy slave connection request #' . $key . '[IP: ' . $ip . '] granted.', 'ACL', 'debug_notice');
					}else {
						@socket_write($socket_descriptor, "ERROR: Access denied.\r\n");
						@socket_close($socket_descriptor);
						rrdp_system__count('aborted_connects');
						rrdp_system__debug('Service connection request #' . $key . '[IP: ' . $ip . '] rejected.', 'ACL', 'debug_warning');
						break;
					}
				}else {
					/* 	we are out of resources - keep these clients in our backlog - 
						!!! Vulnerability !!! How to avoid a denial of service?
					*/	
				}
			}else if(intval($read_socket) == $rrdp_clients[$rrdp_replicator_pid]['ipc']) {
				
				/* === REPLICATOR IPC message === */
				$input = '';
				
				/* handle IPC with the replicator separately */
				while(1) {
					$recv = socket_read($read_socket, 100000, PHP_BINARY_READ );
					if($recv === false) {
						/* replicator connection timeout  */
						rrdp_system__count('connections_timeout');
						rrdp_system__debug('IPC connection timeout to REPLICATOR detected.', 'IPC', 'debug_erorr');	
						/* close IPC child socket */
						
						break;
					}else if($recv == '') {
						/* session closed by replicator */
						if($input) {
							rrdp_system__replicator($input);
							rrdp_system__debug('IPC connection closed by REPLICATOR', 'IPC', 'debug_error');
						}
						break;			
					}else {
						$input .= $recv;
						if (substr($input, -1) == "\n") {
							rrdp_system__replicator($input);
							continue 2;
						}else {
							continue;
						}
					}
				}
				
				
			}else {
				/* handle established connections */
				$index = intval($read_socket);
	
				if(isset($rrdp_ipc_sockets[$index])){
					
					/* === IPC message === */
					$input = '';
					
					while(1) {

						$recv = socket_read($read_socket, 100000, PHP_BINARY_READ );
						if($recv === false) {
							/* timeout  */
							rrdp_system__count('connections_timeout');
							rrdp_system__debug('IPC connection #' . $index . ' timeout detected.', 'IPC', 'debug_erorr');	
							/* close IPC child socket */
							
							break;
						}else if($recv == '') {
							/* session closed by child process */
							if($input) {
								rrdp_system__ipc($input);
								rrdp_system__debug('IPC connection #' . $index . ' closed by child process', 'IPC', 'debug_notice');
							}
							break;			
						}else {
							$input .= $recv;
							if (substr($input, -1) == "\n") {
								rrdp_system__ipc($input);
								continue 2;
							}else {
								continue;
							}
						}
					}
					unset($rrdp_ipc_sockets[$index]);
					continue;

				}else if(isset($rrdp_admin_sockets[$index])) {

					/* === this is a service connection - means default or master-slave === */
					$recv = @socket_read($read_socket, 100000, PHP_NORMAL_READ);

					$msr = ($rrdp_admin_clients[$index]['type'] == 'msr') ? true : false;
					
					rrdp_system__count( (($msr) ? 'msr_bytes_received' : 'srv_bytes_received'), rrdp_system__calc_bytes($recv));
			
					if($recv === false) {
						/* connection lost :( */
						socket_shutdown($read_socket);
						socket_close($read_socket);
						if($msr) {
							### TODO: SEND OUT SNMP TRAP !
							rrdp_system__count('msr_connection_broken');
							rrdp_system__debug('Connection #' . $index . '[IP: ' . $rrdp_admin_clients[$index]['ip'] . '] broken.', 'MSR', 'debug_error');
						}else {
							rrdp_system__count('srv_connection_broken');
						}
						unset($rrdp_admin_clients[$index]);
						continue;
					}else if($recv == "\n") {
						/* end of transmission */	
					}else if($recv) {

						if(isset($options)) unset($options);
						$recv = trim($recv);
				
						if(strpos($recv, " ") !== false) {
							/* correct multiple blanks in sequence automatically */
							$recv = preg_replace("/[[:blank:]]+/"," ",$recv);
							$options = explode(" ", $recv, 2);
							$cmd = $options[0];
							$cmd_options = explode(" ", $options[1]);
						}else {
							$cmd = $recv;
							$cmd_options = '';
						}
						
						if($msr) {
							/* this is a master slave connection */
							if($cmd) {
								if(function_exists('rrdp_msr__' . $cmd)) {
									$rrdp_function = 'rrdp_msr__' . $cmd;
									$rrdp_function($read_socket, $cmd_options);
								}else {
									rrdp_system__socket_write( $read_socket, "% Unknown MSR system command\r\n");
								}
							}
						}else {
							/* this is a normal service client */
							if($cmd) {
								rrdp_system__count('queries_system');

								/* replace all aliases this proxy will also accept */
								$cmd = (isset($rrdp_aliases[$cmd])) ? $rrdp_aliases[$cmd] : $cmd;
								
								if(!$cmd_options[0] && isset($rrdp_help_messages[$cmd]['?'])) {
									rrdp_system__socket_write($read_socket, '% Type "' . $cmd . ' ?" for a list of subcommands' . "\r\n");
										
								}else if( is_array($cmd_options) && end($cmd_options) == "?") {
									/* show help messages */
									$output = "";
									$privileged_mode = ($rrdp_admin_clients[$index]['privileged']) ? 1 : 0 ;
									if(isset($rrdp_help_messages[$cmd]["?"][$privileged_mode])) {
										$root = $rrdp_help_messages[$cmd]["?"][$privileged_mode];
										
										/* find the list of help messages */
										if(sizeof($cmd_options)>1) {
											foreach($cmd_options as $cmd_option ) {
												if(isset($root[$cmd_option])) {
													$root = $root[$cmd_option];
												}else {
													$root = false;
													break;
												}
											}
										}
										if($root){
											ksort($root);
											foreach($root as $cmd => $description) {
												$output .= sprintf("  %-15s %s\r\n", $cmd, (is_array($description) ? $description['info'] : $description) );
											}
											$output .= "\r\n";
										}else {
											$output = "% Unrecognized command\r\n";
										}
										
										rrdp_system__socket_write($read_socket, $output);
									}else {
										rrdp_system__socket_write($read_socket, "% Unrecognized command\r\n");
									}
								}else {
									if(function_exists('rrdp_cmd__' . $cmd)) {
										$rrdp_function = 'rrdp_cmd__' . $cmd;
										$rrdp_function($read_socket, $cmd_options);
									}else {
										rrdp_system__socket_write( $read_socket, "% Invalid input detected\r\n");
									}
								}
							}
							/* return prompt */
							rrdp_system__return_prompt($read_socket);
						}
					}else {
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
	}else {
		continue;
	}
}

/* ####################################   MSR FUNCTIONS   #################################### */
/* alive message - master and slave are playing ping pong */
function rrdp_msr__ping($i) {
	rrdp_system__socket_write($i, "pong\r\n", 'msr_bytes_sent');
	return;
}

function rrdp_msr__block_write() {
	global $rrdp_msr_buffer, $rrdp_remote_proxies;

	$current_time = time();
	$current_timeframe = $current_time + $current_time % 10;
	
	if(sizeof($rrdp_remote_proxies)>0) {
		if(sizeof($rrdp_msr_buffer)>0) {
			foreach($rrdp_msr_buffer as $timeframe => $msr_commands) {
				if($timeframe < $current_timeframe) {

					$buffer = '';
					foreach($msr_commands as $id => $cmd) {
						$buffer .= $id . "\t" . $cmd . "\r\n";
					}
					//$buffer = gzencode($buffer,1);

					foreach($rrdp_remote_proxies as $ip => $fingerprint) {
						$msr_sub_folder = './msr/'. $ip;
						if(!is_dir($msr_sub_folder)) mkdir($msr_sub_folder);
						$fp = fopen($msr_sub_folder . '/' . $timeframe, 'a');
						fwrite($fp, $buffer);
					}
					unset($rrdp_msr_buffer[$timeframe]);
				}
			}
		}
	}else {
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
	
	if(!isset($rrdp_config['last_system_check'])) {
		$rrdp_config['last_system_check'] = $current_time;
		$first_run = true;
	}	
	
	if($first_run || $rrdp_config['last_system_check'] < ($current_time - 30) ) {
		
		/* Status - Filesystem RRA */
		if(is_dir($rrdp_config['path_rra'])) {
		
			$rra_disk_status = shell_exec( "df -k " . $rrdp_config['path_rra'] . " | sed 1d | awk '{printf \"size:\" $2 \" used:\" $3 \" avail:\" $4}'" );
			$disk_states = explode(' ', $rra_disk_status);
			if( is_array( $disk_states ) && sizeof($disk_states)>0 ) {
				foreach($disk_states as $disk_state) {
					list($type, $value) = explode(':', $disk_state);
					if(isset($rrdp_status['rra_disk_' . $type])) {
						$rrdp_status['rra_disk_' . $type] = $value;
					}
				}
			}
			
			#TODO - SNMPTrap if necessary
			
		}
		
		/* Status - Filesystem MSR */
		$msr_disk_status = shell_exec( "df -k ./msr | sed 1d | awk '{printf \"size:\" $2 \" used:\" $3 \" avail:\" $4}'" );
		$disk_states = explode(' ', $msr_disk_status);
		if( is_array( $disk_states ) && sizeof($disk_states)>0 ) {
			foreach($disk_states as $disk_state) {
				list($type, $value) = explode(':', $disk_state);
				if(isset($rrdp_status['msr_disk_' . $type])) {
					$rrdp_status['msr_disk_' . $type] = $value;
				}
			}
		}
		# TODO - SNMPtrap if necessary
	
	
		# TODO - Check backlog and stream ressources
		
		$rrdp_config['last_system_check'] = $current_time;
	}
	
	/* place for improvements like SNMPtraps */
	
	return;
}


function rrdp_system__encryption_init() {
	global $rrdp_encryption, $microtime_start;

	$rsa = new \phpseclib\Crypt\RSA();
	
	if(!file_exists('./include/public.key') || !file_exists('./include/private.key')) {
		$keys = $rsa->createKey(2048);
		$rrdp_encryption['public_key'] = $keys['publickey'];
		$rrdp_encryption['private_key'] = $keys['privatekey'];
		
		file_put_contents('./include/public.key', $rrdp_encryption['public_key']);
		file_put_contents('./include/private.key', $rrdp_encryption['private_key']);
	}
	$rrdp_encryption['public_key'] = file_get_contents('./include/public.key');
	rrd_system__system_boolean_message( 'init: RSA public key', $rrdp_encryption['public_key'], true );
	
	$rrdp_encryption['private_key'] = file_get_contents('./include/private.key');
	rrd_system__system_boolean_message( 'init: RSA private key', $rrdp_encryption['private_key'], true);
		
	$rsa->loadKey($rrdp_encryption['public_key']);
	$rrdp_encryption['public_key_fingerprint'] = $rsa->getPublicKeyFingerprint();
}

function rrdp_system__replicator(&$input) {
	global $rrdp_client, $rrd_config;
	
	$status = @unserialize($input);
	
	if($status !== false && $status['type']) {
		
		switch($status['type']) {
			case 'debug':
				rrdp_system__debug( $status['debug']['msg'], $status['debug']['category'], $status['debug']['level'], 'replicator' );
			break;
			case 'status':
				if( $status['status'] == 'running' ) {
					@socket_listen($rrdp_client);
				}elseif ($status['status'] == 'synchronizing') {
					@socket_shutdown($rrdp_client);					
				}
			break;
			default:
				#TODO undefined state
			break;
		}
	}else {
		/* internal IPC error */
		#TODO
	}
}


function rrdp_system__ipc(&$input) {

	global $rrdp_msr_buffer;

	$child_status = unserialize($input);	
	
	/* handle debug messages */
	if(isset($child_status['debug'])) {
		rrdp_system__debug( $child_status['debug']['msg'], $child_status['debug']['category'], $child_status['debug']['level'], $child_status['debug']['environment'] );
	}
	
	/* update msr buffer */
	if(isset($child_status['msr_commands'])) {
		foreach($child_status['msr_commands'] as $timeframe => $msr_commands) {
			if(!isset($rrdp_msr_buffer[$timeframe])) {
				$rrdp_msr_buffer[$timeframe] = array();
			}
			$rrdp_msr_buffer[$timeframe] += $msr_commands;
		}
	}

	/* update server stats */
	foreach($child_status as $status_variable => $status_value) {
		rrdp_system__count( $status_variable, $status_value );
	}
	
	switch($child_status['status']) {
		case 'CLOSEDOWN_BY_SIGNAL':
		case 'CLOSEDOWN_BY_TIMEOUT':
		case 'CLOSEDOWN_BY_VIOLATION':
		case 'CLOSEDOWN_BY_CLIENT_CMD':
		case 'CLOSEDOWN_BY_CLIENT_DROP':
		case 'CLOSEDOWN_BY_CLIENT_AUTH':
		case 'CLOSEDOWN_BY_ENCRYPTION':
			rrdp_system__count( 'proc_' . strtolower($child_status['status']) );
			
			break;
		default:
			/* process is still running */
			break;
	}
}

function rrd_system__system_die($msg='') {
	global $ppid;
	
	if($ppid) @posix_kill( $ppid , SIGTERM);
	die($msg);	
}

function rrd_system__system_boolean_message($msg, $boolean_state, $exit=false) {
	global $color_theme, $microtime_start;

	$microtime_end = microtime(true);
	$color = $boolean_state ? $color_theme['debug_normal'] : (($exit == true) ? $color_theme['debug_error'] : $color_theme['debug_critical']);
	$status = $boolean_state ? '[OK]' : '[FAILED]';

	$max_msg_length = 80 - 10 - strlen($status) - 1;
	
	if(strlen($msg) > $max_msg_length ) {
		$msg = substr($msg, 0, $max_msg_length-3) . '...';
	}
	
	fwrite(STDOUT, sprintf("\r\n[%.5f] %-{$max_msg_length}s \033[0;{$color}m%s\033[0m", ($microtime_end - $microtime_start), $msg, $status));
	if($boolean_state == false && $exit == true) rrd_system__system_die("\r\n");
}

function rrd_system__system_message($microtime_start, $msg, $level='debug_normal', $exit=false) {
	global $color_theme;

	$microtime_end = microtime(true);
	fwrite(STDOUT, sprintf("\r\n[%.5f] \033[0;{$color_theme[$level]}m%s\033[0m", ($microtime_end - $microtime_start), $msg));
	if($exit) die("\r\n");
}

function rrd_system__read_config_option($param = false) {
	global $rrdp_config;
	if( $param && array_key_exists($param, $rrdp_config) ) {
		return $rrdp_config[$param];
	}else {
		return false;
	}
}

function rrdp_system__calc_bytes(&$str) {
	return ( ini_get('mbstring.func_overload') ? mb_strlen($str , '8bit') : strlen($str) );
}

function rrdp_system__count($variable, $value=1) {
	global $rrdp_status;
	if(isset($rrdp_status[$variable])) {
		/* use 32 bit counters only */
		$rrdp_status[$variable] = (($rrdp_status[$variable] + $value) >=  2147483647)
									? $rrdp_status[$variable] - 2147483647 + $value
									: $rrdp_status[$variable] + $value;
		return;
	}
	return false;
}

function rrdp_system__update($variable) {
	global $rrdp_admin_clients, $rrdp_status;
	switch($variable) {
		case 'max_used_connections':
			if(sizeof($rrdp_admin_clients)> $rrdp_status[$variable]) {
				$rrdp_status[$variable] = sizeof($rrdp_admin_clients);
			}
		break;
	}
	return;
};

function rrdp_system__debug( $msg, $category, $level, $environment = 'proxy') {
	global $rrdp_config, $rrdp_admin_clients, $rrdp_admin_sockets, $color_theme;
	
	if(isset($rrdp_config['debug'][$environment]) && $rrdp_config['debug'][$environment] === true ) {
		foreach($rrdp_admin_clients as $key => $rrdp_admin_client) {
			if( isset($rrdp_admin_client['debug'][$environment]) && $rrdp_admin_client['debug'][$environment] === true ) {
				/* write debug message to socket and return default prompt for proviledge mode */
				rrdp_system__socket_write( $rrdp_admin_sockets[$key], "\r\n\033[0;{$color_theme[$level]}m[" . $category . "] " . $msg . "\r\n\033[0;{$color_theme['debug_prompt']}m" . $rrdp_config['name'] . '#' . "\033[0m");
			}
		}
	}
}

function rrdp_system__return_prompt($socket) {
	global $rrdp_admin_clients, $rrdp_config, $color_theme;
	
	$i = intval($socket);
	
	$prompt = "\033[0;" . (($rrdp_admin_clients[$i]['debug']) ? $color_theme['debug_prompt'] : $color_theme['prompt']) .  "m" . $rrdp_config['name'] . (($rrdp_admin_clients[$i]['privileged']) ? '#' :'>') . "\033[0m";
	rrdp_system__socket_write($socket, $prompt);
}

function rrdp_system__socket_write( $socket, $output, $counter = 'bytes_sent') {
	if($return = @socket_write($socket, $output, strlen($output)) ) {
		rrdp_system__count($counter, rrdp_system__calc_bytes($output));
	}
	return $return;
}


function rrdp_system__socket_close($socket, $msg = false, $force = false) {

	if($msg) {
		rrdp_system__socket_write($socket, $msg);
	}

	if($force) {
		$return = @socket_close($socket);
	}else {
		@socket_shutdown($socket, 2);
		$return = @socket_close($socket);
	}
	return $return;
}

function rrdp_system__status_live($variable) {
	global $rrdp_admin_clients, $rrdp_ipc_sockets, $rrdp_config;
	
	$status = 'n/a';
	switch($variable) {
		case 'threads_connected':
			$status = sizeof($rrdp_admin_clients);
		break;
		case 'uptime':
			$status = time() - $rrdp_config['start'];
		break;
		case 'memory_usage':
			$status = memory_get_usage();
		break;
		case 'memory_peak_usage':
			$status = memory_get_peak_usage();
		break;
		case 'connections_open':
			$status = sizeof($rrdp_ipc_sockets);
		break;
	}
	return $status;
}

function rrdp_system__convert2bytes($val) {

    $val = trim($val);
    $last = strtolower($val[strlen($val)-1]);
    switch($last) {
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }
    return $val;
}

function rrdp_system__logging($msg) {
	global $rrdp_config, $rrdp_logging_buffer;
	/* keep an eye on the number of rows we are allowed to store */
	if( sizeof($rrdp_logging_buffer) == $rrdp_config['logging_buffer'] ) {
		$waste = array_shift($rrdp_logging_buffer);
		unset($waste);
	}
	$rrdp_logging_buffer[] = date(DATE_RFC822) . "    " . $msg;
	return;
}

/* ####################################   SYSTEM COMMANDS   #################################### */
function rrdp_cmd__clear( $socket, $args) {
	global $rrdp_admin_clients, $rrdp_help_messages, $rrdp_status;
	
	$i = intval($socket);
	if( $rrdp_admin_clients[$i]['privileged'] === true ) {
		if(sizeof($args) == 1) {
			if(isset($rrdp_help_messages['clear']['?'][1][ $args[0] ])) {
				$rrdp_function = 'rrdp_cmd__clear_' . $args[0];
				if(function_exists($rrdp_function)) {
					$rrdp_function($socket);
				}
			}else {
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
			}
		}else {
			rrdp_system__socket_write($socket, "% Unrecognized command\r\n");	
		}
		return;
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	return;
}

function rrdp_cmd__clear_counters($socket) {
	global $rrdp_admin_clients, $rrdp_status;
	/* only privileged users are allowed to shut down the proxy from remote */
	foreach($rrdp_status as $variable => $value ) {
		if($value !== 'live') {
			$rrdp_status[$variable] = 0;
		}
	}
	rrdp_system__logging("Counters have been cleared");
	return;
}

function rrdp_cmd__clear_logging($socket) {
	global $rrdp_admin_clients, $rrdp_logging_buffer;
	$rrdp_logging_buffer = array();
	return;
}

function rrdp_cmd__enable( $socket, $args) {
	global $rrdp_admin_clients;
	if(!$args) {
		$i = intval($socket);
		/* only a local connected user is allowed to switch to enhanced mode */
		if(in_array($rrdp_admin_clients[$i]['ip'], array('127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1'))) {
			$rrdp_admin_clients[$i]['privileged'] = true;
			return;
		}
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Privileged mode is restricted to localhost only\r\n");
	return;
}

function rrdp_cmd__disable( $socket, $args) {
	global $rrdp_admin_clients;
	if(!$args) {
		$i = intval($socket);
		/* client would like to return to unprivileged mode */
		$rrdp_admin_clients[$i]['privileged'] = false;
		return;
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	return;
}

function rrdp_cmd__quit( $socket, $args) {
	global $rrdp_admin_clients, $rrdp_admin_sockets;
	if(!$args) {
		$i = intval($socket);
		/* client would like to regularly close the connection */
		socket_shutdown($rrdp_admin_clients[$i]['socket'], 2);
		socket_close($rrdp_admin_clients[$i]['socket']);
		unset($rrdp_admin_clients[$i]);
		unset($rrdp_admin_sockets[$i]);
	}else {
		/* unknown command */
		rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	}
	return;
}

function rrdp_cmd__shutdown( $socket, $args) {
	global $rrdp_clients, $rrdp_admin_clients, $rrdp_ipc_sockets, $rrdp_client, $rrdp_admin, $rrdp_replicator_pid, $rrdcached_pid, $microtime_start;
	
	if(!$args) {
		if( $socket === 'SIGTERM' || ( isset($rrdp_admin_clients[intval($socket)]) && $rrdp_admin_clients[intval($socket)]['privileged'] === true ) ) {
		
			$microtime_start = microtime(true);
			
			fwrite(STDOUT, "\033[2J\033[;H\033[1;33;44m   RRDtool Proxy Server Shutdown                                                 \033[0m" . PHP_EOL);

			socket_close($rrdp_client);
			rrd_system__system_boolean_message( 'close: Client socket', true, false );
			
			if($rrdcached_pid) {
				rrd_system__system_boolean_message( ' stop: RRDCached daemon', true, false );
				posix_kill($rrdcached_pid, SIGTERM);
				while(1){
					$child_status = pcntl_waitpid($rrdcached_pid, $status);
					if($child_status == -1 || $child_status > 0) {
						rrd_system__system_boolean_message( " stop: [PID:$rrdcached_pid] RRDCached daemon stopped", 1, false);
						break;
					}else {
						sleep(1);
					}
				}
			}

			if($rrdp_replicator_pid) {
				$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
				if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
					@socket_write( $rrdp_ipc_sockets[ $key ][1], "shutdown\r\n");
				}
				$child_status = pcntl_waitpid($rrdp_replicator_pid, $status);
				if($child_status == -1 || $child_status > 0) {
					unset($rrdp_clients[$rrdp_replicator_pid]);
					rrd_system__system_boolean_message( " stop: [PID:$rrdp_replicator_pid] Replicator stopped", 1, false);
				}else {
					posix_kill($rrdp_replicator_pid, SIGTERM);
				}
			}
			
			foreach($rrdp_clients as $child_pid => $client_ip) {
			
				$key = $rrdp_clients[$child_pid]['ipc'];
				if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
					@socket_write( $rrdp_ipc_sockets[ $key ][1], "shutdown\r\n");
				}
				
				$child_status = pcntl_waitpid($child_pid, $status);
				if($child_status == -1 || $child_status > 0) {
					unset($rrdp_clients[$child_pid]);
					rrd_system__system_boolean_message( " stop: [PID:$child_pid] Child process stopped", 1, false);
				}else {
					posix_kill($child_pid, SIGTERM);
				}
			}

			socket_close($rrdp_admin);
			rrd_system__system_boolean_message( 'close: Service socket', true, false );			

			foreach($rrdp_admin_clients as $index => $rrdp_admin_client) {
				if($index != $i) {
					@socket_write($rrdp_admin_client['socket'], "Shutting down ... bye ;) \r\n");
				}
				@socket_close($rrdp_admin_clients['socket']);
				rrd_system__system_boolean_message( " stop: [SOCKET:" . intval($rrdp_admin_client['socket']) . "] Service connection closed", 1, false);
				
			}

			fwrite(STDOUT, PHP_EOL . PHP_EOL . '  Bye! :)' . PHP_EOL . PHP_EOL . '________________________________________________________________________________' . PHP_EOL);
			exit;
		}
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	return;
}

function rrdp_cmd__list( $socket, $args) {
	global $rrdp_admin_clients, $rrdp_help_messages;
	
	if(!$args) {
		$i = intval($socket);
		$output = '';
		foreach($rrdp_help_messages['?'][ intval($rrdp_admin_clients[$i]['privileged']) ] as $cmd => $description) {
			$output .= sprintf("  %-15s %s\r\n", $cmd, $description);
		}
		$output .= "\r\n";
		rrdp_system__socket_write($socket, $output);
	}else {
		rrdp_system__socket_write($socket, "% Type \"?\" for a list of commands\r\n");
	}
	return;	
}

function rrdp_cmd__show( $socket, $args) {
	global $rrdp_admin_clients, $rrdp_help_messages;
	
	if(sizeof($args) >= 1) {
		$i = intval($socket);
		if(isset($rrdp_help_messages['show']['?'][ intval($rrdp_admin_clients[$i]['privileged']) ][ $args[0] ])) {
			$rrdp_function = 'rrdp_cmd__show_' . $args[0];
			if(function_exists($rrdp_function)) {
				$rrdp_function($socket, $args);
			}
		}else {
			rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
		}
	}else {
		rrdp_system__socket_write($socket, "% Unrecognized command\r\n");	
	}

	return;
}

function rrdp_cmd__show_threads($socket) {
	global $rrdp_admin_clients;
	
	$output = "\r\n" . sprintf(" %-10s %-15s %-3s\r\n", 'ID', 'IP', 'Privileged Mode');
	foreach($rrdp_admin_clients as $client) {
		$output .= sprintf(" %-10s %-15s %-3s\r\n", '#' . strval(intval($client['socket'])), $client['ip'], ($client['privileged'] ? 'yes' : 'no') );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_processes($socket) {
	global $rrdp_clients;
	
	$output = "\r\n" . sprintf(" %-10s %-15s \r\n", 'PID', 'IP');
	foreach($rrdp_clients as $child_pid => $client) {
		$output .= sprintf(" %-10s %-15s \r\n", '#' . $child_pid, $client['ip'] );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_counters($socket) {
	global $rrdp_admin_clients, $rrdp_status;
	
	$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'Variable', 'Value');
	foreach($rrdp_status as $variable => $value) {
		$output .= sprintf(" %-35s %-12s \r\n", ucfirst($variable), (($value === 'live') ? rrdp_system__status_live($variable) : $value) );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_variables($socket) {
	global $rrdp_admin_clients, $rrdp_config;
	ksort($rrdp_config);
	$output = "\r\n" . sprintf(" %-35s %s \r\n\r\n", 'Name', 'Value');
	foreach($rrdp_config as $variable => $value) {
		if($variable == 'encryption') continue;
		$output .= sprintf(" %-35s %s \r\n", $variable, is_array($value) ? implode(', ', $value) : (($value === false || $value === null ) ? 'disabled' : $value) );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_logging($socket) {
	global $rrdp_logging_buffer;
	
	$output = "\r\n";
	foreach($rrdp_logging_buffer as $msg) {
		$output .= sprintf(" %s \r\n", $msg );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_clients($socket, $args) {
	global $rrdp_config, $rrdp_encryption, $rrdp_remote_clients;
	$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'IP Address', 'Fingerprint');
	foreach($rrdp_remote_clients as $ip => $fingerprint) {
		$output .= sprintf(" %-35s %s \r\n", $ip, $fingerprint );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_servers($socket, $args) {
	global $rrdp_config, $rrdp_encryption, $rrdp_remote_proxies;
	$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'IP Address', 'Fingerprint');
	foreach($rrdp_remote_proxies as $ip => $fingerprint) {
		$output .= sprintf(" %-35s %s \r\n", $ip, $fingerprint );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;	
}

function rrdp_cmd__show_rsa($socket, $args) {
	global $rrdp_config, $rrdp_encryption, $rrdp_remote_clients;
		
	if(isset($args[1])) {
		switch($args[1]) {
			case 'publickey':
				$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'Variable', 'Value');
				$output .= sprintf(" %-35s %s \r\n", 'Public Key', str_replace( "\r\n", "\r\n                                     ", $rrdp_encryption['public_key']));
				$output .= sprintf(" %-35s %s \r\n", 'Fingerprint', $rrdp_encryption['public_key_fingerprint']);
				$output .= "\r\n";	
				rrdp_system__socket_write($socket, $output);
			break;
			default:
				print $args[1];
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
			break;
		}
	}else {
		rrdp_system__socket_write($socket, '% Type "' . $cmd . ' ?" for a list of subcommands' . "\r\n");
	}

}

function rrdp_cmd__show_msr($socket, $args) {
	global $rrdp_admin_clients, $rrdp_config, $rrdp_msr_buffer;
	
	if(isset($args[1])) {
		switch($args[1]) {
			case 'buffer':
				if(sizeof($rrdp_msr_buffer)>0) {
					foreach($rrdp_msr_buffer as $timeframe => $msr_commands) {
						rrdp_system__socket_write($i, "$timeframe:\r\n");
						$output = '';
						foreach($msr_commands as $timestamp => $msr_command) {
							$output .= sprintf(" %-25s %s \r\n", $timestamp, $msr_command);
						}
						rrdp_system__socket_write($socket, $output . "\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, "no entries found\r\n");
				}
			break;
			case 'health':
			break;
			case 'status':
			break;
			default:
				print $args[1];
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
			break;
		}
	}else {
		rrdp_system__socket_write($socket, '% Type "' . $cmd . ' ?" for a list of subcommands' . "\r\n");
	}
}

function rrdp_cmd__show_version($socket=false) {
	global $rrdp_config, $rrdp_clients, $rrdp_encryption;
	
	$runtime = time() - $rrdp_config['start']; 
	$days = floor( $runtime / 86400 );
	$hours = floor( ( $runtime - $days * 86400 ) / 3600 );
	$minutes = floor( ( $runtime - $days * 86400 - $hours * 3600 ) / 60 );
	$seconds = $runtime - $days * 86400 - $hours * 3600 - $minutes * 60;
	
	$memory_limit = rrdp_system__convert2bytes(ini_get('memory_limit'));
	$memory_used = memory_get_usage();
	$memory_usage = round(($memory_used/$memory_limit)*100, 8);
	
	$output = PHP_EOL
			. "#     ___           _   _     __    __    ___     ___                     " . PHP_EOL
			. "#    / __\__ _  ___| |_(_)   /__\  /__\  /   \   / _ \_ __ _____  ___   _ " . PHP_EOL
			. "#   / /  / _` |/ __| __| |  / \// / \// / /\ /  / /_)/ '__/ _ \ \/ / | | |" . PHP_EOL
			. "#  / /__| (_| | (__| |_| | / _  \/ _  \/ /_//  / ___/| | | (_) >  <| |_| |" . PHP_EOL
			. "#  \____/\__,_|\___|\__|_| \/ \_/\/ \_/___,'   \/    |_|  \___/_/\_\\__, |" . PHP_EOL
			. "#                                                                   |___/ " . PHP_EOL
			. PHP_EOL
			." RRDtool Proxy v" . RRDP_VERSION . PHP_EOL
			." Copyright (C) 2004-2017 The Cacti Group" . PHP_EOL
			." {$rrdp_config['name']} uptime is $days days, $hours hours, $minutes minutes, $seconds seconds" . PHP_EOL
			." Memory usage " . $memory_usage . " % (" . $memory_used . "/" . $memory_limit ." in bytes)" . PHP_EOL
			." " . $rrdp_encryption['public_key_fingerprint'] . PHP_EOL
			." Process ID: " .  posix_getpid() . PHP_EOL
			." Session usage (" . sizeof($rrdp_clients) . '/' . $rrdp_config['max_cnn'] . ")" . PHP_EOL . PHP_EOL
			." Server IP [" . gethostbyname(php_uname('n')) . "]" . PHP_EOL
			." Administration: [" . "localhost \t:" . $rrdp_config['port_admin'] . ']' . PHP_EOL
			." Replication:    [" . ($rrdp_config['address'] != '0.0.0.0' ? $rrdp_config['address'] : 'any') . "\t:" . $rrdp_config['port_server'] . ']' . PHP_EOL
			." Clients:        [" . ($rrdp_config['address'] != '0.0.0.0' ? $rrdp_config['address'] : 'any') . "\t:" . $rrdp_config['port_client'] . ']' . PHP_EOL
			. PHP_EOL;
	
	if(is_resource($socket)) {
		rrdp_system__socket_write($socket, $output);
	}else {
		fwrite(STDOUT, $output);
	}
	return;
}

function rrdp_cmd__debug( $socket, $args) {
	global $rrdp_replicator_pid, $rrdp_admin_clients, $rrdp_help_messages, $rrdp_config, $rrdp_clients, $rrdp_ipc_sockets;
	
	if(sizeof($args) == 2) {
		$i = intval($socket);
		if(isset($rrdp_help_messages['debug']['?'][ intval($rrdp_admin_clients[$i]['privileged']) ][ $args[0] ])) {
			$process = $args[0];
			switch($args[1]) {
			case 'on':	
				$rrdp_admin_clients[$i]['debug'][$process] = true;
				$orginal_state = (isset($rrdp_config['debug'][$process]) && $rrdp_config['debug'][$process] === true ) ? true : false;
				$rrdp_config['debug'][$process] = true;
				
				if($process == 'replicator') {
					if($rrdp_replicator_pid) {
						$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
						if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
							@socket_write( $rrdp_ipc_sockets[ $key ][1], "debug_on\r\n");
						}
					}
				}
				
				if($orginal_state === false) {
					rrdp_system__socket_write($socket, "GLOBAL DEBUG mode for $process process started.\r\n" );
				}
			break;
			case 'off':
				unset($rrdp_admin_clients[$i]['debug'][$process]);
				$orginal_state = (isset($rrdp_config['debug'][$process]) && $rrdp_config['debug'][$process] === true ) ? true : false;
				
				$debug_sessions_running = false;
				foreach($rrdp_admin_clients as $rrdp_admin_client) {
					if(isset($rrdp_admin_client['debug'][$process])) {
						$debug_sessions_running = true;
						break;
					}
				}

				if($process == 'replicator') {
					if($rrdp_replicator_pid) {
						$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
						if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
							@socket_write( $rrdp_ipc_sockets[ $key ][1], "debug_off\r\n");
						}
					}
				}

				if($orginal_state === true && $debug_sessions_running === false) {
					$rrdp_config['debug'][$process] = false;
					rrdp_system__socket_write($socket, "GLOBAL DEBUG mode for $process process stopped.\r\n" );
				}
				
			break;
			default:
				print $args[1];
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
			break;
		}
		}else {
			rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
		}
	}else {
		rrdp_system__socket_write($socket, "% Unrecognized command\r\n");	
	}
	return;
}

function rrdp_cmd__set( $socket, $args) {
	global $rrdp_admin_clients, $rrdp_help_messages;
	
	if(sizeof($args) >= 1) {
		$i = intval($socket);
		if(isset($rrdp_help_messages['set']['?'][ intval($rrdp_admin_clients[$i]['privileged']) ][ $args[0] ])) {
			$rrdp_function = 'rrdp_cmd__set_' . $args[0];
			if(function_exists($rrdp_function)) {
				$rrdp_function($socket, $args);
			}
		}else {
			rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
		}
	}else {
		rrdp_system__socket_write($socket, "% Unrecognized command\r\n");	
	}
	return;
}

function rrdp_cmd__set_cluster($socket, $args) {
	global $rrdp_config, $rrdp_encryption, $rrdp_remote_proxies, $rrdp_clients, $rrdp_replicator_pid, $rrdp_ipc_sockets;
	if(isset($args[1])) {
		switch($args[1]) {
			case 'add':		
				if( sizeof($args) == 5 ) {
					
					/* Verify IP address */
					if(filter_var($args[2],FILTER_VALIDATE_IP) === false){
						rrdp_system__socket_write($socket, "% Invalid IP adress\r\n");
						break;
					}
					
					if(filter_var($args[3], FILTER_VALIDATE_REGEXP, array('options'=>array('regexp'=>'/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/'))) === false) {
						rrdp_system__socket_write($socket, "% Invalid PORT. Range: [1024-65535]\r\n");
						break;
					}

					if(filter_var($args[4], FILTER_VALIDATE_REGEXP, array("options"=>array("regexp"=>"/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/"))) === false) {
						rrdp_system__socket_write($socket, "% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]\r\n");
						break;
					}
	
					/* if the server IP has already been defined, then we its settings */
					$rrdp_remote_proxies[$args[2]] = array('port' => $args[3], 'fingerprint' => $args[4]);
					
					/* update local list of servers */
					file_put_contents('./include/proxies', '<?php $rrdp_remote_proxies = ' . var_export($rrdp_remote_proxies, true) . ';');
					
					/* create a new subfolder for this peer (if not already existing) to support data replication */
					if(!is_dir('./msr/' . $args[2])) {
						mkdir('./msr/' . $args[2]);
					}
				
					/* inform REPLICATOR */
					$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
					if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
						@socket_write( $rrdp_ipc_sockets[ $key ][1], "reload_proxy_list\r\n");
					}

				}else {
					rrdp_system__socket_write($socket, "% set cluster add <IP> <Port> <Fingerprint>\r\n");
				}
	
			break;
			case 'remove':
				
				if( isset($args[2]) ) {
				
					if(isset($rrdp_remote_proxies[$args[2]])) {
						unset($rrdp_remote_proxies[$args[2]]);
						/* destroy replication data */
						if(is_dir('./msr/' . $args[2])) {
							rmdir('./msr/' . $args[2]);
						}
						/* update local list of clients */
						file_put_contents('./include/proxies', '<?php $rrdp_remote_proxies = ' . var_export($rrdp_remote_proxies, true) . ';');
						
						/* inform REPLICATOR */
						$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
						if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
							@socket_write( $rrdp_ipc_sockets[ $key ][1], "reload_proxy_list\r\n");
						}
					}else {
						rrdp_system__socket_write($socket, "% Unknown server IP address\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, "% set server remove <IPv4|IPv6>\r\n");
				}
			break;
			case 'update':
				
				if( isset($args[2]) ) {
				
					if(isset($rrdp_remote_proxies[$args[2]])) {
						unset($rrdp_remote_proxies[$args[2]]);
						/* destroy replication data */
						if(is_dir('./msr/' . $args[2])) {
							rmdir('./msr/' . $args[2]);
						}
						/* update local list of clients */
						file_put_contents('./include/proxies', '<?php $rrdp_remote_proxies = ' . var_export($rrdp_remote_proxies, true) . ';');
						
						/* inform REPLICATOR */
						$key = $rrdp_clients[$rrdp_replicator_pid]['ipc'];
						if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {	
							@socket_write( $rrdp_ipc_sockets[ $key ][1], "reload_proxy_list\r\n");
						}			
					}else {
						rrdp_system__socket_write($socket, "% Unknown server IP address\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, "% set server remove <IPv4|IPv6>\r\n");
				}
			break;
			default:
				print $args[1];
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
			break;
		}
	}else {
		rrdp_system__socket_write($socket, '% Type "' . $cmd . ' ?" for a list of subcommands' . "\r\n");
	}
	return;
}

function rrdp_cmd__set_client($socket, $args) {
	global $rrdp_config, $rrdp_encryption, $rrdp_remote_clients;
	if(isset($args[1])) {
		switch($args[1]) {
			case 'add':		
				if( isset($args[2]) && isset($args[3]) ) {
					
					/* Verify IP address */
					if(filter_var($args[2],FILTER_VALIDATE_IP) === false){
						rrdp_system__socket_write($socket, "% Invalid IP adress\r\n");
						break;
					}
					
					/* Verify Fingerprint Format */
					$fingerprint = trim($args[3]);
					preg_match_all("/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/", $args[3], $output_array);
					
					if( isset($output_array[0][0]) && $output_array[0][0] == $args[3] ) {
					
						/* if the client IP has already been defined, then overwrite its fingerprint */
						$rrdp_remote_clients[$args[2]] = $args[3];
						/* update local list of clients */
						file_put_contents('./include/clients', '<?php $rrdp_remote_clients = ' . var_export($rrdp_remote_clients, true) . ';');
				
					}else {
					
						rrdp_system__socket_write($socket, "% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, "% set client add <IP> <Fingerprint>\r\n");
				}
	
			break;
			case 'remove':
				
				if( isset($args[2]) ) {
				
					if(isset($rrdp_remote_clients[$args[2]])) {
						unset($rrdp_remote_clients[$args[2]]);
						/* update local list of clients */
						file_put_contents('./include/clients', '<?php $rrdp_remote_clients = ' . var_export($rrdp_remote_clients, true) . ';');
					}else {
						rrdp_system__socket_write($socket, "% Unknown client IP address\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, "% set client remove <IPv4|IPv6>\r\n");
				}
	
			break;			
			default:
				print $args[1];
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
			break;
		}
	}else {
		rrdp_system__socket_write($socket, '% Type "' . $cmd . ' ?" for a list of subcommands' . "\r\n");
	}
	return;
}

function rrdp_cmd__set_rsa($socket, $args) {
	global $rrdp_config, $rrdp_encryption, $rrdp_remote_clients;
		
	if(isset($args[1])) {
		switch($args[1]) {
			case 'keys':

				$rsa = new \phpseclib\Crypt\RSA();
				$keys = $rsa->createKey(2048);
				$rrdp_encryption['public_key'] = $keys['publickey'];
				$rrdp_encryption['private_key'] = $keys['privatekey'];
		
				file_put_contents('./include/public.key', $rrdp_encryption['public_key']);
				file_put_contents('./include/private.key', $rrdp_encryption['private_key']);
		
				$rsa->loadKey($rrdp_encryption['public_key']);
				$rrdp_encryption['public_key_fingerprint'] = $rsa->getPublicKeyFingerprint();
			
				rrdp_cmd__show_rsa($socket, array( 1 => 'publickey' ) );
			
			break;
			default:
				print $args[1];
				rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
			break;
		}
	}else {
		rrdp_system__socket_write($socket, '% Type "' . $cmd . ' ?" for a list of subcommands' . "\r\n");
	}
	return;
}

/** 
  * Handle a new client connection 
  */ 
function handle_client($ssock, $csock, $ipc_sockets) 
{ 
    GLOBAL $__server_listening, $rrdp_status, $rrdcached_pid;

	list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
	
	#rrdp_system__logging('DEBUG: Client Handler started.');
    
    $pid = pcntl_fork(); 

    if ($pid == -1) { 
        
		/* === fork failed === */ 
        rrdp_system__logging('DEBUG: Client Handler - Fork failed.');
        die; 										//TODO: handling missing
        
	
	}elseif ($pid == 0) { 

	    	/* === child === */   	
	    	include('./lib/functions.php');
		include('./lib/client.php');
	     
		/* stop main loop, because we have to reuse the same code base */
		$__server_listening = false;

	    	/* free up unused resources */
		socket_close($ssock);
		socket_close($ipc_socket_child);
				
		/* overwrite array $rrdp_status to do our own calculations */
		$rrdp_status = array( 'bytes_received' => 0, 'bytes_sent' => 0, 'queries_rrdtool_total' => 0, 'queries_rrdtool_valid' => 0, 'queries_rrdtool_invalid' => 0, 'rrd_pipe_broken' => 0, 'status' => 'RUNNING');
		
		/* handle client parent and child communication */
        	interact($csock, $ipc_socket_parent); 

		/* close client connection */
		@socket_shutdown($csock);
		@socket_close($csock);

		/* send IPC update message to parent */
		socket_write( $ipc_socket_parent, serialize($rrdp_status));

		/* shutdown connection to parent */
		socket_shutdown($ipc_socket_parent);
		socket_close($ipc_socket_parent);
		
		/* kill the process itself */
		exit(0);
    
	}else { 
		/* === parent === */
		
		/* free up unused resources */
		socket_close($ipc_socket_parent);
		socket_close($csock);
		
		/* return child's process identifier */ 
		return $pid;
	} 
} 

/** 
  * Handle a new server connection 
  */ 
function handle_replicator($ipc_sockets) 
{ 
    GLOBAL $__server_listening, $rrdp_status; 

	list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
    
    $pid = pcntl_fork(); 

    if ($pid == -1) { 
        
		/* === fork failed === */ 
        die; 										//TODO: handling missing
	
	}elseif ($pid == 0) { 

		/* === child === */ 
		include('./lib/functions.php');
		include('./lib/replicator.php');
        
		set_error_handler("__errrorHandler");
		
		/* stop main loop, because we have to reuse the same code base */
		$__server_listening = false;

		/* limit memory consumption */
		ini_set("memory_limit", "64M");
		
		/* free up unused resources */
		socket_close($ipc_socket_child);
				
		/* overwrite array $rrdp_status to do our own calculations */
		$rrdp_status = array( 'bytes_received' => 0, 'bytes_sent' => 0, 'queries_rrdtool_total' => 0, 'queries_rrdtool_valid' => 0, 'queries_rrdtool_invalid' => 0, 'rrd_pipe_broken' => 0, 'status' => 'RUNNING');
		
		/* handle client parent and child communication */
        interact(); 

		/* send IPC update message to parent */
		socket_write( $ipc_socket_parent, serialize($rrdp_status));

		/* shutdown connection to parent */
		socket_shutdown($ipc_socket_parent);
		socket_close($ipc_socket_parent);
		
		/* kill the process itself */
		exit(0);
    
	}else { 
		/* === parent === */
		
		/* free up unused resources */
		socket_close($ipc_socket_parent);

		/* return child's process identifier */ 
		return $pid;
	} 
}

/*	display_help - displays the usage of the RRDproxy */
function display_help () {
	$output = "\r\n"
			. " RRDtool Proxy v" . RRDP_VERSION . "\r\n"
			. " Copyright (C) 2004-2017 The Cacti Group\r\n"
			. " usage: rrdtool-proxy.php [--wizard] [-w] [--version] [-v]\r\n"
			. " Optional:\r\n"
			. " -v --version   - Display this help message\r\n"
			. " -w --wizard    - Start Configuration Wizard\r\n"
			. "\r\n";
	fwrite(STDOUT, $output);
}

/*  signal handler  */
function rrdp_sig_handler($signo) {
 	switch ($signo) {
         case SIGTERM:
             rrdp_cmd__shutdown('SIGTERM', false);
             exit;
             break;
         case SIGHUP:
             break;
         case SIGUSR1:
             break;
         default:
     }
}
?>
