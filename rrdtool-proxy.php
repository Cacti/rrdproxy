<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2016 The Cacti Group                                 |
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

chdir( dirname( __FILE__ ) );

/* ---------------------------- BEGIN - SYSTEM STARTUP ROUTINE ---------------------------- */
$microtime_start = microtime(true);

require_once('./rrdtool-proxy.lib.php');
fwrite(STDOUT, PHP_EOL . '___RRDtool Proxy Server Startup_________________________________________________' . PHP_EOL);

/* No Windows! Please ;) */
$support_os = strstr(PHP_OS, "WIN") ? false : true;
rrd_system__system_boolean_message( 'test: operation system supported', $support_os, true );

/* RRDtool Proxy has already been started ? */
exec('ps -ef | grep -v grep | grep -v "sh -c" | grep rrdtool-proxy.php', $output);
$not_running = (sizeof($output)>=2) ? false : true;
rrd_system__system_boolean_message( 'test: no proxy instance running', $not_running, true );

/* check state of required and optional php modules */
$support_sockets = extension_loaded('sockets');
rrd_system__system_boolean_message( 'test: php module \'sockets\'', $support_sockets, true );
$support_posix = extension_loaded('posix');
rrd_system__system_boolean_message( 'test: php module \'posix\'', $support_posix, true );
$support_pcntl = extension_loaded('pcntl');	
rrd_system__system_boolean_message( 'test: php module \'pcntl\'', $support_pcntl, true );
$support_gmp = extension_loaded('gmp');
rrd_system__system_boolean_message( 'test: php module \'gmp\'', $support_gmp );
$support_openssl = extension_loaded('openssl');
rrd_system__system_boolean_message( 'test: php module \'openssl\'', $support_openssl );	
$support_mcrypt = extension_loaded('mcrypt');
rrd_system__system_boolean_message( 'test: php module \'mcrypt\'', $support_mcrypt );	

exec("ulimit -n", $max_open_files);
exec("pidof php", $pid_of_php);
exec("ls -l /proc/{$pid_of_php[0]}/fd/ | wc -l", $open_files);
if($max_open_files[0] == 'unlimited') $max_open_files[0] = 1048576;
$max_concurrent_streams = intval($max_open_files[0]-$open_files[0]/2);
rrd_system__system_boolean_message( 'test: max. number of concurrent streams', $max_concurrent_streams, true );	

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
require_once('./rrdtool-proxy.lib.php');
require_once('./rrdtool-proxy.cfg.php');
@include_once('./clients');

/* include external libraries */
set_include_path("./ext/");
require_once('Crypt/RSA.php');
require_once('Crypt/AES.php');

/* initiate RSA encryption */
rrdp_system__encryption_init();

/* keep startup time in mind */
$rrdp_config['start'] = time();

declare(ticks = 100);

/* Socket Server Presets */
ini_set("max_execution_time", "0");
ini_set("memory_limit", "1024M");
error_reporting(E_ALL ^ E_NOTICE);

$__server_listening = true; 
$rrdp_msr_buffer = array();
$rrdp_logging_buffer = array();

/* create a Service TCP Stream socket supporting IPv6 and 4 */
$rrdp_srv = @socket_create(AF_INET6 , SOCK_STREAM, SOL_TCP);
if(socket_last_error() == 97) {
	$rrdp_config['ipv6'] = false;
	socket_clear_error();
	$rrdp_srv = @socket_create(AF_INET , SOCK_STREAM, SOL_TCP);
}else {
	$rrdp_config['ipv6'] = true;
}

rrd_system__system_boolean_message( 'test: ipv6 supported', $rrdp_config['ipv6']);


/* set up a service socket for administration */
if(!$rrdp_srv) { 
	rrd_system__system_die( PHP_EOL . "Unable to create socket. Error: " . socket_strerror(socket_last_error()) . PHP_EOL);
}
@socket_set_option($rrdp_srv, SOL_SOCKET, SO_REUSEADDR, 1);
if(!@socket_bind($rrdp_srv, $rrdp_config['address'], $rrdp_config['service_port'])) {
	rrd_system__system_die( PHP_EOL . "Unable to bind socket to '" . $rrdp_config['address'] . ":" . $rrdp_config['service_port'] ."'" . PHP_EOL);
};
socket_set_nonblock($rrdp_srv);
socket_listen($rrdp_srv);
rrd_system__system_boolean_message( 'init: tcp service socket', $rrdp_srv, true);


/* set up a default socket for RRDtool requests */
$rrdp = @socket_create( (($rrdp_config['ipv6']) ? AF_INET6 : AF_INET ), SOCK_STREAM, SOL_TCP);
if(!$rrdp) { 
	rrd_system__system_die( PHP_EOL . "Unable to create socket. Error: " . socket_strerror(socket_last_error()) . PHP_EOL); 
}
@socket_set_option($rrdp, SOL_SOCKET, SO_REUSEADDR, 1);
if(!@socket_bind($rrdp, $rrdp_config['address'], $rrdp_config['default_port'])) {
    rrd_system__system_die( PHP_EOL . "Unable to bind socket to '" . $rrdp_config['address'] . ":" . $rrdp_config['default_port'] ."'" . PHP_EOL);
};
socket_set_nonblock($rrdp);
rrd_system__system_boolean_message( 'init: tcp default socket', $rrdp, true);


/* start only listening for default connections (with backlog) as long as MSR has not been enabled */
if(!$rrdp_config['server_id']) {
	socket_listen($rrdp, $rrdp_config['backlog']);
}

/* create a small summary including some hints */
fwrite(STDOUT, PHP_EOL);
rrdp_cmd__show_version();

if(!$support_gmp) fwrite(STDOUT, "\033[0;{$color_theme['debug_critical']}m" . '*Enable GMP for PHP to increase RSA encryption/decryption performance' . "\033[0m" . PHP_EOL);
if(!$support_openssl) fwrite(STDOUT, "\033[0;{$color_theme['debug_critical']}m" . '*Enable OpenSSL for PHP to increase AES encryption/decryption performance' . "\033[0m" . PHP_EOL);

/* signal the parent to exit - we are up and ready */
@posix_kill( $ppid , SIGUSR1);
fwrite(STDOUT, '________________________________________________________________________________' . PHP_EOL);

/* ---------------------------- END - SYSTEM STARTUP ROUTINE ---------------------------- */

$rrdp_clients = array();
$rrdp_ipc_sockets = array();
$rrdp_srv_sockets = array();
$rrdp_srv_clients = array();

while($__server_listening) {

	$write = array();
	$except= array();

	$tv_sec = 30;
	
#	if(!$rrdp_config['server_id']) {
		##$tv_sec = NULL;
	#}else {
		rrdp_msr__block_write();
#	}
	
    /* setup clients listening to socket for reading */
    $read = array();
	$read[1] = $rrdp_srv;
	if(!$rrdp_config['server_id']) {
		$read[0] = $rrdp;
	}
	
	/* check child processes */
	$i = 0;
	foreach($rrdp_clients as $child_pid => $client) {
		$i++;
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
	
	/* all service connections need to be monitored for changes */
	foreach($rrdp_srv_clients as $rrdp_srv_client) {
        $read[] = $rrdp_srv_client['socket'];
	}

    $ready = socket_select($read, $write, $except, $tv_sec);
	if($ready) {
		foreach($read as $read_socket_index => $read_socket) {
			if(!$rrdp_config['server_id'] && $read_socket == $rrdp) {
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
						$pid = handle_client($rrdp, $socket_descriptor, $ipc_sockets);
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
				}
			}else if($read_socket == $rrdp_srv) {
			
				/* check if this is a new service client is trying to connect */
				if($rrdp_config['max_srv_cnn'] > sizeof($rrdp_srv_clients)) {
				
					$socket_descriptor = socket_accept($read_socket);

					/* check if the new client has the permission to connect */
					socket_getpeername($socket_descriptor, $ip);
					
					/* take care of IPv6, IPv4 and embedded IPv4 addresses */
					if( in_array($ip, array('127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1') ) ) {
						if(!in_array($socket_descriptor, $rrdp_srv_sockets)) {
							$key = intval($socket_descriptor);
							$rrdp_srv_sockets[$key] = $socket_descriptor;
							$rrdp_srv_clients[$key] = array( 'socket' => $socket_descriptor, 'ip' => $ip, 'privileged' => false, 'debug' => false, 'type' => 'srv' );
							socket_write($socket_descriptor, "\033[0;32m" . $rrdp_config['name'] . ">\033[0m");
							
							rrdp_system__debug('Service connection request #' . $key . '[IP: ' . $ip . '] granted.', 'ACL', 'debug_notice');
						}
					}elseif( $ip == $rrdp_config['slave'] ) {
						$key = intval($socket_descriptor);
						$rrdp_srv_sockets[$key] = $socket_descriptor;
						$rrdp_srv_clients[$key] = array( 'socket' => $socket_descriptor, 'ip' => $ip, 'privileged' => false, 'debug' => false, 'type' => 'msr' );
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

				}else if(isset($rrdp_srv_sockets[$index])) {

					/* === this is a service connection - means default or master-slave === */
					$recv = @socket_read($read_socket, 100000, PHP_NORMAL_READ);

					$msr = ($rrdp_srv_clients[$index]['type'] == 'msr') ? true : false;
					
					rrdp_system__count( (($msr) ? 'msr_bytes_received' : 'srv_bytes_received'), rrdp_system__calc_bytes($recv));
			
					if($recv === false) {
						/* connection lost :( */
						socket_shutdown($read_socket);
						socket_close($read_socket);
						if($msr) {
							### TODO: SEND OUT SNMP TRAP !
							rrdp_system__count('msr_connection_broken');
							rrdp_system__debug('Connection #' . $index . '[IP: ' . $rrdp_srv_clients[$index]['ip'] . '] broken.', 'MSR', 'debug_error');
						}else {
							rrdp_system__count('srv_connection_broken');
						}
						unset($rrdp_srv_clients[$index]);
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
									$privileged_mode = ($rrdp_srv_clients[$index]['privileged']) ? 1 : 0 ;
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
						socket_close($rrdp_srv_client['socket']);
						unset($rrdp_srv_clients[$index]);
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
	global $rrdp_msr_buffer;

	$current_time = time();
	$current_timeframe = $current_time + $current_time % 300;
	
	if(sizeof($rrdp_msr_buffer)>0) {
		foreach($rrdp_msr_buffer as $timeframe => $msr_commands) {
			if($timeframe < $current_timeframe) {
				$fp = fopen('./msr/' . $timeframe, 'a');
				foreach($msr_commands as $id => $cmd) {
					fwrite($fp, $id . "\t" . $cmd . "\r\n");
				}
				unset($rrdp_msr_buffer[$timeframe]);
			}
		}
	}
	return;
}


/* ####################################   INTERNAL FUNCTIONS   #################################### */

function rrdp_system__encryption_init() {
	global $rrdp_encryption, $microtime_start;

	$rsa = new Crypt_RSA();
	
	if(!file_exists('./public.key') || !file_exists('./private.key')) {
		$keys = $rsa->createKey(2048);
		$rrdp_encryption['public_key'] = $keys['publickey'];
		$rrdp_encryption['private_key'] = $keys['privatekey'];
		
		file_put_contents('./public.key', $rrdp_encryption['public_key']);
		file_put_contents('./private.key', $rrdp_encryption['private_key']);
	}
	$rrdp_encryption['public_key'] = file_get_contents('./public.key');
	rrd_system__system_boolean_message( 'init: RSA public key', $rrdp_encryption['public_key'], true );
	
	$rrdp_encryption['private_key'] = file_get_contents('./private.key');
	rrd_system__system_boolean_message( 'init: RSA private key', $rrdp_encryption['private_key'], true);
		
	$rsa->loadKey($rrdp_encryption['public_key']);
	$rrdp_encryption['public_key_fingerprint'] = $rsa->getPublicKeyFingerprint();
}

function rrdp_system__ipc(&$input) {
	global $rrdp_msr_buffer;

	$child_status = unserialize($input);	

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
	global $rrdp_srv_clients, $rrdp_status;
	switch($variable) {
		case 'max_used_connections':
			if(sizeof($rrdp_srv_clients)> $rrdp_status[$variable]) {
				$rrdp_status[$variable] = sizeof($rrdp_srv_clients);
			}
		break;
	}
	return;
};

function rrdp_system__debug( $msg, $category, $level ) {
	global $rrdp_config, $rrdp_srv_clients, $rrdp_srv_sockets, $color_theme;
	
	if($rrdp_config['debug']) {
		foreach($rrdp_srv_clients as $key => $rrdp_srv_client) {
			if($rrdp_srv_client['debug']) {
				/* write debug message to socket and return default prompt for proviledge mode */
				rrdp_system__socket_write( $rrdp_srv_sockets[$key], "\r\n\033[0;{$color_theme[$level]}m[" . $category . "] " . $msg . "\r\n\033[0;{$color_theme['debug_prompt']}m" . $rrdp_config['name'] . '#' . "\033[0m");
			}
		}
	}
}

function rrdp_system__return_prompt($socket) {
	global $rrdp_srv_clients, $rrdp_config, $color_theme;
	
	$i = intval($socket);
	
	$prompt = "\033[0;" . (($rrdp_srv_clients[$i]['debug']) ? $color_theme['debug_prompt'] : $color_theme['prompt']) .  "m" . $rrdp_config['name'] . (($rrdp_srv_clients[$i]['privileged']) ? '#' :'>') . "\033[0m";
	rrdp_system__socket_write($socket, $prompt);
}

function rrdp_system__socket_write( $socket, $output, $counter = 'bytes_sent') {
	if($return = @socket_write($socket, $output, strlen($output)) ) {
		rrdp_system__count($counter, rrdp_system__calc_bytes($output));
	}
	return $return;
}

function rrdp_system__status_live($variable) {
	global $rrdp_srv_clients, $rrdp_ipc_sockets, $rrdp_config;
	
	$status = 'n/a';
	switch($variable) {
		case 'threads_connected':
			$status = sizeof($rrdp_srv_clients);
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
        // The 'G' modifier is available since PHP 5.1.0
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
	}
	$rrdp_logging_buffer[] = date(DATE_RFC822) . "    " . $msg;
	return;
}

/* ####################################   SYSTEM COMMANDS   #################################### */
function rrdp_cmd__clear( $socket, $args) {
	global $rrdp_srv_clients, $rrdp_help_messages, $rrdp_status;
	
	$i = intval($socket);
	if( $rrdp_srv_clients[$i]['privileged'] === true ) {
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
	global $rrdp_srv_clients, $rrdp_status;
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
	global $rrdp_srv_clients, $rrdp_logging_buffer;
	$rrdp_logging_buffer = array();
	return;
}

function rrdp_cmd__enable( $socket, $args) {
	global $rrdp_srv_clients;
	if(!$args) {
		$i = intval($socket);
		/* only a local connected user is allowed to switch to enhanced mode */
		if(in_array($rrdp_srv_clients[$i]['ip'], array('127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1'))) {
			$rrdp_srv_clients[$i]['privileged'] = true;
			return;
		}
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Privileged mode is restricted to localhost only\r\n");
	return;
}

function rrdp_cmd__disable( $socket, $args) {
	global $rrdp_srv_clients;
	if(!$args) {
		$i = intval($socket);
		/* client would like to return to unprivileged mode */
		$rrdp_srv_clients[$i]['privileged'] = false;
		return;
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	return;
}

function rrdp_cmd__quit( $socket, $args) {
	global $rrdp_srv_clients, $rrdp_srv_sockets;
	if(!$args) {
		$i = intval($socket);
		/* client would like to regularly close the connection */
		socket_shutdown($rrdp_srv_clients[$i]['socket'], 2);
		socket_close($rrdp_srv_clients[$i]['socket']);
		unset($rrdp_srv_clients[$i]);
		unset($rrdp_srv_sockets[$i]);
	}else {
		/* unknown command */
		rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	}
	return;
}

function rrdp_cmd__shutdown( $socket, $args) {
	global $rrdp_clients, $rrdp_srv_clients, $rrdp_ipc_sockets, $rrdp, $rrdp_srv;
	if(!$args) {
		$i = intval($socket);
		/* only privileged users are allowed to shut down the proxy from remote */
		if( $rrdp_srv_clients[$i]['privileged'] === true ) {
		
			$microtime_start = microtime(true);
			rrd_system__system_message( $microtime_start, "RRDtool Proxy shutdown process started");

			socket_close($rrdp);
			rrd_system__system_message( $microtime_start, "Socket for default port closed");

			rrd_system__system_message( $microtime_start, "Stop child processes:");
			
			foreach($rrdp_clients as $child_pid => $client_ip) {
			
				$key = $rrdp_clients[$child_pid]['ipc'];
				if(isset($rrdp_ipc_sockets[ $key ]) && is_resource($rrdp_ipc_sockets[ $key ][1])) {
					@socket_write( $rrdp_ipc_sockets[ $key ][1], "shutdown\r\n");
				}
				
				//$child_status = pcntl_waitpid($child_pid, $status);
				//if($child_status == -1 || $child_status > 0) {
					//unset($rrdp_clients[$child_pid]);
					//rrd_system__system_message( $microtime_start, "[PID:$child_pid] Child process stopped");
				//}else {
					//posix_kill($child_pid, SIGTERM);
				//}
			}

			socket_close($rrdp_srv);
			rrd_system__system_message( $microtime_start, "Service socket closed");

			rrd_system__system_message( $microtime_start, "Close service connections:");			
			foreach($rrdp_srv_clients as $index => $rrdp_srv_client) {
				if($index != $i) {
					@socket_write($rrdp_srv_client['socket'], "Shutting down ... bye ;) \r\n");
				}
				@socket_close($rrdp_srv_clients['socket']);
				rrd_system__system_message( $microtime_start, "[SOCKET:" . intval($rrdp_srv_client['socket']) . "] Service connection closed");
			}

			/* ... bye :) */			
			rrd_system__system_message( $microtime_start, "RRDtool Proxy shutdown process complete\r\n");	
			exit;
		}
	}
	/* permission denied */
	rrdp_system__socket_write($socket, "% Unrecognized command\r\n");
	return;
}

function rrdp_cmd__list( $socket, $args) {
	global $rrdp_srv_clients, $rrdp_help_messages;
	
	if(!$args) {
		$i = intval($socket);
		$output = '';
		foreach($rrdp_help_messages['?'][ intval($rrdp_srv_clients[$i]['privileged']) ] as $cmd => $description) {
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
	global $rrdp_srv_clients, $rrdp_help_messages;
	
	if(sizeof($args) >= 1) {
		$i = intval($socket);
		if(isset($rrdp_help_messages['show']['?'][ intval($rrdp_srv_clients[$i]['privileged']) ][ $args[0] ])) {
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
	global $rrdp_srv_clients;
	
	$output = "\r\n" . sprintf(" %-10s %-15s %-3s\r\n", 'ID', 'IP', 'Privileged Mode');
	foreach($rrdp_srv_clients as $client) {
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

function rrdp_cmd__show_status($socket) {
	global $rrdp_srv_clients, $rrdp_status;
	
	$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'Variable', 'Value');
	foreach($rrdp_status as $variable => $value) {
		$output .= sprintf(" %-35s %-12s \r\n", ucfirst($variable), (($value === 'live') ? rrdp_system__status_live($variable) : $value) );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_variables($socket) {
	global $rrdp_srv_clients, $rrdp_config;
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
	global $rrdp_srv_clients, $rrdp_logging_buffer;
	
	$output = "\r\n";
	foreach($rrdp_logging_buffer as $msg) {
		$output .= sprintf(" %s \r\n", $msg );
	}
	$output .= "\r\n";	
	rrdp_system__socket_write($socket, $output);
	return;
}

function rrdp_cmd__show_rsa($socket, $args) {
	global $rrdp_srv_clients, $rrdp_config, $rrdp_encryption, $rrdp_remote_clients;
		
	if(isset($args[1])) {
		switch($args[1]) {
			case 'publickey':
				$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'Variable', 'Value');
				$output .= sprintf(" %-35s %s \r\n", 'Public Key', str_replace( "\r\n", "\r\n                                     ", $rrdp_encryption['public_key']));
				$output .= sprintf(" %-35s %s \r\n", 'Fingerprint', $rrdp_encryption['public_key_fingerprint']);
				$output .= "\r\n";	
				rrdp_system__socket_write($socket, $output);
			break;
			case 'clients':
				$output = "\r\n" . sprintf(" %-35s %-12s \r\n\r\n", 'IP Address', 'Fingerprint');
				foreach($rrdp_remote_clients as $ip => $fingerprint) {
					$output .= sprintf(" %-35s %s \r\n", $ip, $fingerprint );
				}
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
	global $rrdp_srv_clients, $rrdp_config, $rrdp_msr_buffer;
	
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
	global $rrdp_config, $rrdp_encryption;
	
	$runtime = time() - $rrdp_config['start']; 
	$days = floor( $runtime / 86400 );
	$hours = floor( ( $runtime - $days * 86400 ) / 3600 );
	$minutes = floor( ( $runtime - $days * 86400 - $hours * 3600 ) / 60 );
	$seconds = $runtime - $days * 86400 - $hours * 3600 - $minutes * 60;
	
	$memory_limit = rrdp_system__convert2bytes(ini_get('memory_limit'));
	$memory_used = memory_get_usage();
	$memory_usage = round(($memory_used/$memory_limit)*100, 2);
	
	$output ="\r\n"
			." RRDtool Proxy v" . RRDP_VERSION . "\r\n"
			." Copyright (C) 2004-2015 The Cacti Group\r\n"
			." {$rrdp_config['name']} uptime is $days days, $hours hours, $minutes minutes, $seconds seconds\r\n"
			." Memory usage " . $memory_usage . " % (" . $memory_used . "/" . $memory_limit ." in bytes)\r\n"
			." " . $rrdp_encryption['public_key_fingerprint'] . "\r\n\r\n"
			." Proxy is listening on ['localhost' <ipv" . ($rrdp_config['ipv6'] ? '6' : '4' ) . '> ' . $rrdp_config['service_port'] . ']' . "\r\n";
	if(!$rrdp_config['server_id']) {
		$output .= " Proxy is listening on ['" . ($rrdp_config['address'] ? $rrdp_config['address'] : 'any') . "' <ipv" . ($rrdp_config['ipv6'] ? '6' : '4' ) . '> ' . $rrdp_config['default_port'] . ']' . "\r\n";
	}
	$output .= "\r\n";
	
	if(is_resource($socket)) {
		rrdp_system__socket_write($socket, $output);
	}else {
		fwrite(STDOUT, $output);
	}
	return;
}

function rrdp_cmd__debug( $socket, $args) {
	global $rrdp_srv_clients, $rrdp_help_messages, $rrdp_config;
	
	if(sizeof($args) == 1) {
		$i = intval($socket);
		if(isset($rrdp_help_messages['debug']['?'][ intval($rrdp_srv_clients[$i]['privileged']) ][ $args[0] ])) {
			if($args[0] == "on") {
				$rrdp_srv_clients[$i]['debug'] = true;
				$rrdp_config['debug'] = true;
			}else {
				$rrdp_srv_clients[$i]['debug'] = false;
				foreach($rrdp_srv_clients as $rrdp_srv_client) {
					if($rrdp_srv_client['debug']) {
						$rrdp_config['debug'] = true;
						return;
					}
				}
				$rrdp_config['debug'] = false;
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
	global $rrdp_srv_clients, $rrdp_help_messages;
	
	if(sizeof($args) >= 1) {
		$i = intval($socket);
		if(isset($rrdp_help_messages['set']['?'][ intval($rrdp_srv_clients[$i]['privileged']) ][ $args[0] ])) {
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

function rrdp_cmd__set_rsa($socket, $args) {
	global $rrdp_srv_clients, $rrdp_config, $rrdp_encryption, $rrdp_remote_clients;
		
	if(isset($args[1])) {
		switch($args[1]) {
			case 'keys':

				$rsa = new Crypt_RSA();
				$keys = $rsa->createKey(2048);
				$rrdp_encryption['public_key'] = $keys['publickey'];
				$rrdp_encryption['private_key'] = $keys['privatekey'];
		
				file_put_contents('./public.key', $rrdp_encryption['public_key']);
				file_put_contents('./private.key', $rrdp_encryption['private_key']);
		
				$rsa->loadKey($rrdp_encryption['public_key']);
				$rrdp_encryption['public_key_fingerprint'] = $rsa->getPublicKeyFingerprint();
			
				rrdp_cmd__show_rsa($socket, array( 1 => 'publickey' ) );
			
			break;
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
						file_put_contents('clients', '<?php $rrdp_remote_clients = ' . var_export($rrdp_remote_clients, true) . ';');
				
					}else {
					
						rrdp_system__socket_write($socket, "% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, "% set rsa add <IP> <Fingerprint>\r\n");
				}
	
			break;
			case 'remove':
				
				if( isset($args[2]) ) {
				
					if(isset($rrdp_remote_clients[$args[2]])) {
						unset($rrdp_remote_clients[$args[2]]);
						/* update local list of clients */
						file_put_contents('clients', '<?php $rrdp_remote_clients = ' . var_export($rrdp_remote_clients, true) . ';');
					}else {
						rrdp_system__socket_write($socket, "% Unknown client IP address\r\n");
					}
				}else {
					rrdp_system__socket_write($socket, "% set rsa remove <IPv4|IPv6>\r\n");
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

/** 
  * Handle a new client connection 
  */ 
function handle_client($ssock, $csock, $ipc_sockets) 
{ 
    GLOBAL $__server_listening, $socket_descriptor, $rrdp_status, $rrdp_srv_sockets; 

	list($ipc_socket_parent, $ipc_socket_child) = $ipc_sockets;
    
    $pid = pcntl_fork(); 

    if ($pid == -1) { 
        
		/* === fork failed === */ 
        die; 										//TODO: handling missing
	
	}elseif ($pid == 0) { 

		/* === child === */ 
		include('./rrdtool-proxy.client.php');
        
		/* stop main loop, because we have to reuse the same code base */
		$__server_listening = false;

		/* limit memory consumption */
		ini_set("memory_limit", "4M");
		
		/* free up unused resources */
		socket_close($ssock);
		socket_close($ipc_socket_child);
				
		/* overwrite array $rrdp_status to do our own calculations */
		$rrdp_status = array( 'bytes_received' => 0, 'bytes_sent' => 0, 'queries_rrdtool_total' => 0, 'queries_rrdtool_valid' => 0, 'queries_rrdtool_invalid' => 0, 'rrd_pipe_broken' => 0, 'status' => 'RUNNING');
		
		/* handle client parent and child communication */
        interact($csock, $ipc_socket_parent); 

		/* close client connection */
		socket_shutdown($csock);
		socket_close($csock);

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

?>