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

function interact($socket_client, $ipc_socket_parent) {

    /* 
		Clients using the default port are only allowed to talk to RRDtool directly.
		But the child will keep the parent up-to-date by using IPC.
	*/ 
	global $rrdcached_pid, $rrdp_config, $rrdp_encryption, $rrdtool_cmds, $rrdtool_custom_cmds, $rrdtool_msr_cmds, $rrdp_remote_clients, $rrdp_remote_proxies, $rrdp_status, $rrdtool_env_vars, $rrdp_client_cnn_params;
	if($rrdcached_pid) putenv('RRDCACHED_ADDRESS=unix:' . realpath('') . '/run/rrdcached.sock');

	$rrdp_status_backup = $rrdp_status;
	$cmd_multiline = false;
	$rrdtool_process = false;
	$client_authenticated = false;
	
	/* avoid zombies */
	socket_set_option($socket_client,SOL_SOCKET, SO_RCVTIMEO, array("sec"=>10, "usec"=>0));
	socket_set_block ($socket_client);
	socket_set_block ($ipc_socket_parent);

	/* enable message encryption */
	$rsa = new \phpseclib\Crypt\RSA();
	
	$input = '';
	$tv_sec = $rrdp_config['remote_cnn_timeout'];
	
	while(1) {
	
	    /* setup clients listening to socket for reading */
		$read = array();
		$read[0] = $socket_client;
		$read[1] = $ipc_socket_parent;
	
	    $ready = socket_select($read, $write, $except, $tv_sec);
		if($ready) {
			foreach($read as $read_socket_index => $read_socket) {
			
				if($read_socket == $socket_client) {

					/* RRDtool client is talking to us */
					
					while(1) {
						$recv = @socket_read($read_socket, 100000, PHP_BINARY_READ );
						if($recv === false) {
							/* timeout  */
							rrdp_system__socket_write($socket_client, ( ($client_authenticated) ? encrypt(RRD_ERROR . "Timeout", $client_public_key) : RRD_ERROR . "Timeout") . "\r\n");
							$rrdp_status['status'] = 'CLOSEDOWN_BY_TIMEOUT';
							break 3;
							
						}else if($recv == '') {
							/* socket session dropped by client */
							$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_DROP';
							break 3;
							
						}else {
												
							$input .= $recv;
							if (substr($input, -1) == "\n") {
								rrdp_system__count('bytes_received', rrdp_system__calc_bytes($input));
																
								if ( !$client_authenticated ) {
									if(strpos($input, '-----BEGIN PUBLIC KEY-----') === false) {
										/* authentication failed !!! */		
										rrdp_system__socket_write($socket_client, "Authentication failed\r\n");
										$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_AUTH';
										break 3;
									}
									
									if(strpos($input, '-----END PUBLIC KEY-----') !== false) {
										$client_public_key = trim($input);
										socket_getpeername($socket_client, $ip);
										$rsa_finger_print = isset($rrdp_remote_clients[$ip]) ? $rrdp_remote_clients[$ip] : 'unknown';
										
										$rsa->loadKey($client_public_key);
										
										if($rsa_finger_print == $rsa->getPublicKeyFingerprint()) {
											/* registered public key has been received */
											$client_authenticated = true;
											/* send out proxy's public key */
											rrdp_system__socket_write($socket_client, $rrdp_encryption['public_key'] . "\r\n");
											$input = '';
											continue;
										}else {
											/* authentication failed !!! */
											rrdp_system__socket_write($socket_client, "Authentication failed\r\n");
											$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_AUTH';
											break 3;
										}
									}else {
										continue;
									}
								}else {
									
									$input = (decrypt($input, $rrdp_encryption));
									if(strpos($input, "\x1f\x8b") === 0) {
										$input = gzdecode($input);
									}									
								}
								
								if (strpos($input, ' ') !== false) {
									$options = explode(' ', $input, 2);
									$cmd = $options[0];
									$cmd_options = $options[1];
								}else {
									$cmd = $input;
									$cmd_options = '';
								}
								$input = '';	
								
								/* try to react as similar as possible */
								if(!$cmd) {
									$cmd = 'info';
								}

								if( in_array($cmd, $rrdtool_cmds) === true ) {
								
									rrdp_system__count('queries_rrdtool_total');
								
									/* open a persistent RRDtool pipe only on demand */
									if($rrdtool_process === false) {
										$rrdtool_process_pipes	= rrdtool_pipe_init($rrdp_config);
										$rrdtool_process		= $rrdtool_process_pipes[0];
										$rrdtool_pipes			= $rrdtool_process_pipes[1];
									}
									
									$auto_compression = in_array($cmd, array('xport', 'fetch', 'dump')) ? true : false;
									
									$rrd_exec_status = rrdtool_pipe_execute($cmd . ' ' . $cmd_options . "\r\n", $rrdtool_pipes, $read_socket, $client_public_key, $auto_compression);
									
									if( $rrd_exec_status === true ) {	

										rrdp_system__count('queries_rrdtool_valid');
									
										/* update local cache by valid RRDtool commands for MSR */
										if( sizeof($rrdp_remote_proxies)>0 && in_array($cmd , $rrdtool_msr_cmds) === true) {
											list($mtime,$time) = explode(' ',microtime());
											$offset = $time %10;
											$block = $time - $offset + 10;
											$rrdp_status['msr_commands'][$block][$offset+$mtime . '_' . intval($read_socket)] = $cmd . ' ' . $cmd_options;
											if(sizeof($rrdp_status['msr_commands'])>1 | $time >= $block)  { 
												$msr_block = key($rrdp_status['msr_commands']);
												$msr_message['msr_commands'][$msr_block] = $rrdp_status['msr_commands'][$msr_block];
												if (@socket_write( $ipc_socket_parent, serialize($msr_message) . "\r\n")) {
													unset($rrdp_status['msr_commands'][$msr_block]);
													unset($msr_message);
													$rrdp_status = $rrdp_status_backup;
												};
											}
										}
									}else if( $rrd_exec_status === null ) {
										/* RRDtool pipe broken */
										rrdp_system__count('rrd_pipe_broken');
										rrdp_system__socket_write($socket, encrypt(RRD_ERROR . "RRDTOOL_PIPE_BROKEN", $client_public_key) . "\r\n");
										rrdtool_pipe_close($rrdtool_process);
										$rrdtool_process = false;
									}else {
										/* client tried to execute an invalid or unsupported RRDtool command */
										rrdp_system__count('queries_rrdtool_invalid');
									}
							
								}elseif( in_array($cmd, array('exit', 'quit', 'shutdown')) === true ) {
									/* client wants to quit on a regular basis */
									$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_CMD';
									break 3;

								}elseif(in_array($cmd, $rrdtool_custom_cmds)) {
								
									$rrdp_exec_status = false;
									$options = explode(' ', $cmd_options);

									switch ($cmd) {
										case 'setenv':
											if(sizeof($options) == 2 && in_array($options[0], $rrdtool_env_vars)) {
												putenv($options[0]. "=" . $options[1]);
												rrdp_system__socket_write($read_socket, encrypt(RRD_OK, $client_public_key) . "\r\n");
											}else {
												rrdp_system__socket_write($read_socket, encrypt(RRD_ERROR . ' % setenv <name> <value>', $client_public_key) . "\r\n");
											}
											break;
										
										case 'getenv':
											if(sizeof($options)== 1 && in_array($options[0], $rrdtool_env_vars)) {
												$output = getenv($options[0]);
												rrdp_system__socket_write($read_socket, encrypt($output . "\n" . RRD_OK, $client_public_key) . "\r\n");
											}else {
												rrdp_system__socket_write($read_socket, encrypt(RRD_ERROR . ' % getenv <name>', $client_public_key) . "\r\n");
											}
											break;
											
										case 'setcnn':
											if(sizeof($options) == 2 && in_array($options[0], $rrdp_client_cnn_params)) {
												if($options[0] == 'timeout') {
													if( in_array($options[1], array('null', 'off', 'disabled', '-1')) ) {
														$tv_sec = null;
														rrdp_system__socket_write($read_socket, encrypt("% Timeout disabled.\n" . RRD_OK, $client_public_key) . "\r\n");
													}elseif (is_numeric($options[1])) {
														$tv_sec = abs($options[1]);
														rrdp_system__socket_write($read_socket, encrypt("% Timeout " . $tv_sec. "s.\n" . RRD_OK, $client_public_key) . "\r\n");
													}else {
														rrdp_system__socket_write($read_socket, encrypt(RRD_ERROR . ' % Out of range.', $client_public_key) . "\r\n");
													}
												}
											}else {
												rrdp_system__socket_write($read_socket, encrypt(RRD_ERROR . " % setcnn <parameter> <value>", $client_public_key) . "\r\n");
											}
											break;
										
										case 'fc-list':
											$output = shell_exec('fc-list');
											rrdp_system__socket_write($read_socket, encrypt($output . "\n" . RRD_OK, $client_public_key) . "\r\n");
											break;
										case 'file_exists':
										case 'is_dir':
										case 'mkdir':
																
											/* execution of internal PHP functions to support any kind of file transaction */
											chdir($rrdp_config['path_rra']);
											
											$rrdp_exec_status = call_user_func_array($cmd, $options);
											rrdp_system__socket_write($read_socket, encrypt( ($rrdp_exec_status === true) ? RRD_OK : RRD_ERROR , $client_public_key) . "\r\n");
											break;

										default:
										break;
									}					
									
									/* update local cache for MSR */
									if($rrdp_exec_status === true ) {
										if( in_array($cmd , $rrdtool_msr_cmds) === true) {
											list($mtime,$time) = explode(' ',microtime());
											$offset = $time %10;
											$block = $time - $offset + 10;
											$rrdp_status['msr_commands'][$block][$offset+$mtime . '_' . intval($read_socket)] = $cmd . ' ' . $cmd_options;
											if(sizeof($rrdp_status['msr_commands'])>1 | $time >= $block )  { 
												$msr_block = key($rrdp_status['msr_commands']);
												$msr_message['msr_commands'][$msr_block] = $rrdp_status['msr_commands'][$msr_block];
												if (@socket_write( $ipc_socket_parent, serialize($msr_message) . "\r\n")) {
													unset($rrdp_status['msr_commands'][$msr_block]);
													unset($msr_message);
													$rrdp_status = $rrdp_status_backup;
												};
											}
										}	
									}									
									
								}else {
									/* kick that client if it does not know how to talk to me */
									rrdp_system__socket_write($read_socket, encrypt(RRD_ERROR . " % Invalid input detected", $client_public_key) . "\r\n");
									$rrdp_status['status'] = 'CLOSEDOWN_BY_VIOLATION';
									break 3;
								}
								break 1;
							}else {
								continue;
							}
						}
					}
				}else if($read_socket == $ipc_socket_parent) {
					
					/* RRDtool proxy is talking to us */
					
					while(1) {
						$recv = @socket_read($ipc_socket_parent, 8192, PHP_BINARY_READ );
						if($recv === false) {
							/* timeout  */
							break;
							
						}else if($recv == '') {
							/* socket session dropped by proxy */
							break;
							
						}else {
							$input .= $recv;
							if (substr($input, -1) == "\n") {
								rrdp_system__count('bytes_received', rrdp_system__calc_bytes($input));
								$cmd = trim($input);

								switch($cmd) {
									case 'shutdown':
										rrdp_system__socket_write($socket_client, ( ($client_authenticated) ? encrypt(RRD_ERROR . "Shutting down ...", $client_public_key) : RRD_ERROR . "Shutting down ...") . "\r\n");
										socket_close($ipc_socket_parent);
										exit;
									case 'status':
										socket_write( $ipc_socket_parent, "running\r\n");
										break 4;
									default:
										break 3;
								}
							}else {
								continue;
							}
						}
					}
					
				}
			}
		}else {
			rrdp_system__socket_write($socket_client, "Timeout\r\n");
			$rrdp_status['status'] = 'CLOSEDOWN_BY_TIMEOUT';
			break 1;
		}
	}
	
	if($rrdtool_process) {
		rrdtool_pipe_close($rrdtool_process);
	}
	return;

}
?>
