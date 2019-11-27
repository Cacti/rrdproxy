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

function interact($socket_client) {
	/*
		Clients using the default port are only allowed to talk to RRDtool directly.
		But the child will keep its parent up-to-date by using IPC.
	*/
	global $rrdcached_pid, $rrdp_config, $ipc_socket_parent, $rrdtool_cmds, $rrdtool_custom_cmds, $rrdtool_msr_cmds, $rrdp_status, $rrdtool_env_vars, $rrdp_client_cnn_params;
	global $encryption;
	if($rrdcached_pid) putenv('RRDCACHED_ADDRESS=unix:' . realpath('') . '/run/rrdcached.sock');

	/* switch into the rra directory */
	chdir($rrdp_config['path_rra']);

	set_time_limit(0);

	$encryption = true;
	$rrdp_status_backup = $rrdp_status;
	$rrdtool_process = false;
	$client_authenticated = false;
	$end_of_packet = "_EOP_\r\n";
	$end_of_sequence = "_EOT_\r\n";

	$tv_sec = $rrdp_config['remote_cnn_timeout'];

	/* avoid zombies */
	socket_set_option($socket_client,SOL_SOCKET, SO_RCVTIMEO, array("sec"=>600, "usec"=>0));
	socket_set_block ($socket_client);
	socket_set_block ($ipc_socket_parent);

	/* enable message encryption */
	$rsa = new \phpseclib\Crypt\RSA();

	$input = '';

	while(1) {

		/* setup clients listening to socket for reading */
		$read = array();
		$read[0] = $socket_client;
		$read[1] = $ipc_socket_parent;

		$ready = socket_select($read, $write, $except, $tv_sec);

		switch ($err = socket_last_error( )) {
			case 0:
				socket_clear_error();
				break;
			default:
				__logging(LOGGING_LOCATION_BUFFERED, 'Critical error occured: ' . $err, 'IPC', SEVERITY_LEVEL_CRITICAL);
				break 2;
		}

		if($ready>0) {
			foreach($read as $read_socket_index => $read_socket) {

				if($read_socket == $socket_client) {

					/* RRDtool client is talking to us */

					while(1) {

						$recv = @socket_read($read_socket, 100000, PHP_BINARY_READ );

						if($recv === false) {
							/* timeout  */
							rrdp_system__socket_write($socket_client, ( ($client_authenticated) ? encrypt(RRD_ERROR . "Timeout", $client_public_key) : RRD_ERROR . "Timeout") . $end_of_sequence);
							__logging(LOGGING_LOCATION_BUFFERED, 'Client connection timeout detected', 'IPC', SEVERITY_LEVEL_WARNING);
							$rrdp_status['status'] = 'CLOSEDOWN_BY_TIMEOUT';
							break 3;

						}else if($recv === '') {
							/* socket session dropped by client */
							__logging(LOGGING_LOCATION_BUFFERED, 'Connection dropped by client', 'IPC', SEVERITY_LEVEL_NOTIFICATION);
							$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_DROP';
							break 3;

						}else {

							$input .= $recv;
							if (strpos($input, $end_of_sequence) !== false ) { //end of one or more transactions detected
								rrdp_system__count('bytes_received', rrdp_system__calc_bytes($input));

								$transactions = explode($end_of_sequence, $input);
								$input = array_pop($transactions);

								foreach($transactions as $transaction) {
									if ( !$client_authenticated ) {
										if(strpos($transaction, '-----BEGIN PUBLIC KEY-----') === false) {
											/* authentication failed !!! */
											rrdp_system__socket_write($socket_client, "Authentication failed" . $end_of_sequence);
											__logging(LOGGING_LOCATION_BUFFERED, 'Client Authentication failed by invalid key format', 'IPC', SEVERITY_LEVEL_ERROR);
											$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_AUTH';
											break 4;
										}else {
											$client_public_key = $transaction;
											socket_getpeername($socket_client, $ip);
											$rsa_finger_print = isset($rrdp_config['remote_clients'][$ip]) ? $rrdp_config['remote_clients'][$ip] : 'unknown';
											$rsa->loadKey($client_public_key);

											if($rsa_finger_print == $rsa->getPublicKeyFingerprint()) {
												/* registered public key has been received */
												$client_authenticated = true;
												/* send out proxy's public key */
												rrdp_system__socket_write($socket_client, $rrdp_config['encryption']['public_key'] . $end_of_sequence);
												__logging(LOGGING_LOCATION_BUFFERED, 'Client Authentication successful', 'IPC', SEVERITY_LEVEL_DEBUG);
												continue;
											}else {
												/* authentication failed !!! */
												rrdp_system__socket_write($socket_client, "Authentication failed" . $end_of_sequence);
												__logging(LOGGING_LOCATION_BUFFERED, 'Client Authentication failed by invalid public key', 'IPC', SEVERITY_LEVEL_ERROR);
												$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_AUTH';
												break 4;
											}
										}
									}else {
										$transaction = decrypt($transaction);

										if($transaction === false) {
											rrdp_system__socket_write($socket_client, "Decryption error" . $end_of_sequence);
											__logging(LOGGING_LOCATION_BUFFERED, 'Client message decryption failed.', 'IPC', SEVERITY_LEVEL_ERROR);
											$rrdp_status['status'] = 'CLOSEDOWN_BY_DECRYPTION';
											break 4;
										}

										if(strpos($transaction, "\x1f\x8b") === 0) {
											$transaction = gzdecode($transaction);
										}

										if (strpos($transaction, ' ') !== false) {
											$options = explode(' ', $transaction, 2);
											$cmd = $options[0];
											$cmd_options = $options[1];
										}else {
											$cmd = $transaction;
											$cmd_options = '';
										}

										/* try to react as similar as possible */
										if(!$cmd) {
											$cmd = 'info';
										}

										__logging(LOGGING_LOCATION_BUFFERED, 'REQUEST: ' . $cmd . ' ' . $cmd_options , 'IPC', SEVERITY_LEVEL_DEBUG);


										if( in_array($cmd, $rrdtool_cmds) === true ) {
											rrdp_system__count('queries_rrdtool_total');

											/* open a persistent RRDtool pipe only on demand */
											if($rrdtool_process === false) {
												$rrdtool_process_pipes	= rrdtool_pipe_init($rrdp_config);
												$rrdtool_process		= $rrdtool_process_pipes[0];
												$rrdtool_pipes			= $rrdtool_process_pipes[1];
											}

											$auto_compression = (in_array($cmd, array('xport', 'fetch', 'dump', 'graph', 'graphv', 'updatev ', 'info')) && strpos($cmd_options, '--imgformat=PNG') === false) ? true : false;
											$rrd_exec_status = rrdtool_pipe_execute($cmd . ' ' . $cmd_options . "\r\n", $rrdtool_pipes, $socket_client, $client_public_key, $auto_compression, false, $end_of_sequence);

											if( $rrd_exec_status === true ) {

												rrdp_system__count('queries_rrdtool_valid');

												/* update local cache by valid RRDtool commands for MSR */
												if(__sizeof($rrdp_config['remote_proxies'])>0 && in_array($cmd , $rrdtool_msr_cmds) === true) {
													__logging(LOGGING_LOCATION_BUFFERED, 'MSR: ' . $cmd . ' ' . $cmd_options , 'MSR', SEVERITY_LEVEL_DEBUG);
													list($mtime,$time) = explode(' ',microtime());
													$offset = $time %10;
													$block = $time - $offset + 10;
													$rrdp_status['msr_commands'][$block][$offset+$mtime . '_' . intval($read_socket)] = $cmd . ' ' . $cmd_options;
													if(__sizeof($rrdp_status['msr_commands'])>1 | $time >= $block)  {
														$msr_block = key($rrdp_status['msr_commands']);
														$msr_message['type'] = 'msr';
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
												rrdp_system__socket_write($socket_client, encrypt(RRD_ERROR . "RRDTOOL_PIPE_BROKEN", $client_public_key) . $end_of_sequence);
												rrdtool_pipe_close($rrdtool_process);
												$rrdtool_process = false;
											}else {
												/* client tried to execute an invalid or unsupported RRDtool command */
												rrdp_system__count('queries_rrdtool_invalid');
											}

										}elseif( in_array($cmd, array('exit', 'quit', 'shutdown')) === true ) {
											/* client wants to quit on a regular basis */
											$rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_CMD';
											break 4;

										}elseif(in_array($cmd, $rrdtool_custom_cmds)) {

											$rrdp_exec_status = false;
											$options = explode(' ', $cmd_options);

											switch ($cmd) {
												case 'setenv':
													if(__sizeof($options) >= 2 && in_array($options[0], $rrdtool_env_vars)) {
														$enviro_var = array_shift($options);
														putenv("'". $enviro_var. "'='" . str_replace("'", '', implode(' ', $options)) . "'");
														rrdp_system__socket_write($socket_client, encrypt(RRD_OK, $client_public_key) . $end_of_sequence);
														__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
													}else {
														rrdp_system__socket_write($socket_client, encrypt(RRD_ERROR . ' % setenv <name> <value>', $client_public_key) . $end_of_sequence);
														__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
													}
													break;

												case 'getenv':
													if(__sizeof($options)== 1 && in_array($options[0], $rrdtool_env_vars)) {
														$output = getenv($options[0]);
														rrdp_system__socket_write($socket_client, encrypt($output . "\n" . RRD_OK, $client_public_key) . $end_of_sequence);
														__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . $output . "\n" . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
													}else {
														rrdp_system__socket_write($socket_client, encrypt(RRD_ERROR . ' % getenv <name>', $client_public_key) . $end_of_sequence);
														__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
													}
													break;

												case 'setcnn':
													if(__sizeof($options) == 2 && in_array($options[0], $rrdp_client_cnn_params)) {
														if($options[0] == 'timeout') {
															if( in_array($options[1], array('null', 'off', 'disabled', '-1')) ) {
																$tv_sec = null;
																rrdp_system__socket_write($socket_client, encrypt("% Timeout disabled.\n" . RRD_OK, $client_public_key) . $end_of_sequence);
																__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
															}elseif (is_numeric($options[1])) {
																$tv_sec = abs($options[1]);
																rrdp_system__socket_write($socket_client, encrypt("% Timeout " . $tv_sec. "s.\n" . RRD_OK, $client_public_key) . $end_of_sequence);
																__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
															}else {
																rrdp_system__socket_write($socket_client, encrypt(RRD_ERROR . ' % Out of range.', $client_public_key) . $end_of_sequence);
																__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
															}
														}elseif($options[0] == 'encryption') {
															if( in_array($options[1], array('null', 'off', 'disabled', '-1')) ) {
																rrdp_system__socket_write($socket_client, encrypt("% Encryption will be disabled.\n" . RRD_OK, $client_public_key) . $end_of_sequence);
																$encryption = false;
																__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
															}else if ( in_array($options[1], array('true', 'on', 'enabled', '1')) ) {
																rrdp_system__socket_write($socket_client, encrypt("% Encryption will be enabled.\n" . RRD_OK, $client_public_key) . $end_of_sequence);
																$encryption = true;
																__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
															}else {
																rrdp_system__socket_write($socket_client, encrypt(RRD_ERROR . ' % Out of range.', $client_public_key) . $end_of_sequence);
																__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
															}
														}
													}else {
														rrdp_system__socket_write($socket_client, encrypt(RRD_ERROR . " % setcnn <parameter> <value>", $client_public_key) . $end_of_sequence);
														__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
													}
													break;

												case 'fc-list':
													$output = shell_exec('fc-list');
													rrdp_system__socket_write($socket_client, encrypt($output . "\n" . RRD_OK, $client_public_key) . $end_of_sequence);
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
													break;
												case 'rrd-list':
													/* scan RRA folder */;
													clearstatcache();
													$buffer = '';
													$rra_path_absolute = rtrim($rrdp_config['path_rra'], '/');
													$dir_iterator = new RecursiveDirectoryIterator($rra_path_absolute);
													$iterator = new RecursiveIteratorIterator($dir_iterator, RecursiveIteratorIterator::SELF_FIRST);

													foreach ($iterator as $file) {
														if (substr($file->getPathname(),-3) == 'rrd') {
															$buffer .=  str_replace( $rra_path_absolute . '/', '', $file->getPathname()) . ',' . $file->getSize() . ',' . $file->getMTime() . "\r\n";
														}
													}

													$buffer .= RRD_OK;
													$buffer_length = strlen($buffer);
													$buffer = gzencode($buffer,1);
													$buffer_length_new = strlen($buffer);
													rrdp_system__socket_write( $read_socket, encrypt( $buffer, $client_public_key) . $end_of_sequence );
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length_new . ' Bytes, compression: on , ratio: ' . round(($buffer_length/$buffer_length_new),2) . ' , packets: 1', 'IPC', SEVERITY_LEVEL_DEBUG);
													$buffer = '';
													break;
												case 'filemtime':

													$rrdp_exec_return = call_user_func_array($cmd, $options);
													rrdp_system__socket_write($socket_client, encrypt( $rrdp_exec_return . "\r\n" . RRD_OK, $client_public_key) . $end_of_sequence);
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . $rrdp_exec_return . "\r\n" . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
													break;
												case 'file_exists':
												case 'is_dir':
												case 'mkdir':

													$rrdp_exec_status = call_user_func_array($cmd, $options);
													rrdp_system__socket_write($socket_client, encrypt( ($rrdp_exec_status === true) ? RRD_OK : RRD_ERROR , $client_public_key) . $end_of_sequence);
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . ($rrdp_exec_status === true) ? RRD_OK : RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
													break;
												case 'archive':
													if(__sizeof($options[0]) && (substr($options[0],-3) == 'rrd') && file_exists($options[0]) && $rrdp_config['path_rra_archive']) {
														$source_file = $options[0];
														$target_dir  = $rrdp_config['path_rra_archive'] . '/' . ltrim(dirname($source_file), './');
														$target_file = $rrdp_config['path_rra_archive'] . '/' . $source_file;
														if (!is_dir($target_dir)) {
															mkdir($target_dir);
														}
														$rrdp_exec_status = rename($source_file, $target_file);
													}else {
														$rrdp_exec_status = false;
													}
													rrdp_system__socket_write($socket_client, encrypt( $rrdp_exec_status ? RRD_OK : RRD_ERROR , $client_public_key) . $end_of_sequence);
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . $rrdp_exec_status ? RRD_OK : RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
													break;
												case 'unlink':
													if(__sizeof($options[0]) && (substr($options[0],-3) == 'rrd') && file_exists($options[0])) {
														$rrdp_exec_status = call_user_func_array($cmd, $options);
													}else {
														$rrdp_exec_status = false;
													}
													rrdp_system__socket_write($socket_client, encrypt( ($rrdp_exec_status === true) ? RRD_OK : RRD_ERROR , $client_public_key) . $end_of_sequence);
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . ($rrdp_exec_status === true) ? RRD_OK : RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
													break;
												case 'removespikes':
													$cmd_options = str_replace('-R=.', '-R=' . $rrdp_config['path_rra'], $cmd_options);
													$rrdp_exec_return = shell_exec( PHP_BINARY . ' -q ' . $rrdp_config['path_cli'] . '/removespikes.php ' . $cmd_options);
													rrdp_system__socket_write($socket_client, encrypt( $rrdp_exec_return . "\r\n" . RRD_OK, $client_public_key) . $end_of_sequence);
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . $rrdp_exec_return . "\r\n" . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
													break;
												case 'version':
													rrdp_system__socket_write($socket_client, encrypt( RRDP_VERSION_FULL . "\r\n" . RRD_OK, $client_public_key) . $end_of_sequence);
													__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRDP_VERSION_FULL . "\r\n" . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
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
													if(__sizeof($rrdp_status['msr_commands'])>1 | $time >= $block )  {
														$msr_block = key($rrdp_status['msr_commands']);
														$msr_message['type'] = 'msr';
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
											__logging(LOGGING_LOCATION_BUFFERED, 'Client is using invalid commands.', 'IPC', SEVERITY_LEVEL_ERROR);
											rrdp_system__socket_write($socket_client, encrypt(RRD_ERROR . " % Invalid input detected", $client_public_key) . $end_of_sequence);
											$rrdp_status['status'] = 'CLOSEDOWN_BY_VIOLATION';
											break 4;
										}

									}
								}
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

								$status = unserialize(trim($input));

								if ($status !== false && $status['type']) {
									switch($status['type']) {
										case 'shutdown':
											rrdp_system__socket_write($socket_client, ( ($client_authenticated) ? encrypt(RRD_ERROR . "Shutting down ...", $client_public_key) : RRD_ERROR . "Shutting down ...") . $end_of_sequence);
											socket_close($ipc_socket_parent);
											exit;
										case 'status':
											socket_write( $ipc_socket_parent, "running\r\n");
											break 4;
										default:
											break 3;
									}
								}
							}else {
								continue;
							}
						}
					}

				}
			}
		}else {
			rrdp_system__socket_write($socket_client, "Timeout" . $end_of_sequence);
			$rrdp_status['status'] = 'CLOSEDOWN_BY_TIMEOUT';
			break 1;
		}
	}

	if($rrdtool_process) {
		rrdtool_pipe_close($rrdtool_process);
	}
	return;
}

function custom_signal_handler($signo) {

}

?>
