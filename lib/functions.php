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

function rrdtool_pipe_init($rrdp_config) {

    $fds = array(
		0 => array('pipe', 'r'),				// stdin
        1 => array('pipe', 'w'),				// stdout
        2 => array('file', '/dev/null', 'a')	// stderr
    );
    $process = @proc_open($rrdp_config['path_rrdtool'] . " - " . $rrdp_config['path_rra'], $fds, $pipes);

	if($process === false){
		return false;
	}else {
		/* make stdin/stdout/stderr non-blocking */
		stream_set_blocking($pipes[0], 0);
		stream_set_blocking($pipes[1], 0);
		return array($process, $pipes);
	}
}

function rrdtool_pipe_close($process) {
    proc_close($process);
}

function rrdtool_pipe_execute($command, $pipes, $socket, $client_public_key, $compression, $silent_mode = false) {
    $stdout = '';
    $return_code = fwrite($pipes[0], $command);

	if($return_code === false) {
		/* pipe broken */
		return null;
	}
	
	$buffer = '';
	while (!feof($pipes[1])) {
		$stdout = fread($pipes[1], 8192);
		/* don't return empty strings */
		if($stdout)	{
		
			$buffer .= $stdout;
			
			if ( substr_count($stdout, "OK u") ) {
				if(!$silent_mode) {
					rrdp_system__socket_write( $socket, encrypt( ( ($compression === true) ? gzencode($buffer,1) : $buffer ), $client_public_key) . "\r\n");	
				}
				return true;
			}elseif ( substr_count($stdout, "ERROR") ) {
				if(!$silent_mode) {
					rrdp_system__socket_write( $socket, encrypt( ( ($compression === true) ? gzencode($buffer,1) : $buffer ), $client_public_key) . "\r\n");	
				}
				return false;
			}else {
				if(strlen($buffer) <= 65536 ) {
					continue;
				}else {
					if(!$silent_mode) {
						rrdp_system__socket_write( $socket, encrypt( ( ($compression === true) ? gzencode($buffer,1) : $buffer ), $client_public_key) . "\r\n");
					}
					$buffer = '';
				}
			}
		}
	}
}

function encrypt($output, $rsa_key) {

	$rsa = new \phpseclib\Crypt\RSA();
	$aes = new \phpseclib\Crypt\Rijndael();
	$aes_key = \phpseclib\Crypt\Random::string(192);
	
	$aes->setKey($aes_key);
	$ciphertext = base64_encode($aes->encrypt($output));
	$rsa->loadKey($rsa_key);
	$aes_key = base64_encode($rsa->encrypt($aes_key));
	$aes_key_length = str_pad(dechex(strlen($aes_key)),3,'0',STR_PAD_LEFT); 
	
	return $aes_key_length . $aes_key . $ciphertext;
}

function decrypt($input, &$rrdp_encryption){
			 
	$rsa = new \phpseclib\Crypt\RSA();
	$aes = new \phpseclib\Crypt\Rijndael();

	$aes_key_length = hexdec(substr($input,0,3));
	$aes_key = base64_decode(substr($input,3,$aes_key_length)); 
	$ciphertext = base64_decode(substr($input,3+$aes_key_length));
	
	$rsa->loadKey($rrdp_encryption['private_key']);
	$aes_key = $rsa->decrypt($aes_key);
	$aes->setKey($aes_key);                       
	$plaintext = $aes->decrypt($ciphertext);

	return $plaintext;
}

