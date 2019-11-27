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

function rrdtool_pipe_execute($command, $pipes, $socket, $client_public_key, $compression, $silent_mode = false, $terminator = "_EOT_\r\n") {

    $stdout = '';
    $return_code = fwrite($pipes[0], $command);

    if($return_code === false) {
        /* pipe broken */
        __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL PIPE BROKEN caused by: ' . $command, 'IPC', SEVERITY_LEVEL_ALERT);
        return null;
    }

    $buffer = '';
    $packets = 0;
    $max_buffer_size = $compression ? 655360 : 65536;

    while (!feof($pipes[1])) {

        $stdout = fread($pipes[1], 8192);
        if($stdout) {
            $buffer .= $stdout;
        }



        if ( substr_count($buffer, "OK u") ) {

            $buffer = trim($buffer);

            if(!$silent_mode) {
                if($compression) {
                    $buffer_length = strlen($buffer);
                    $buffer = gzencode($buffer,1);

                    if($buffer === false) {
                        __logging(LOGGING_LOCATION_BUFFERED, 'COMPRESSION ERROR', 'IPC', SEVERITY_LEVEL_EMERGENCY);
                        return true;
                    }

                    $buffer_length_new = strlen($buffer);
                    rrdp_system__socket_write( $socket, encrypt( $buffer, $client_public_key) . $terminator); $packets++;
#__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE 1: ' . $terminator, 'IPC', SEVERITY_LEVEL_DEBUG);
                    __logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length_new . ' Bytes, compression: on , ratio: ' . round(($buffer_length/$buffer_length_new),2) . ' , packets: ' . $packets, 'IPC', SEVERITY_LEVEL_DEBUG);
                }else {
                    if(is_resource($socket) === true) {
                        $buffer_length = strlen($buffer);
                        rrdp_system__socket_write( $socket, encrypt( $buffer, $client_public_key) . $terminator); $packets++;
#__logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE 2: ' . $terminator, 'IPC', SEVERITY_LEVEL_DEBUG);
                        __logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length . ' Bytes, compression: off' . ' , packets: ' . $packets, 'IPC', SEVERITY_LEVEL_DEBUG);
                    }else {
                        return $buffer;
                    }
                }
            }else {
                __logging(LOGGING_LOCATION_BUFFERED, 'NO RESPONSE (silent_mode=1) ' . 'Status: ' . RRD_OK, 'IPC', SEVERITY_LEVEL_DEBUG);
            }
            return true;
        }elseif ( substr_count($buffer, "ERROR") ) {
            if(!$silent_mode) {
                if(is_resource($socket) === true) {
                    __logging(LOGGING_LOCATION_BUFFERED, $buffer, 'IPC', SEVERITY_LEVEL_DEBUG);
                    rrdp_system__socket_write( $socket, encrypt( ( ($compression === true) ? gzencode($buffer,1) : $buffer ), $client_public_key) . $terminator);
                }
            }else {
                __logging(LOGGING_LOCATION_BUFFERED, 'NO RESPONSE (silent_mode=1) ' . 'Status: ' . RRD_ERROR, 'IPC', SEVERITY_LEVEL_DEBUG);
            }
            return false;
        }else {
            if(strlen($buffer) <= $max_buffer_size | is_resource($socket) === false ) {
                continue;
            }else {
                if(!$silent_mode) {
                    if($compression) {
                        $buffer_length = strlen($buffer);
                        $buffer = gzencode($buffer,1);

                        if($buffer === false) {
                            __logging(LOGGING_LOCATION_BUFFERED, 'COMPRESSION ERROR', 'IPC', SEVERITY_LEVEL_EMERGENCY);
                            return true;
                        }

                        $buffer_length_new = strlen($buffer);
                        rrdp_system__socket_write( $socket, encrypt( $buffer, $client_public_key) . "_EOP_\r\n"); $packets++;
                        __logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length_new . ' Bytes, compression: on , ratio: ' . round(($buffer_length/$buffer_length_new),2), 'IPC', SEVERITY_LEVEL_DEBUG);
                    }else {
                        $buffer_length = strlen($buffer);
                        rrdp_system__socket_write( $socket, encrypt( $buffer, $client_public_key) . "_EOP_\r\n"); $packets++;
                        __logging(LOGGING_LOCATION_BUFFERED, 'RESPONSE: ' . RRD_OK . ', payload: ' . $buffer_length . ' Bytes, compression: off', 'IPC', SEVERITY_LEVEL_DEBUG);
                    }
                }
                $buffer = '';
            }
        }

    }
}

function encrypt($output, $rsa_key) {
    global $encryption;

    if($encryption) {
        $rsa = new \phpseclib\Crypt\RSA();
        $aes = new \phpseclib\Crypt\Rijndael();
        $aes_key = \phpseclib\Crypt\Random::string(192);

        $aes->setKey($aes_key);
        $ciphertext = base64_encode($aes->encrypt($output));
        $rsa->loadKey($rsa_key);
        $aes_key = base64_encode($rsa->encrypt($aes_key));
        $aes_key_length = str_pad(dechex(strlen($aes_key)),3,'0',STR_PAD_LEFT);

        return $aes_key_length . $aes_key . $ciphertext;
    }else {
        return $output;
    }
}

function decrypt($input){
    global $rrdp_config, $encryption;

    if($encryption) {
        $rsa = new \phpseclib\Crypt\RSA();
        $aes = new \phpseclib\Crypt\Rijndael();

        $aes_key_length = hexdec(substr($input,0,3));
        $aes_key = base64_decode(substr($input,3,$aes_key_length));
        $ciphertext = base64_decode(substr($input,3+$aes_key_length));

        $rsa->loadKey($rrdp_config['encryption']['private_key']);
        $aes_key = $rsa->decrypt($aes_key);
        $aes->setKey($aes_key);
        $plaintext = $aes->decrypt($ciphertext);

        return $plaintext;
    }else {
        return $input;
    }
}

function __logging($location, $msg, $category, $severity) {
    global $rrdp_config, $ipc_socket_parent, $ipc_global_resource_id, $severity_levels, $c_pid;

    if ( ($location === LOGGING_LOCATION_BUFFERED && $rrdp_config['logging_severity_buffered'] && $severity <= $rrdp_config['logging_severity_buffered'])
        || ($location === LOGGING_LOCATION_SNMP && $rrdp_config['logging_severity_snmp'] && $severity <= $rrdp_config['logging_severity_snmp'])
        || ($rrdp_config['logging_severity_console'] && $severity <= $rrdp_config['logging_severity_console'] && ( $rrdp_config['logging_category_console'] == 'all' || stripos($rrdp_config['logging_category_console'], $category) !== false) ) ) {

        socket_write( $ipc_socket_parent, serialize( array('type' => 'debug', 'debug' => array('msg' => '#' . $ipc_global_resource_id . ' [' . $c_pid . '] ' . $msg, 'category' => $category, 'severity' => $severity, 'location' => $location ) ) ) . "\r\n");
        #	if($severity === SEVERITY_LEVEL_DEBUG) usleep(100000);
    }
    return;
}

function __sizeof($array) {
	return ($array === false || !is_array($array)) ? 0 : sizeof($array);
}
function __count($array) {
	return ($array === false || !is_array($array)) ? 0 : count($array);
}

function __errorHandler($code, $text, $file, $line) {

    if (!(error_reporting() & $code)) {
        return;
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

/*  client signal handler  */
function __sig_handler($signo) {
    switch ($signo) {
        case SIGTERM :
            exit ;
            break;
        case SIGHUP :
            break;
        case SIGUSR1 :
            break;
        default :
    }
}

function is_rrdtool_proxy_running() {
	exec('ps -ef | grep -v grep | grep -E "php .*rrdtool-proxy.php"', $output);
	return (__sizeof($output) >= 2 ) ? false : true;
}

function is_rrdcached_running() {
	exec('ps -ef | grep -v grep | grep -v "sh -c" | grep rrdcached', $output);
	return (__sizeof($output) >= 2 && !$force ) ? false : true;
}

