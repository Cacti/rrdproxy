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

function interact() {
    global $rrdp_remoteproxies, $ipc_socket_parent, $debug_mode, $rrdp_config, $rrdp_remote_proxies, $rrdp_encryption, $rrdtool_cmds, $rrdtool_custom_cmds, $rrdp_replicator_cmds, $rrdtool_msr_cmds, $rrdp_remote_clients, $rrdp_status, $rrdtool_env_vars, $rrdp_client_cnn_params;
    global $rrdcached_pid, $rrdtool_process, $rrdtool_pipes, $rrdp_encryption;
    if($rrdcached_pid) putenv('RRDCACHED_ADDRESS=unix:' . realpath('') . '/run/rrdcached.sock');

    $memory_table = array();
    $rrdp_status_backup = $rrdp_status;
    $rrdtool_process = false;
    $full_synchronized = false;
    $shutdown_triggered = false;

    $rrdp_remoteproxies = array();
    $rrdp_replicator_state = 'running';

    /* enable message encryption */
    $rsa = new \phpseclib\Crypt\RSA();

    /* start listening for cluster peers */
    $rrdp_server = @socket_create( (($rrdp_config['ipv6']) ? AF_INET : AF_INET ), SOCK_STREAM, SOL_TCP);
    if(!$rrdp_server) {
        rrd_system__system_die( PHP_EOL . "Unable to create socket. Error: " . socket_strerror(socket_last_error()) . PHP_EOL);
    }
    @socket_set_option($rrdp_server, SOL_SOCKET, SO_REUSEADDR, 1);
    if(!@socket_bind($rrdp_server, $rrdp_config['address'], $rrdp_config['port_server'])) {
        rrd_system__system_die( PHP_EOL . "Unable to bind socket to '" . $rrdp_config['address'] . ":" . $rrdp_config['port_server'] ."'" . PHP_EOL);
    };

    socket_set_option($rrdp_server,SOL_SOCKET, SO_RCVTIMEO, array("sec"=>15, "usec"=>0));
    socket_set_nonblock ($rrdp_server);
    socket_set_nonblock ($ipc_socket_parent);

    rrd_system__system_boolean_message( 'init: replicator engine [PID: ' . getmypid() .']', $rrdp_server, true);

    /* replicator startup - connect to registered peers automatically */
    if($rrdp_remote_proxies && sizeof($rrdp_remote_proxies)>0) {
        foreach($rrdp_remote_proxies as $proxy_ip => $proxy_settings) {
            /* first off verify that replication subfolders have been created for the case that a new server has been setup with an old configuration */
            if (!is_dir('./msr/' . $proxy_ip)) {
                mkdir('./msr/' . $proxy_ip);
            }

            $remote_socket = __remote_connect( $proxy_ip, $proxy_settings['port'], $proxy_settings['fingerprint'] );
            if($remote_socket !== false) {
                $rrdp_remoteproxies[ intval($remote_socket['socket']) ] = $remote_socket;
            }
        }
    }

    /* start listening for incoming requests by other new peers */
    socket_listen($rrdp_server);

    $__replicator_listening = true;
    while($__replicator_listening) {

        /* setup a dedicated persistent RRD_PIPE  */
        if($rrdtool_process === false) {
            $rrdtool_process_pipes	= rrdtool_pipe_init($rrdp_config);
            $rrdtool_process		= $rrdtool_process_pipes[0];
            $rrdtool_pipes			= $rrdtool_process_pipes[1];
        }

        $write  = array();
        $except = array();
        $tv_sec = 1;

        /* setup clients listening to socket for reading */
        $read = array();
        $read[0] = $rrdp_server;
        $read[1] = $ipc_socket_parent;

        /* all remote proxy connections need to be monitored for changes, too */
        foreach($rrdp_remoteproxies as $rrdp_remoteproxy) {
            $read[] = $rrdp_remoteproxy['socket'];
        }

        $ready = socket_select($read, $write, $except, $tv_sec);
        if($ready) {
            foreach($read as $read_socket_index => $read_socket) {
                if($read_socket == $rrdp_server) {

                    /* a proxy server is trying to connect */
                    $socket_descriptor = socket_accept($read_socket);
                    socket_getpeername($socket_descriptor, $ip);
                    /* verify authorization */
                    if( array_key_exists($ip, $rrdp_remote_proxies) === true ) {

                        $key = intval($socket_descriptor);
                        $rrdp_remoteproxies[$key] = array( 'socket' => $socket_descriptor, 'ip' => $ip, 'public_key' => false, 'authenticated' => false, 'last_seen' => time());
                        __logging(LOGGING_LOCATION_BUFFERED, 'Remote Proxy connection request #' . $key . '[IP: ' . $ip . '] granted', 'ACL', SEVERITY_LEVEL_DEBUG);

                    }else {

                        @socket_write($socket_descriptor, "ERROR: Access denied.\r\n");
                        @socket_close($socket_descriptor);
                        rrdp_system__count('connections_refused');
                        __logging(LOGGING_LOCATION_BUFFERED, 'Remote Proxy connection request [IP: ' . $ip . '] rejected.', 'ACL', SEVERITY_LEVEL_WARNING);

                    }

                }else if($read_socket == $ipc_socket_parent) {

                    /* ===> Mom is calling <=== so shut up and listen :):):) */
                    $input = '';
                    while(1) {
                        $recv = @socket_read($ipc_socket_parent, 8192, PHP_BINARY_READ );
                        if($recv === false) {
                            /* timeout  */
                            break;

                        }else if($recv == '') {

                            /* socket session dropped by proxy :/  */
                            break;

                        }else {
                            $input .= $recv;

                            if (substr($input, -1) == "\n") {
                                $status = unserialize(trim($input));

                                if ($status !== false && $status['type']) {
                                    switch($status['type']) {

                                        case 'reload_running_config':
                                            if(isset($status['rrdp_config'])) {
                                                $rrdp_config = $status['rrdp_config'];
                                                __logging(LOGGING_LOCATION_BUFFERED, 'Running config reloaded.', 'SYS', SEVERITY_LEVEL_DEBUG);
                                            }
                                            break 2;

                                        case 'reload_proxy_list':
                                            $reloaded = @include('./include/proxies');
                                            if($reloaded) {
                                                __logging(LOGGING_LOCATION_BUFFERED, 'Remote proxies list successfully reloaded.', 'SYS', SEVERITY_LEVEL_DEBUG);
                                            }else {
                                                __logging(LOGGING_LOCATION_BUFFERED, 'Unable to refresh remote proxies list.', 'SYS', SEVERITY_LEVEL_ERROR);
                                            }
                                            break 2;

                                        case 'status':
                                            // TODO - Provide more information about our connection status
                                            socket_write( $ipc_socket_parent, "running\r\n");
                                            break 2;

                                        case 'shutdown':
                                            $shutdown_triggered = true;
                                            rrdp_system__socket_write($socket_client, ( ($client_authenticated) ? encrypt(RRD_ERROR . "Shutting down ...", $client_public_key) : RRD_ERROR . "Shutting down ...") . "\r\n");
                                            socket_close($ipc_socket_parent);
                                            exit;

                                        default:
                                            break;
                                    }
                                }

                            }else {
                                continue;
                            }
                        }
                    }

                }else {
                    /* handle established remote proxy connections
                        - established does here not automatically mean authenticated.
                    */

                    $index = intval($read_socket);

                    if(isset($rrdp_remoteproxies[$index])) {

                        $input = '';
                        $output = '';

                        /* Remote proxy is talking to us */
                        while(1) {
                            $recv = @socket_read($read_socket, 100000, PHP_BINARY_READ );
                            if($recv === false) {
                                /* keep the connection persistent*/
                                break;

                            }else if($recv == '') {
                                /* socket session dropped by client */
                                rrdp_system__socket_close($read_socket, false, true);
                                unset($rrdp_remoteproxies[$index]);
                                $rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_DROP';
                                __logging(LOGGING_LOCATION_BUFFERED, 'Connection dropped by remote client #' . intval($read_socket), 'MSR', SEVERITY_LEVEL_WARNING);
                                break;

                            }else {

                                $input .= $recv;
                                if (strpos($input, "\n") !== false) {
                                    rrdp_system__count('bytes_received', rrdp_system__calc_bytes($input));

                                    if ( $rrdp_remoteproxies[$index]['authenticated'] === false ) {
                                        if(strpos($input, '-----BEGIN PUBLIC KEY-----') === false) {
                                            /* authentication failed !!! */
                                            rrdp_system__socket_close($read_socket, "Authentication failed\r\n");
                                            unset($rrdp_remoteproxies[$index]);
                                            $rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_AUTH';
                                            __logging(LOGGING_LOCATION_BUFFERED, 'Authentication failed - Invalid communication sequence #' . intval($read_socket), 'MSR', SEVERITY_LEVEL_WARNING);
                                            break;
                                        }

                                        if(strpos($input, '-----END PUBLIC KEY-----') !== false) {
                                            $client_public_key = trim($input);
                                            $ip = $rrdp_remoteproxies[$index]['ip'];
                                            $rsa_finger_print = isset($rrdp_remote_proxies[$ip]) ? $rrdp_remote_proxies[$ip]['fingerprint'] : 'unknown';

                                            $rsa->loadKey($client_public_key);

                                            if($rsa_finger_print == $rsa->getPublicKeyFingerprint()) {
                                                /* registered public key has been received */
                                                $rrdp_remoteproxies[$index]['authenticated'] = true;
                                                $rrdp_remoteproxies[$index]['public_key'] = $client_public_key;
                                                $rrdp_remoteproxies[$index]['last_seen'] = time();
                                                __logging(LOGGING_LOCATION_BUFFERED, 'Authentication successful #' . intval($read_socket), 'MSR', SEVERITY_LEVEL_DEBUG);
                                                /* send out proxy's public key */
                                                rrdp_system__socket_write($read_socket, $rrdp_encryption['public_key'] . "\r\n");
                                                $input = '';
                                                continue 2;
                                            }else {
                                                /* authentication failed !!! */
                                                rrdp_system__socket_close($read_socket, "Authentication failed\r\n");
                                                __logging(LOGGING_LOCATION_BUFFERED, 'Authentication failed - Fingerprints not matching #' . intval($read_socket), 'MSR', SEVERITY_LEVEL_WARNING);
                                                unset($rrdp_remoteproxies[$index]);
                                                $rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_AUTH';
                                                break;
                                            }
                                        }else {
                                            continue;
                                        }
                                    }else {

                                        $chunks = explode("\n", $input);
                                        $input = array_pop($chunks);

                                        foreach($chunks as $chunk) {

                                            $output .= decrypt(trim($chunk), $rrdp_encryption);

                                            if(strpos($output, "\x1f\x8b") === 0) {
                                                $output = gzdecode($output);
                                            }

                                            if ( substr_count($output, 'END_OF_MSG') ) {
                                                $output = str_replace('END_OF_MSG', '', $output);
                                                $rrdp_remoteproxies[$index]['last_seen'] = time();
                                                break 2;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        $time = time();
                        __logging(LOGGING_LOCATION_BUFFERED, $time . 'RECEIVED #[IP: ' . $rrdp_remoteproxies[intval($read_socket)]['ip'] . ']: ' .  $output, 'MSR', SEVERITY_LEVEL_DEBUG);
                        handle__request( $output, $read_socket );
                        __logging(LOGGING_LOCATION_BUFFERED, $time . 'RECEIVED #[IP: ' . $rrdp_remoteproxies[intval($read_socket)]['ip'] . ']: ' .  $output, 'MSR', SEVERITY_LEVEL_DEBUG);
                        //sleep(1);
                    }
                }
            }

        }else {

            /* non-recurring full synchronization */
            if( $full_synchronized === false & $rrdp_replicator_state == 'running' ) {

                if(microtime(true)-$rrdp_config['start'] >= 15) {

                    $remote_uptime_max = 0;
                    $remote_index = false;

                    /* ask every peer for status */
                    foreach($rrdp_remoteproxies as $index => $rrdp_remoteproxy) {

                        $remote_socket = $rrdp_remoteproxy['socket'];
                        $public_key = $rrdp_remoteproxy['public_key'];

                        rrdp_system__socket_write( $remote_socket, encrypt( 'STATUS END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                        $response = __remote_read( $remote_socket );

                        if($response !== false) {

                            $remote_uptime = $response[2];
                            $local_uptime = microtime(true)-$rrdp_config['start'];

                            /* TODO -- race condition - better you focus on delta instead of using absolute uptime */
                            if ( $remote_uptime > $local_uptime && $remote_uptime > $remote_uptime_max ) {
                                $remote_uptime_max = $remote_uptime;
                                $remote_index = $index;
                            }

                        }else {
                            /* remote proxy did not answer :| */
                        }
                    }

                    if($remote_index) {
                        $rrdp_replicator_state = 'synchronizing';
                        $read_socket = $rrdp_remoteproxies[$remote_index]['socket'];
                        $public_key = $rrdp_remoteproxies[$remote_index]['public_key'];
                        $ip = $rrdp_remoteproxies[$remote_index]['ip'];
                        __logging(LOGGING_LOCATION_BUFFERED, 'Start full synchronisation process with #' . intval($read_socket) . ' [IP: ' . $ip . ']', 'MSR', SEVERITY_LEVEL_NOTIFICATION);
                        rrdp_system__socket_write( $read_socket, encrypt( 'FULLSCAN END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                    }else {
                        /* I am a legend or the only bastard who is working */
                        $full_synchronized = true;
                    }

                }

            }else {

                /* recurring incremental synchronization */
                if( $shutdown_triggered === false ) {

                    /* ask every cluster node for DIFF updates */
                    foreach($rrdp_remoteproxies as $index => $rrdp_remoteproxy) {
                        if((time() - $rrdp_remoteproxy['last_seen']) > 5 ) {
                            //	rrdp_system__socket_write( $rrdp_remoteproxy['socket'], encrypt( 'DIFF 0 END_OF_MSG', $rrdp_remoteproxy['public_key'] ) . "\r\n", 'msr_bytes_sent');
                        }
                    }
                }
            }
        }
        //sleep(10);
        //break;
    }

}

/* internal function to establish an encrypted remote connection to registered peers */
function __remote_connect( $remote_ip, $remote_port, $remote_fingerprint ) {
    global $rrdp_config, $rrdp_encryption;

    /* enable message encryption */
    $rsa = $rsa = new \phpseclib\Crypt\RSA();

    $rrdp_socket = @socket_create( (($rrdp_config['ipv6']) ? AF_INET6 : AF_INET ), SOCK_STREAM, SOL_TCP);

    if( @socket_connect( $rrdp_socket, $remote_ip, $remote_port) === true ) {

        socket_write($rrdp_socket, $rrdp_encryption['public_key'] . "\r\n");

        /* read public key being returned by the proxy server */
        $rrdp_public_key = '';
        while(1) {
            $recv = socket_read($rrdp_socket, 1000, PHP_BINARY_READ );
            if($recv === false) {
                /* timeout  */
                $rrdp_public_key = false;
                break;
            }else if($recv == '') {
                /* session closed by remote Proxy */
                break;
            }else {
                $rrdp_public_key .= $recv;
                if (substr($rrdp_public_key, -1) == "\n") {
                    $rrdp_public_key = trim($rrdp_public_key);
                    break;
                }
            }
        }

        $rsa->loadKey($rrdp_public_key);
        $fingerprint = $rsa->getPublicKeyFingerprint();
        if($remote_fingerprint != $fingerprint) {
            /* fingerprint mismatch */
            return false;
        }else {
            return array( 'socket' => $rrdp_socket, 'ip' => $remote_ip, 'public_key' => $rrdp_public_key, 'authenticated' => true, 'last_seen' => time());
        }
    }
    return false;
}


/* internal function to read the response of a registered peer to a previous request */
function __remote_read($read_socket) {
    global $rrdp_remoteproxies, $rrdp_encryption;

    $index = intval($read_socket);
    $input = '';
    $first_packet = true;

    while(1) {
        $recv = @socket_read($read_socket, 100000, PHP_BINARY_READ );

        if($recv === false) {
            /* keep the connection persistent*/
            break;

        }else if($recv == '') {
            /* socket session dropped by client */
            rrdp_system__socket_close($read_socket, false, true);
            unset($rrdp_remoteproxies[$index]);
            $rrdp_status['status'] = 'CLOSEDOWN_BY_CLIENT_DROP';
            __logging(LOGGING_LOCATION_BUFFERED, 'Connection dropped by remote client #' . intval($read_socket), 'MSR', SEVERITY_LEVEL_WARNING);
            break;

        }else {

            $input .= $recv;
            if (strpos($input, "\n") !== false) {
                rrdp_system__count('bytes_received', rrdp_system__calc_bytes($input));

                $chunks = explode("\n", $input);
                $input = array_pop($chunks);

                foreach($chunks as $chunk) {

                    $packet = decrypt( trim($chunk), $rrdp_encryption);

                    if(strpos($packet, "\x1f\x8b") === 0) {
                        $packet = gzdecode($packet);
                    }

                    if( $first_packet ) {
                        list($cmd, $status, $payload) = explode(' ', $packet, 3);
                        $first_packet = false;
                        $packet = $payload;
                    }

                    if ( substr_count($packet, 'END_OF_MSG') ) {
                        $payload .= str_replace('END_OF_MSG', '', $packet);

                        $rrdp_remoteproxies[$index]['last_seen'] = time();

                        return array( $cmd, $status, $payload);

                        break 2;	#superfluous
                    }elseif( !$first_packet) {
                        $payload .= $packet;
                    }
                }
            }
        }
    }
    return false;
}


function handle__request( $input, $read_socket ) {
    global $rrdp_config, $rrdp_remoteproxies, $rrdp_encryption, $rrdcached_pid, $replicator_system_start, $rrdtool_process, $rrdtool_pipes;


    __logging(LOGGING_LOCATION_BUFFERED, 'INPUT: ' . $input, 'MSR', SEVERITY_LEVEL_DEBUG);


    $options = explode(' ', $input, 2);
    $type = $options[0];
    $cmd_options = isset($options[1]) ? explode(' ', $options[1]) : false;


    $index		= intval($read_socket);
    $ip 		= $rrdp_remoteproxies[$index]['ip'];
    $public_key = $rrdp_remoteproxies[$index]['public_key'];

    switch($type) {
        case 'STATUS':
            /* status request will return the UNIX uptime */
            $runtime = microtime(true)-$rrdp_config['start'];
            rrdp_system__socket_write( $read_socket,  encrypt('__STATUS 200 ' . $runtime . ' END_OF_MSG', $public_key) . "\r\n", 'msr_bytes_sent');
            __logging(LOGGING_LOCATION_BUFFERED, 'SENT [IP: ' . $ip . ']: __STATUS 200 ' . $runtime, 'MSR', SEVERITY_LEVEL_DEBUG);
            break;

        case '__STATUS':
            break;

        case 'DIFF':
            /* request the oldest DIFF file if existing */
            if($cmd_options && is_array($cmd_options) && is_numeric($cmd_options[0]) ) {
                /*
                    first argument will be used to confirm that a previous file transfer has been completed successful.
                    If this procedure will be called up for the first time, remote proxy will send "0" as arg1.
                */

                $path = './msr/' . $rrdp_remoteproxies[$index]['ip'] . '/';
                if($cmd_options[0]) {
                    $last_file = $path . $cmd_options[0];   // cmd_option[0] has already been validated by is_numeric() above
                    if( is_file( $last_file ) ) {
                        unlink($last_file);
                    }
                }

                $content = scandir($path, SCANDIR_SORT_ASCENDING);

                if(sizeof($content) >= 3) {
                    $current_file = $content[2];
                    $content_file = file_get_contents($path . $current_file);
                    $buffer = '__DIFF 200 ' . $current_file . '::' . $content_file . 'END_OF_MSG';
                    if(strlen($buffer)>65536) {
                        $buffer = gzencode($buffer,1);
                    }
                    rrdp_system__socket_write( $read_socket, encrypt( $buffer, $public_key ) . "\r\n", 'msr_bytes_sent');
                }else {
                    /* no new replication logs found - synchronization complete */
                    rrdp_system__socket_write( $read_socket, encrypt( '__DIFF 204 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                    __logging(LOGGING_LOCATION_BUFFERED, 'SENT [IP: ' . $ip . ']: __DIFF 204 ' . $runtime, 'MSR', SEVERITY_LEVEL_DEBUG);
                }
            }else {
                /* invalid request */
                __logging(LOGGING_LOCATION_BUFFERED, 'Invalid request from [IP: ' . $ip . ']: ' . $input, 'MSR', SEVERITY_LEVEL_CRITICAL);

                rrdp_system__socket_write( $read_socket, encrypt( '__DIFF 400 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                __logging(LOGGING_LOCATION_BUFFERED, 'SENT [IP: ' . $ip . ']: __DIFF 400 ' . $runtime, 'MSR', SEVERITY_LEVEL_DEBUG);
            }
            break;

        case '__DIFF':

            __logging(LOGGING_LOCATION_BUFFERED, "SERIALIZED: " . serialize($cmd_options), 'MSR', SEVERITY_LEVEL_DEBUG);


            if($cmd_options && is_array($cmd_options) && is_numeric($cmd_options[0]) ) {

                __logging(LOGGING_LOCATION_BUFFERED, "READ #1: ", 'MSR', SEVERITY_LEVEL_DEBUG);


                $status = array_shift($cmd_options);
                __logging(LOGGING_LOCATION_BUFFERED, "Status " . $status, 'MSR', SEVERITY_LEVEL_DEBUG);
                switch($status) {
                    case 200:
                        __logging(LOGGING_LOCATION_BUFFERED, "READ #200: ", 'MSR', SEVERITY_LEVEL_DEBUG);


                        $diff_content = implode(' ', $cmd_options);

                        __logging(LOGGING_LOCATION_BUFFERED, "What we have : $diff_content" , 'MSR', SEVERITY_LEVEL_CRITICAL);

                        list($period, $transactions) = explode('::', $diff_content);
                        __logging(LOGGING_LOCATION_BUFFERED, "TRANSACTIONS: " . $transactions, 'MSR', SEVERITY_LEVEL_DEBUG);

                        $transactions = explode("\r", $transactions);
                        foreach($transactions as $transaction) {

                            list($time, $transaction) = trim(explode("\t", $transaction));
                            if($time)
                                __logging(LOGGING_LOCATION_BUFFERED, '#1 ' . $transaction, 'MSR', SEVERITY_LEVEL_DEBUG);

                        }

                        //	foreach ($msr_commands as $id => $cmd) {
                        //		$buffer .= $id . "\t" . $cmd . "\r\n";
                        //	}

                        /* request next transaction log */
                        rrdp_system__socket_write( $read_socket, encrypt( 'DIFF ' . $period  .' END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                        break;
                    case 204:
                        __logging(LOGGING_LOCATION_BUFFERED, "READ #204: ", 'MSR', SEVERITY_LEVEL_DEBUG);
                        __logging(LOGGING_LOCATION_BUFFERED, 'synchronization complete ... ;) ', 'MSR', SEVERITY_LEVEL_DEBUG);
                        break;
                    case 400:
                        /* what have we done wrong ??? */
                        break;
                }
            }
            break;


        case 'FULLSCAN':
            /* fullscan makes existing(!) incremental synchronization files obsolete */
            $diff_path = './msr/' . $rrdp_remoteproxies[$index]['ip'] . '/';
            $dir_iterator = new RecursiveDirectoryIterator($diff_path, FilesystemIterator::SKIP_DOTS);
            $iterator = new RecursiveIteratorIterator($dir_iterator, RecursiveIteratorIterator::CHILD_FIRST);
            foreach ( $iterator as $file ) {
                unlink($file);
            }

            /* scan RRA folder */;
            $rra_path_absolute = rtrim($rrdp_config['path_rra'], '/');

            $dir_iterator = new RecursiveDirectoryIterator($rra_path_absolute);
            $iterator = new RecursiveIteratorIterator($dir_iterator, RecursiveIteratorIterator::SELF_FIRST);

            $buffer = false;

            foreach ($iterator as $file) {
                if( $buffer === false ) {
                    $buffer = '__FULLSCAN 200 ';
                }
                if (substr($file->getPathname(),-3) == 'rrd') {
                    $buffer .= './' . ltrim( str_replace( $rra_path_absolute, '', $file->getPath() ),'/' ) . ',' . $file->getBasename() . ',' . $file->getSize() . "," . $file->getMTime() . "\r\n" ;
                }
                if(strlen($buffer) <= 65536 ) {
                    continue;
                }else {
                    __logging(LOGGING_LOCATION_BUFFERED, $buffer, 'MSR', SEVERITY_LEVEL_DEBUG);
                    rrdp_system__socket_write( $read_socket, encrypt( gzencode($buffer,1), $public_key ) . "\r\n", 'msr_bytes_sent');
                    $buffer = '';
                }
            }

            if( $buffer === false ) {
                $buffer = '__FULLSCAN 204 ';
            }
            __logging(LOGGING_LOCATION_BUFFERED, $buffer, 'MSR', SEVERITY_LEVEL_DEBUG);
            rrdp_system__socket_write( $read_socket, encrypt( gzencode($buffer . ' END_OF_MSG',1), $public_key ) . "\r\n", 'msr_bytes_sent');

            break;

        case '__FULLSCAN':
            if($cmd_options && is_array($cmd_options)) {
                $status = $cmd_options[0];
                if($status == 200) {
                    $scan = explode( PHP_EOL, trim($cmd_options[1]) );
                    if(sizeof($scan)>0) {
                        foreach($scan as $line) {
                            $file_settings = explode(',', $line);

                            $folder 	= $file_settings[0];
                            $file 		= $file_settings[1];
                            $file_size 	= $file_settings[2];
                            $mtime 		= $file_settings[3];

                            if($folder != './') {
                                $rra_subfolder = rtrim($rrdp_config['path_rra'], '/') . '/' . ltrim($folder, './');
                                $rra_file_path_absolute = $rra_subfolder . '/' . $file;

                                /* create subfolder if not already existing */
                                if(!is_dir($rra_subfolder)) {
                                    if (mkdir($rra_subfolder) === false ) {
                                        __logging(LOGGING_LOCATION_BUFFERED, 'Cannot create RRA subfolder: ' . $rra_subfolder , 'MSR', SEVERITY_LEVEL_CRITICAL);
                                    }else {
                                        __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: created: ' . $rra_subfolder , 'MSR', SEVERITY_LEVEL_DEBUG);
                                    };

                                    if (touch($rra_subfolder, $mtime) === false) {
                                        __logging(LOGGING_LOCATION_BUFFERED, 'Cannot set modification time for RRA subfolder: ' . $rra_subfolder , 'MSR', SEVERITY_LEVEL_CRITICAL);
                                    }else {
                                        __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: set mtime: ' . $rra_subfolder , 'MSR', SEVERITY_LEVEL_DEBUG);
                                    };
                                    __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: restored: ' . $rra_subfolder , 'MSR', SEVERITY_LEVEL_INFORMATION);
                                }

                            }else {
                                $rra_file_path_absolute = rtrim($rrdp_config['path_rra'], '/') . '/' . $file;
                            }

                            if(!file_exists($rra_file_path_absolute)) {

                                __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: file not found: ' . $rra_file_path_absolute , 'MSR', SEVERITY_LEVEL_DEBUG);

                                /* request the complete dump of that RRDfile */
                                $msg = 'RRDDUMP ' . rtrim($folder, '/') . '/' . $file;
                                rrdp_system__socket_write( $read_socket, encrypt( $msg . ' END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                                __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: sent data request: ' . $msg , 'MSR', SEVERITY_LEVEL_DEBUG);

                                $response = __remote_read( $read_socket );
                                if($response !== false) {
                                    if(substr_count($response[2], "OK u")) {
                                        list($payload,$mtime) = explode(':__filemtime__:', $response[2]);
                                        $rrd_data = substr( $payload, 0, strpos($payload, "OK u"));
                                        file_put_contents( $rra_file_path_absolute . '.xml', $rrd_data );
                                        $rrd_exec_status = rrdtool_pipe_execute('restore ' . $rra_file_path_absolute . '.xml ' . $folder . '/' . $file . "\r\n", $rrdtool_pipes, false, false, false, true);
                                        if($rrd_exec_status) {
                                            touch($rra_file_path_absolute, $mtime);
                                            $memory_table[$rra_file_path_absolute] = $mtime;
                                            unlink($rra_file_path_absolute . '.xml');
                                            __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: file restored: ' . $rra_file_path_absolute , 'MSR', SEVERITY_LEVEL_DEBUG);
                                        }else {
                                            __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: file restoral failed: ' . $rra_file_path_absolute , 'MSR', SEVERITY_LEVEL_CRITICAL);
                                        }
                                    }
                                }
                            }else {
                                /* file is already existing - in this case we have to compare
                                 * local and remote last update time of this file */

                                $rrd_return = rrdtool_pipe_execute('last ' . rtrim($folder, '/') . '/' . $file . "\r\n", $rrdtool_pipes, false, false, false);
                                if ( substr_count($rrd_return, "OK u") ) {
                                    $local_last = rtrim(substr($rrd_return, 0, strpos($rrd_return, 'OK u')));
                                }else {
                                    $local_last = 0;
                                }

                                __logging(LOGGING_LOCATION_BUFFERED, 'LAST: local:' . rtrim($folder, '/') . '/' . $file . ' - ' . $local_last, 'MSR', SEVERITY_LEVEL_DEBUG);

                                /* request the local remote update time of the RRDfile */
                                rrdp_system__socket_write( $read_socket, encrypt( 'RRDLAST ' . rtrim($folder, '/') . '/' . $file . ' END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                                $response = __remote_read( $read_socket );

                                if($response !== false) {
                                    if(substr_count($response[2], "OK u")) {
                                        $remote_last = rtrim(substr($response[2], 0, strpos($response[2], 'OK u')));
                                    }else {
                                        $remote_last = 0;
                                    }

                                    __logging(LOGGING_LOCATION_BUFFERED, 'LAST: remote:' . rtrim($folder, '/') . '/' . $file . ' - ' . $remote_last, 'MSR', SEVERITY_LEVEL_DEBUG);

                                    if($local_last > $remote_last) {
                                        /* local file seems to be more up-to-date */

                                    }elseif ($local_last < $remote_last) {
                                        /* remote file is more accurate than local copy */
                                        rrdp_system__socket_write( $read_socket, encrypt( 'RRDDUMP ' . rtrim($folder, '/') . '/' . $file . ' END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                                        $response = __remote_read( $read_socket );
                                        if($response !== false) {
                                            if(substr_count($response[2], "OK u")) {
                                                list($payload,$mtime) = explode(':__filemtime__:', $response[2]);
                                                $rrd_data = substr( $payload, 0, strpos($payload, "OK u"));
                                                file_put_contents( $rra_file_path_absolute . '.xml', $rrd_data );
                                                $rrd_exec_status = rrdtool_pipe_execute('restore ' . $rra_file_path_absolute . '.xml ' . $folder . '/' . $file . ".tmp\r\n", $rrdtool_pipes, false, false, false, true);
                                                if($rrd_exec_status) {
                                                    unlink($rra_file_path_absolute);
                                                    unlink($rra_file_path_absolute . '.xml');
                                                    rename($rra_file_path_absolute . '.tmp', $rra_file_path_absolute);
                                                    touch($rra_file_path_absolute, $mtime);

                                                    $memory_table[$rra_file_path_absolute] = $mtime;

                                                    __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: file restored: ' . $rra_file_path_absolute , 'MSR', SEVERITY_LEVEL_DEBUG);
                                                }else {
                                                    __logging(LOGGING_LOCATION_BUFFERED, 'SYNC: file restoral failed: ' . $rra_file_path_absolute , 'MSR', SEVERITY_LEVEL_CRITICAL);
                                                }
                                            }

                                        }

                                    }else {

                                    }
                                }
                            }
                        }

                    }elseif ($status == 204) {

                    }else {

                    }

                }
            }
            break;

        case 'RRDLAST':

            if($cmd_options && is_array($cmd_options) && substr($cmd_options[0],-3) == 'rrd') {
                $rra_path_absolute = rtrim($rrdp_config['path_rra'], '/') . '/' . ltrim($cmd_options[0], './');
                if(file_exists($rra_path_absolute)) {

                    if($rrdcached_pid) {
                        $rrd_cmd = 'flushcached ' . $cmd_options[0];
                        $rrd_exec_status = rrdtool_pipe_execute($rrd_cmd . "\r\n", $rrdtool_pipes, false, false, false, true);
                        if(!$rrd_exec_status) {
                            __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' failed', 'MSR', SEVERITY_LEVEL_WARNING);
                            rrdp_system__socket_write( $read_socket, encrypt( '__RRDDUMP 424 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                        }else {
                            __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' executed', 'MSR', SEVERITY_LEVEL_DEBUG);
                        }
                    }

                    $rrd_cmd = 'last ' . $cmd_options[0];
                    rrdp_system__socket_write( $read_socket, encrypt( '__RRDLAST 201 ', $public_key ) . "\r\n", 'msr_bytes_sent');
                    $rrd_exec_status = rrdtool_pipe_execute($rrd_cmd . "\r\n", $rrdtool_pipes, $read_socket, $public_key, 1);
                    rrdp_system__socket_write( $read_socket, encrypt( ' END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');

                    if($rrd_exec_status) {
                        __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' executed', 'MSR', SEVERITY_LEVEL_DEBUG);
                    }else {
                        __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' failed', 'MSR', SEVERITY_LEVEL_WARNING);
                    }
                }else {
                    rrdp_system__socket_write( $read_socket, encrypt( '__RRDLAST 404 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                }

            }else {
                /* invalid request */
                rrdp_system__socket_write( $read_socket, encrypt( '__RRDLAST 400 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
            }



            break;

        case 'RRDDUMP':
            if($cmd_options && is_array($cmd_options) && substr($cmd_options[0],-3) == 'rrd') {

                $rra_path_absolute = rtrim($rrdp_config['path_rra'], '/') . '/' . ltrim($cmd_options[0], './');

                if(file_exists($rra_path_absolute)) {

                    if($rrdcached_pid) {
                        $rrd_cmd = 'flushcached ' . $cmd_options[0];
                        $rrd_exec_status = rrdtool_pipe_execute($rrd_cmd . "\r\n", $rrdtool_pipes, false, false, false, true);
                        if(!$rrd_exec_status) {
                            __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' failed', 'MSR', SEVERITY_LEVEL_WARNING);
                            rrdp_system__socket_write( $read_socket, encrypt( '__RRDDUMP 424 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                        }else {
                            __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' executed', 'MSR', SEVERITY_LEVEL_DEBUG);
                        }
                    }

                    $rrd_cmd = 'dump ' . $cmd_options[0];
                    rrdp_system__socket_write( $read_socket, encrypt( '__RRDDUMP 201 ', $public_key ) . "\r\n", 'msr_bytes_sent');
                    $rrd_exec_status = rrdtool_pipe_execute($rrd_cmd . "\r\n", $rrdtool_pipes, $read_socket, $public_key, 1);
                    rrdp_system__socket_write( $read_socket, encrypt( ':__filemtime__:' . filemtime($rra_path_absolute) . ' END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');

                    if($rrd_exec_status) {
                        __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' executed', 'MSR', SEVERITY_LEVEL_DEBUG);
                    }else {
                        __logging(LOGGING_LOCATION_BUFFERED, 'RRDTOOL: "' . $rrd_cmd . '"' . ' failed', 'MSR', SEVERITY_LEVEL_WARNING);
                    }
                }else {
                    rrdp_system__socket_write( $read_socket, encrypt( '__RRDDUMP 404 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
                }

            }else {
                /* invalid request */
                rrdp_system__socket_write( $read_socket, encrypt( '__RRDDUMP 400 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
            }
            break;

        case '__RRDDUMP':


            break;

        default:
            /* invalid request */
            //rrdp_system__socket_write( $read_socket, encrypt( '404 END_OF_MSG', $public_key ) . "\r\n", 'msr_bytes_sent');
            break;
    }
}

?>
