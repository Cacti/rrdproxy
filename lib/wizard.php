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
	$active_config = array();
	
	$rrdp_default_config = array(
		'name' => 'rrdp',
		'address' => '0.0.0.0',
		'port_client' => 40301,
		'port_server' => 40302,
		'port_admin' => 40303,
		'max_admin_cnn' => 5,
		'remote_cnn_timeout' => 5,
		'logging_buffer' => 10000,
		'path_rra' => realpath('./rra'),
		'path_rrdtool' => '/usr/bin/rrdtool',
		'path_rrdcached' => '/usr/bin/rrdcached',
		'rrdcache_update_cycle' => 600,
		'rrdcache_update_delay' => 0,
		'rrdcache_life_cycle' => 7200,
		'rrdcache_write_threads' => 4,
	);
	
	wizard();
	
	function wizard() {
	
		global $microtime_start, $rrdp_default_config, $active_config;

		/* include external libraries */
		set_include_path("./include/phpseclib/");
		require_once('Math/BigInteger.php');
		require_once('Crypt/Base.php');
		require_once('Crypt/Hash.php');
		require_once('Crypt/Random.php');
		require_once('Crypt/RSA.php');
		require_once('Crypt/Rijndael.php');
		
		#### -- WELCOME -- ####
		wizard_handle_output("\033[1;33;44m   RRDtool Proxy Server Wizard                                              1/7 \033[0m", false, true, true);
		$msg = 'Welcome to the Wizard of the RRDtool Proxy Server brought to you by the Cacti Group. '
			 . 'This tool allows you to setup the RRDtool Proxy Server for the first time as well as to reconfigure an existing configuration. '
			 . 'You can abort this script anytime with CTRL+C and restart this wizard with following command: <path_to_php> ./rrdtool-proxy.php --wizard' . PHP_EOL . PHP_EOL
			 . 'Default values or already existing configuration parameters will be shown in square brackets. Simply press ENTER to reuse them. '
			 . 'After a new configuration file has been written a running instance of the RRDtool proxy server needs to be restarted to apply all of your changes.';
			 
		
		wizard_handle_output( wordwrap($msg, 75), true, true);
		
		$filter_options = array('options' => array('regexp' => '/[\s]*/'));
		wizard_handle_input("\033[1mPress ENTER to continue ...\033[0m", FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;		

	#### -- SYSTEM REQUIREMENTS -- ####
		wizard_handle_output("\033[1;33;44m   RRDtool Proxy Server Wizard                                              2/7 \033[0m", false, true, true);
		wizard_handle_output('Checking System Requirements...', true);
		
		$microtime_start = microtime(true);		// reset system start time	
		$support_os = strstr(PHP_OS, "WIN") ? false : true;
		rrd_system__system_boolean_message( 'test: operation system supported', $support_os, true );

		/* check state of required and optional php modules */
		rrd_system__system_boolean_message( 'test: php module \'sockets\'', extension_loaded('sockets'), true );
		rrd_system__system_boolean_message( 'test: php module \'posix\'', extension_loaded('posix'), true );
		rrd_system__system_boolean_message( 'test: php module \'pcntl\'', extension_loaded('pcntl'), true );
		rrd_system__system_boolean_message( 'test: php module \'gmp\'', extension_loaded('gmp'), true );
		rrd_system__system_boolean_message( 'test: php module \'openssl\'', extension_loaded('openssl'), true );
		rrd_system__system_boolean_message( 'test: php module \'zlib\'', extension_loaded('zlib'), true );
		#rrd_system__system_boolean_message( 'test: php module \'readline\'', extension_loaded('readline'), true );

		exec("ulimit -n", $max_open_files);
		$pid_of_php = getmypid();		
		exec("ls -l /proc/$pid_of_php/fd/ | wc -l", $open_files);
		if($max_open_files[0] == 'unlimited') $max_open_files[0] = 1048576;
		rrd_system__system_boolean_message( 'test: max. number of open files [' . $max_open_files[0] . ']', $max_open_files[0], true );
		rrd_system__system_boolean_message( 'test: max. number of connections in backlog [' . SOMAXCONN . ']', SOMAXCONN, true );
		
		wizard_handle_output(PHP_EOL . 'Checking System Settings...', true);
		/* detect network interfaces */
		exec("ifconfig | grep 'inet ' |  grep -v 127.0.0.1 | sed -e 's/Bcast//' | sed -e 's/Mask//' | cut -d: -f2", $network_interfaces);
		rrd_system__system_boolean_message( 'test: network interfaces [' . sizeof($network_interfaces) . ']', $network_interfaces, true);

		/* create a Service TCP Stream socket supporting IPv6 and 4 */
		$test_socket = @socket_create(AF_INET6 , SOCK_STREAM, SOL_TCP);
		if(socket_last_error() == 97) {
			$system__ipv6_supported = false;
			socket_clear_error();
			$test_socket = @socket_create(AF_INET , SOCK_STREAM, SOL_TCP);
		}else {
			$system__ipv6_supported = true;
		}
		rrd_system__system_boolean_message( 'test: ipv6 supported', $system__ipv6_supported);
		rrd_system__system_boolean_message( 'test: socket module', $test_socket, true);
		

		wizard_handle_output(PHP_EOL . 'Checking System Configurations...', true);
		$system__include_folder_writeable = is_readable('./include');
		rrd_system__system_boolean_message( 'test: Include folder is readable', $system__include_folder_writeable, true );		
		
		$system__include_folder_writeable = is_writable('./include');
		rrd_system__system_boolean_message( 'test: Include folder is writeable', $system__include_folder_writeable, true );
		
		$system__config = file_exists('./include/config');
		if($system__config) {
			include_once('./include/config');
			$system__config = (isset($rrdp_config) && is_array($rrdp_config));
		}
		rrd_system__system_boolean_message( 'read: RRDproxy configuration file', $system__config, false );

		
		$system__config_tmp = file_exists('./include/config.tmp');
		if($system__config_tmp) {
			include_once('./include/config.tmp');
			$system__config_tmp = (isset($rrdp_config_tmp) && is_array($rrdp_config_tmp));
		}
		rrd_system__system_boolean_message( 'read: RRDproxy temporary configuration file', $system__config_tmp, false );
		
		$system__public_key = file_exists('./include/public.key');
		rrd_system__system_boolean_message( 'read: RSA public key', $system__public_key, false );
		$system__private_key = file_exists('./include/private.key');
		rrd_system__system_boolean_message( 'read: RSA private key', $system__private_key, false );		
		$system__proxies = file_exists('./include/proxies');
		rrd_system__system_boolean_message( 'read: Server configuration', $system__proxies, false );
		$system__clients = file_exists('./include/clients');
		rrd_system__system_boolean_message( 'read: Client configuration', $system__clients, false );

		$filter_options = array('options' => array('regexp' => '/[\s]*/'));
		wizard_handle_input( PHP_EOL . "\033[1mPress ENTER to continue ...\033[0m", FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;	
		
	
	#### -- DATA ENCRYPTION -- ####
		wizard_handle_output("\033[1;33;44m   RRDtool Proxy Server Wizard                                              3/7 \033[0m", false, true, true);

		$microtime_start = microtime(true);		// reset system start time	
		
		$msg = 'RRDproxy requires data encryption for client to proxy as well as proxy to proxy communication due to security reasons. '
			 . 'Unencrypted connections will not be supported. ' . PHP_EOL 
			 . 'In detail data gets encrypted by single-use AES keys of 192Bit while 2048Bit RSA will be used for the key exchange itself. '
			 . 'Please note that this version does currently not have an embedded RSA key rotation process.';
		
		if($system__public_key & $system__private_key) {
			$msg .= PHP_EOL 
				 . PHP_EOL . "\033[1;32m**RSA key-pair detected:"
				 . PHP_EOL . "  Public Key  (last updated: " . date ("F d Y H:i:s", filemtime('./include/public.key')) . ")"
				 . PHP_EOL . "  Private Key (last updated: " . date ("F d Y H:i:s", filemtime('./include/private.key')) . ")\033[0m" . PHP_EOL
				 . PHP_EOL . "\033[1mWould you like to reuse the existing RSA key-pair? [y/n]\033[0m";
			$pattern = '/[yYnN]/';
			$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
			$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
			$microtime_start = microtime(true);	// reset system start time
			if($input == 'Y') {
				rrd_system__system_boolean_message( 'load: RSA public key', $system__public_key, true );
				rrd_system__system_boolean_message( 'load: RSA private key', $system__private_key, true );
				$refresh_rsa_keys = false;
			}else {
				rrd_system__system_boolean_message( 'delete: Old RSA public key', unlink('./include/public.key'), true );
				rrd_system__system_boolean_message( 'delete: Old RSA private key', unlink('./include/private.key'), true );
				$refresh_rsa_keys = true;
			}
		}else {
			$refresh_rsa_keys = true;
			wizard_handle_output( wordwrap($msg, 75), true, true);
		}

		if($refresh_rsa_keys === true) {
			$rsa = new \phpseclib\Crypt\RSA();
			$keys = $rsa->createKey(2048);
			rrd_system__system_boolean_message( 'create: Generate RSA key-pair (2048Bit)', $keys, true );
			rrd_system__system_boolean_message( '  save: New RSA public key', file_put_contents('./include/public.key', $keys['publickey']), true );
			rrd_system__system_boolean_message( '  save: New RSA private key', file_put_contents('./include/private.key', $keys['privatekey']), true );
		}

		$filter_options = array('options' => array('regexp' => '/[\s]*/'));
		wizard_handle_input( PHP_EOL . "\033[1mPress ENTER to continue ...\033[0m", FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;			

		
	#### -- SYSTEM Parameters -- ####
		wizard_handle_output("\033[1;33;44m   RRDtool Proxy Server Wizard                                              4/7 \033[0m", false, true, true);

		$msg = 'This section allows to modify different system and connection parameters of RRDproxy. If your have any doubts whether you should modify a value or not '
		     . 'you can go on with the default value shown in square brackets by just pressing ENTER. ';
		wizard_handle_output( wordwrap($msg, 75), true, true);
	
		if($system__config_tmp) {
			$msg = "\033[1;32m**Temporary Wizard Configuration detected:"
				 . PHP_EOL . "  Temporary configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/config.tmp')) . ")\033[0m" . PHP_EOL
				 . PHP_EOL . "\033[1mWould you like to reload all configuration parameters of your last wizard session? [y/n]\033[0m";
			$pattern = '/[yYnN]/';
			$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
			$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );		
			$microtime_start = microtime(true);	// reset system start time		
			if($input == 'Y') {
				$active_config = $rrdp_config_tmp;
				rrd_system__system_boolean_message( 'restore: Temporary session data', $active_config, true );
			}else {
				$status = unlink('./include/config.tmp');
				rrd_system__system_boolean_message( ' delete: Temporary session data', $status, false );
			}
			wizard_handle_output( '', true, true);	
			unset($rrdp_config_tmp);
		}
		
		if($system__config) {
			$msg = "\033[1;32m**RRDproxy Configuration detected:"
				 . PHP_EOL . "  Configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/config')) . ")\033[0m" . PHP_EOL
				 . PHP_EOL . "\033[1mWould you like to reload all parameters of this configuration file? " . ($system__config_tmp ? '(Note: This will overwrite one or more attributes of session data being restored one step before.) ' : '' ) . "[y/n]\033[1m";
			$pattern = '/[yYnN]/';
			$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
			$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );		
			$microtime_start = microtime(true);	// reset system start time		
			if($input == 'Y') {
				$active_config = $rrdp_config;
				rrd_system__system_boolean_message( 'restore: System Configuration', $active_config, true );
			}else {
				$status = unlink('./include/config');
				rrd_system__system_boolean_message( ' delete: System Configuration', $status, false );
			}
			wizard_handle_output( '', true, true);	
			unset($rrdp_config);
		}
		
		/* neither a final nor a temporary system configuration file have been found */
		if(!isset($active_config)) {
			wizard_handle_output( '', true);	
			$active_config = array();
		}
			
		foreach($rrdp_default_config as $index => $value) {
			if( !isset($active_config[$index])) {
				$active_config[$index] = $value;
			}
		}			

		$rrdp_default_config_inputs = array(
			'name' => array(
				'msg' => "\033[1;32ma)\033[0m For local administration tasks RRDproxy offers its own CLI. Define your own system prompt of max. 8 characters [%s]:",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^[\s|\w]{0,8}$/',
				'help' => '% Only whitespace and wording characters including underscore'
			),
			'address' => array(
				'msg' => "\033[1;32mb)\033[0m Following IP addresses have been detected on your system:" . PHP_EOL . '  '
						. implode(',', $network_interfaces) . PHP_EOL 
						. 'Choose one IP the proxy should listen to for incoming requests or press ENTER to listen to all interfaces:',
				'filter' => FILTER_VALIDATE_IP,
				'filter_options' => array('default' => '0.0.0.0'),
				'help' => '% Only valid IPv4 or IPv6 addresses or 0.0.0.0'
			),
			'port_client' => array(
				'msg' => "\033[1;32mc)\033[0m Active clients (like Cacti servers for example) have to connect to the proxy using a dedicated TCP port [%s]:",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/',
				'help' => '% Only valid port numbers between 1024 and 65535'
			),
			'port_server' => array(
				'msg' => "\033[1;32md)\033[0m Proxy to proxy connections have to run over a separate path using a different port [%s]:",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/',
				'help' => '% Only valid port numbers between 1024 and 65535'
			),
			'port_admin' => array(
				'msg' => "\033[1;32me)\033[0m Administrators have to connect to the proxy interface locally using a dedicated TCP port. [%s]:",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/',
				'help' => '% Only valid port numbers between 1024 and 65535'
			),
			'max_admin_cnn' => array(
				'msg' => "\033[1;32mf)\033[0m Maximum number of concurrent local (admin) sessions being allowed [%s]:",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^([1-9]|10)$/',
				'help' => '% Range 1 - 10'
			),
			'remote_cnn_timeout' => array(
				'msg' => "\033[1;32mh)\033[0m Timeout value for client to proxy connections in seconds [%s]:",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^([1-9]|1[0-9]|2[0-9]|30)$/',
				'help' => '% Range 1 - 30'
			),
			'logging_buffer' => array(
				'msg' => "\033[1;32mi)\033[0m Maximum number of log entries this system will keep in memory [%s]:",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^([1-9]\d{3,4}|100000)$/',
				'help' => '% Range 1 000 - 100 000'
			),
			'path_rra' => array(
				'msg' => "\033[1;32mj)\033[0m Absolute(!) path to the RRA folder containing all RRDfiles [%s]:",
				'filter' => FILTER_CALLBACK,
				'filter_options' => 'wizard_verify_path'
			),
			'path_rrdtool' => array(
				'msg' => "\033[1;32mj)\033[0m Absolute(!) path to your RRDtool binary [%s]:",
				'filter' => FILTER_CALLBACK,
				'filter_options' => 'wizard_verify_rrdtool'
			),
		);
			
		wizard_handle_output( "\033[1mSettings:\033[0m", false, false);
		foreach( $active_config as $attribute => $value ) {
			if(isset($rrdp_default_config_inputs[$attribute])) {
				
				if(isset($rrdp_default_config_inputs[$attribute]['filter_options'])) {
					$filter_options['options'] = $rrdp_default_config_inputs[$attribute]['filter_options'];
				}else {
					$filter_options = array();
					if($rrdp_default_config_inputs[$attribute]['filter'] == FILTER_VALIDATE_REGEXP) {
						$filter_options = array('options'=>array('regexp'=>$rrdp_default_config_inputs[$attribute]['pattern']));
					}
				}
				$input = wizard_handle_input( wordwrap( sprintf($rrdp_default_config_inputs[$attribute]['msg'], $value), 75), $rrdp_default_config_inputs[$attribute]['filter'], $filter_options, (isset($rrdp_default_config_inputs[$attribute]['help']) ? $rrdp_default_config_inputs[$attribute]['help'] : false), true);
				if($input) { 
					$active_config[$attribute] = $input;
				}
				file_put_contents('./include/config.tmp', '<?php $rrdp_config_tmp = ' . var_export($active_config, true) . ';');
			}
		}
		
	#### -- Cache Settings -- ####
		wizard_handle_output("\033[1;33;44m   RRDtool Proxy Server Wizard                                              5/7 \033[0m", false, true, true);
		$msg = 'If you are not making use of other I/O caches like Cacti-BOOST you can setup the proxy to manage a caching daemon, "RRDcached", offered by RRDtool itself.'
			 . 'Using RRDcache will reduce dramatically the I/O load of your file system and avoid, if configured correctly, '
			 . 'that RRD files will be updated with every update command being received.';
		wizard_handle_output( wordwrap($msg, 75), true, true);

		$msg = "\033[1mWould you like to enable the use of RRDCached? [y/n]\033[0m";

		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
		if($input == 'Y') {

			$rrdp_rrdcached_config_inputs = array(
				'path_rrdcached' => array(
					'msg' => "\033[1;32ma)\033[0m Absolute(!) path to your RRDCached binary [%s]:",
					'filter' => FILTER_CALLBACK,
					'filter_options' => 'wizard_verify_rrdcached'
				),
				'rrdcache_update_cycle' => array(
					'msg' => "\033[1;32mb)\033[0m Threshold in seconds mesaurements of an active polling object will be keept in memory. If breached related cached data will be written to disk.[%s]:",
					'filter' => FILTER_VALIDATE_REGEXP,
					'pattern' => '/^$|^([1-9]\d{1,3}|10000)$/',
					'help' => '% Range 10 - 10 000'
				),
				'rrdcache_update_delay' => array(
					'msg' => "\033[1;32mc)\033[0m A random delay between 0 and x seconds RRDcache will delay writing of each RRD to avoid too many writes being queued simultaneously. By default, there is no delay.[%s]:",
					'filter' => FILTER_VALIDATE_REGEXP,
					'pattern' => '/^$|^(0|[1-9]\d{1}|10)$/',
					'help' => '% Range 0 - 10'
				),
				'rrdcache_life_cycle' => array(
					'msg' => "\033[1;32md)\033[0m Define the number of seconds RRDcached should scan the complete cache to ensure that measurements no longer being updated will be written to disk. This process is CPU intensive and should not be executed too often. Due to that reason a high value of e.g. 7200 is acceptable in most cases.[%s]:",
					'filter' => FILTER_VALIDATE_REGEXP,
					'pattern' => '/^$|^([1-9]\d{3}|10000)$/',
					'help' => '% Range 1 000 - 10 000'
				),
				'rrdcache_write_threads' => array(
					'msg' => "\033[1;32me)\033[0m Specify the number of write threads used for writing RRD files. Increasing this number will allow RRDCached to have more simultaneous I/O requests into the kernel. Default value is 4.[%s]:",
					'filter' => FILTER_VALIDATE_REGEXP,
					'pattern' => '/^$|^([1-9]\d{1}|10)$/',
					'help' => '% Range 1 - 10'
				),

			);

			wizard_handle_output( "\033[1mSettings:\033[0m", false, false);
			foreach( $active_config as $attribute => $value ) {
				if(isset($rrdp_rrdcached_config_inputs[$attribute])) {

					if(isset($rrdp_rrdcached_config_inputs[$attribute]['filter_options'])) {
						$filter_options['options'] = $rrdp_rrdcached_config_inputs[$attribute]['filter_options'];
					}else {
						$filter_options = array();
						if($rrdp_rrdcached_config_inputs[$attribute]['filter'] == FILTER_VALIDATE_REGEXP) {
							$filter_options = array('options'=>array('regexp'=>$rrdp_rrdcached_config_inputs[$attribute]['pattern']));
						}
					}
					$input = wizard_handle_input( wordwrap( sprintf($rrdp_rrdcached_config_inputs[$attribute]['msg'], $value), 75), $rrdp_rrdcached_config_inputs[$attribute]['filter'], $filter_options, (isset($rrdp_rrdcached_config_inputs[$attribute]['help']) ? $rrdp_rrdcached_config_inputs[$attribute]['help'] : false), true);
					if($input) {
						$active_config[$attribute] = $input;
					}
					file_put_contents('./include/config.tmp', '<?php $rrdp_config_tmp = ' . var_export($active_config, true) . ';');
				}
			}

		}else {
			$active_config['path_rrdcached'] = '';
			file_put_contents('./include/config.tmp', '<?php $rrdp_config_tmp = ' . var_export($active_config, true) . ';');
		}
		wizard_handle_output( '', true, true);


		$filter_options = array('options' => array('regexp' => '/[\s]*/'));
		wizard_handle_input( PHP_EOL . "\033[1mPress ENTER to save new system configuration ...\033[0m", FILTER_VALIDATE_REGEXP, $filter_options, false, true );
		$microtime_start = microtime(true);	// reset system start time	
		rrd_system__system_boolean_message( '   save: New system configuration', file_put_contents('./include/config', '<?php $rrdp_config = ' . var_export($active_config, true) . ';'), true );
		rrd_system__system_boolean_message( ' delete: Temporary session data', unlink('./include/config.tmp'), true );		
				
		$filter_options = array('options' => array('regexp' => '/[\s]*/'));
		wizard_handle_input( PHP_EOL . "\033[1mPress ENTER to continue ...\033[0m", FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;	
		
	#### -- Client Connections -- ####
		wizard_handle_output("\033[1;33;44m   RRDtool Proxy Server Wizard                                              6/7 \033[0m", false, true, true);
		$msg = 'This version does not support the automatic registration of new trusted clients - these have to be defined manually. '
			 . 'To decide whether a client has the permission to access RRDs through the proxy its IP address as well as the fingerprint '
			 . 'of its current public RSA key has to be registered to RRDproxy.' .  PHP_EOL 
			 . 'Please note: Every kind of external device, like a Cacti poller for example, is a RRDproxy client. Other RRDproxies have to be registered in section 7.';
		wizard_handle_output( wordwrap($msg, 75), true, true);
		
		if($system__clients) {
			$msg = "\033[1;32m**RRDproxy Trusted Clients detected:"
				 . PHP_EOL . "  Configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/clients')) . ")\033[0m" . PHP_EOL
				 . PHP_EOL . "\033[1mWould you like to reuse all entries of this configuration file? [y/n]\033[0m";
			$pattern = '/[yYnN]/';
			$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
			$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );		
			$microtime_start = microtime(true);	// reset system start time		
			if($input == 'Y') {
				include_once('./include/clients');
				rrd_system__system_boolean_message( 'load: Trusted Client Connections', isset($rrdp_remote_clients), true );
				
				if( sizeof($rrdp_remote_clients) > 0 ) {
					wizard_handle_output( '', true, true);
					$output = sprintf(" %-27s %-12s " . PHP_EOL, 'IP Address', 'Fingerprint');
					foreach($rrdp_remote_clients as $ip => $fingerprint) {
						$output .= sprintf(" %-27s %s \r\n", $ip, $fingerprint );
					}
					wizard_handle_output( $output, true, false);
				}
			
			}else {
				$status = unlink('./include/clients');
				rrd_system__system_boolean_message( ' delete: Trusted Client Connections', $status, false );
			}
			wizard_handle_output( '', true, true);	
		}

		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		while(1) {
			$msg = 'Would you like to add '	. (isset($rrdp_remote_clients) ? 'another ' : 'a new ') . 'trusted client connection ? [y/n]';
			$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
			
			if(!isset($rrdp_remote_clients)) {
				$rrdp_remote_clients = array();
			}
			
			if($input == 'N') {
				$microtime_start = microtime(true);	// reset system start time
				rrd_system__system_boolean_message( ' save: New client configuration', file_put_contents('./include/clients', '<?php $rrdp_remote_clients = ' . var_export($rrdp_remote_clients, true) . ';'), true );
				wizard_handle_output( '', true, false);
				if(!sizeof($rrdp_remote_clients)>0) {
					$msg = '**Warning: You haven\'t defined any trusted client connection yet. External systems will not be able to connect to the proxy.';
					wizard_handle_output( wordwrap($msg, 75), true, true);
				}
				$msg = 'Tip: Use "set client add <IP> <Fingerprint>" within the admin console to add new clients dynamically.';
				wizard_handle_output( wordwrap($msg, 75), true, true);
				break;
			}elseif($input == 'Y') {
				$client_ip = wizard_handle_input('IP:', FILTER_VALIDATE_IP, false, '% Invalid IPv4 or IPv6 address format');
				$client_fingerprint =  wizard_handle_input('Fingerprint:', FILTER_VALIDATE_REGEXP, array("options"=>array("regexp"=>"/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/")), '% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]');
				$rrdp_remote_clients[$client_ip] = $client_fingerprint;
			}
		}

		$filter_options = array('options' => array('regexp' => '/[\s]*/'));
		wizard_handle_input( PHP_EOL . "\033[1mPress ENTER to continue ...\033[0m", FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;	
		
		
	#### -- Proxy-2-Proxy Connections -- ####
		wizard_handle_output("\033[1;33;44m   RRDtool Proxy Server Wizard                                              7/7 \033[0m", false, true, true);
		$msg = 'This version does not support the automatic registration of new proxy cluster members - these have to be defined manually. '
			 . 'To decide whether a cluster member has the correct permissions its IP address as well as the fingerprint of its current public RSA key has to be registered to the RRDproxy.';
		wizard_handle_output( wordwrap($msg, 75), true, true);
		
		if($system__proxies) {
			$msg = "\033[1;32m**RRDproxy Trusted Proxies detected:"
				 . PHP_EOL . "  Configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/proxies')) . ")\033[0m" . PHP_EOL
				 . PHP_EOL . "\033[1mWould you like to reuse all entries of this configuration file? [y/n]\033[0m";
			$pattern = '/[yYnN]/';
			$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
			$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );		
			$microtime_start = microtime(true);	// reset system start time		
			if($input == 'Y') {
				include_once('./include/proxies');
				rrd_system__system_boolean_message( 'load: Trusted Proxy Connections', isset($rrdp_remote_proxies), true );
				
				if( sizeof($rrdp_remote_proxies) > 0 ) {
					wizard_handle_output( '', true, true);
					$output = sprintf(" %-27s %-12s " . PHP_EOL, 'IP Address', 'Fingerprint');
					foreach($rrdp_remote_proxies as $ip => $fingerprint) {
						$output .= sprintf(" %-27s %s \r\n", $ip, $fingerprint );
					}
					wizard_handle_output( $output, true, false);
				}
			
			}else {
				$status = unlink('./include/proxies');
				rrd_system__system_boolean_message( ' delete: Trusted Proxy Connections', $status, false );
			}
			wizard_handle_output( '', true, true);	
		}

		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		while(1) {
			$msg = 'Would you like to add '	. (isset($rrdp_remote_proxies) ? 'another ' : 'a new ') . 'trusted proxy connection ? [y/n]';
			$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
			
			if(!isset($rrdp_remote_proxies)) {
				$rrdp_remote_proxies = array();
			}
			
			if($input == 'N') {
				$microtime_start = microtime(true);	// reset system start time
				rrd_system__system_boolean_message( ' save: New proxy configuration', file_put_contents('./include/proxies', '<?php $rrdp_remote_proxies = ' . var_export($rrdp_remote_proxies, true) . ';'), true );
				wizard_handle_output( '', true, false);

				$msg = 'Tip: Use "set proxy add <IP> <Port> <Fingerprint>" within the admin console to add new clients dynamically.';
				wizard_handle_output( wordwrap($msg, 75), true, true);
				break;
			}elseif($input == 'Y') {
				$client_ip = wizard_handle_input('IP:', FILTER_VALIDATE_IP, false, '% Invalid IPv4 or IPv6 address format');
				$client_port = wizard_handle_input('PORT:', FILTER_VALIDATE_REGEXP, array('options'=>array('regexp'=>'/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/')), '% Invalid PORT. Range: [1024-65535]');
				$client_fingerprint =  wizard_handle_input('Fingerprint:', FILTER_VALIDATE_REGEXP, array("options"=>array("regexp"=>"/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/")), '% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]');
				$rrdp_remote_proxies[$client_ip] = array('port' => $client_port, 'fingerprint' => $client_fingerprint);
			}
		}

		$filter_options = array('options' => array('regexp' => '/[\s]*/'));
		wizard_handle_input( PHP_EOL . "\033[1mPress ENTER to continue ...\033[0m", FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;

	}
	
	
	function wizard_verify_rrdtool($path) {
		global $active_config;
	
		$valid_path = false;
		if(!$path) $path = $active_config['path_rrdtool'];
	
		/* Get RRDtool version */
		if( strpos( $path, '.' ) === 0 ) {
			$msg = "Path is not absolute.";
		}elseif ( !file_exists($path) ) {
			$msg = "File not found";
		}elseif ( !is_executable($path) ) {
			$msg = "File is not executable.";
		}else {
			$out_array = array();
			exec( escapeshellcmd($path) . ' 2>/dev/null', $out_array);
			if (sizeof($out_array) > 0) {
				if(strpos($out_array[0], 'RRDtool') !== 0) {
					$msg = "Invalid output.";
				}else {
					if (preg_match('/^RRDtool ([1-9]\.[0-9])/', $out_array[0], $m)) {
						if( version_compare( $m[1], '1.5', '>=')) {
							$valid_path = true;
						}else {
							$msg = "RRDtool version 1.5 or above required.";
						}
					}
				}
			}else {
				$msg = "Invalid output.";
			}
		}
		
		if($valid_path) {
			return $path;
		}else {
			wizard_handle_output("\033[0;31m%$msg\033[0m" . PHP_EOL);
			return false;
		}
	}
	
	function wizard_verify_rrdcached($path) {
		global $active_config;

		$valid_path = false;
		if(!$path) $path = $active_config['path_rrdcached'];

		/* Get RRDtool version */
		if( strpos( $path, '.' ) === 0 ) {
			$msg = "Path is not absolute.";
		}elseif ( !file_exists($path) ) {
			$msg = "File not found";
		}elseif ( !is_executable($path) ) {
			$msg = "File is not executable.";
		}else {
			$valid_path = true;
		}

		if($valid_path) {
			return $path;
		}else {
			wizard_handle_output("\033[0;31m%$msg\033[0m" . PHP_EOL);
			return false;
		}
	}

	function wizard_verify_path($path) {
		global $active_config;
		
		$valid_path = false;
		if(!$path) $path = $active_config['path_rra'];
		
		if( strpos( $path, '.' ) === 0 ) {
			$msg = "Path is not absolute.";
		}elseif(!is_dir($path)) {
			$msg = "Unknown directory.";
		}elseif(!is_readable($path)) {
			$msg = "Directory is not readable.";
		}elseif(!is_writable($path)) {
			$msg = "Directory is not writeable.";
		}else {
			$valid_path = true;
		}

		if($valid_path) {
			return $path;
		}else {
			wizard_handle_output("\033[0;31m%$msg\033[0m" . PHP_EOL);
			return false;
		}
	}
		
	function wizard_handle_output($msg, $new_line=false, $new_line_after=false, $clear_commandline_screen=false) {
		fwrite(STDOUT, ($clear_commandline_screen ? chr(27) . "[2J" . chr(27) . "[;H" : '' ) . ($new_line ? PHP_EOL : '') . $msg . ($new_line_after ? PHP_EOL : ''));
	}
	
	function wizard_handle_input($msg, $filter=FILTER_DEFAULT, $filter_options=false, $filter_help_msg=false, $new_line=false, $new_line_after=false, $clear_commandline_screen=false) {
		while(1!=0) {
		
			wizard_handle_output($msg . ' ', $new_line, $new_line_after, $clear_commandline_screen);

			$input = trim(fgets(STDIN));
			$filtered_value = filter_var($input, $filter, $filter_options);
			
			if( $filtered_value !== false) {
				return $filtered_value;
			}else {
				if( $filter_help_msg ) {
					wizard_handle_output("\033[0;31m$filter_help_msg\033[0m" . PHP_EOL);
				}
				continue;
			}
		}		
	}
	
?>
