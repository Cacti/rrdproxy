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
global $active_config;

$active_config = array(
	'version' => RRDP_VERSION,
	'name' => 'rrdp',
	'ip_version' => 4,
	'address_4' => '0.0.0.0',
	'address_6' => '::',
	'port_client' => 40301,
	'port_server' => 40302,
	'port_admin' => 40303,
	'max_admin_cnn' => 5,
	'remote_cnn_timeout' => 30,
	'logging_size_buffered' => 10000,
	'logging_size_snmp' => 10000,
	'logging_severity_buffered' => 5,
	'logging_severity_snmp' => 5,
	'logging_severity_terminal' => 0,
	'logging_severity_console' => 0,
	'logging_category_console' => 'all',
	'path_rra' => realpath('./rra'),
	'path_rra_archive' => realpath('./archive'),
	'path_rrdtool' => '/usr/bin/rrdtool',
	'path_rrdcached' => '/usr/bin/rrdcached',
	'rrdcache_update_cycle' => 600,
	'rrdcache_update_delay' => 0,
	'rrdcache_life_cycle' => 7200,
	'rrdcache_write_threads' => 4,
	'enable_password' => '',
);

wizard();

function wizard() {

	global $microtime_start, $active_config;

	/* include external libraries */
	set_include_path("./include/phpseclib/");
	require_once('Math/BigInteger.php');
	require_once('Crypt/Base.php');
	require_once('Crypt/Hash.php');
	require_once('Crypt/Random.php');
	require_once('Crypt/RSA.php');
	require_once('Crypt/Rijndael.php');

	#### -- WELCOME -- ####
	wizard_handle_title(1, 'Welcome');
	wizard_handle_output( rrdp_get_cacti_proxy_logo(), true, true);

	$msg = 'Welcome to the Wizard of the RRDtool Proxy Server, brought to you by the Cacti Group. ' . PHP_EOL . PHP_EOL
		. 'This tool allows you to setup the RRDtool Proxy Server for the first time as well or to reconfigure an existing configuration. '
		. 'You can abort this script anytime with CTRL+C and restart this wizard with the command: ';
	wizard_handle_output( wordwrap($msg, 75), true, true);

	$msg = ANSI_BOLD . '<path_to_php> ./rrdtool-proxy.php --wizard' . ANSI_RESET;
	wizard_handle_output( wizard_prompt_wordwrap('Example', $msg, 75), true, true);

	$msg = 'When editing a value, any existing or default value will be shown in square brackets. '
		. 'To accept these, simply press ENTER to reuse them. ' . PHP_EOL . PHP_EOL
		. 'Once the configuration file has been updated, any running instance of RRDtool '
		. 'Proxy Server will need to be restarted to pick these changes up.';
	wizard_handle_output( wordwrap($msg, 75), true, true);

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input(ANSI_BOLD . "Press ENTER to continue ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;

	#### -- SYSTEM REQUIREMENTS -- ####
	wizard_handle_title(2,'Requirements');
	wizard_handle_output(rrdp_get_cacti_proxy_logo(), true, true);

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
	exec("ip addr show | grep -v '127.0.0.1' | grep -Po '(inet \K[\d.]+)'", $network_interfaces_4);
	exec("ip addr show | grep -v '::1' |  grep -v 'fe80::' | grep -Po '(inet6 \K[a-z0-9:]+)'", $network_interfaces_6);
	$network_interfaces = $network_interfaces_4 + $network_interfaces_6;

	rrd_system__system_boolean_message( 'test: network interfaces [' . __sizeof($network_interfaces) . ']', $network_interfaces, true);

	$system__ipv4_supported = defined('AF_INET');
	rrd_system__system_boolean_message( 'test: ipv4 supported', $system__ipv4_supported);
	$system__ipv6_supported = defined('AF_INET6');
	rrd_system__system_boolean_message( 'test: ipv6 supported', $system__ipv6_supported);

	wizard_handle_output(PHP_EOL . 'Checking System Configurations...', true);
	$system__include_folder_writeable = is_readable('./include');
	rrd_system__system_boolean_message( 'test: Include folder is readable', $system__include_folder_writeable, true );

	$system__include_folder_writeable = is_writable('./include');
	rrd_system__system_boolean_message( 'test: Include folder is writeable', $system__include_folder_writeable, true );

	$system__config = file_exists('./include/config');
	if($system__config) {
		include('./include/config');
		$system__config = (isset($rrdp_config) && is_array($rrdp_config));
	}
	rrd_system__system_boolean_message( 'read: RRDtool Proxy Server configuration file', $system__config, false );


	$system__config_tmp = file_exists('./include/config.tmp');
	if($system__config_tmp) {
		include('./include/config.tmp');
		$system__config_tmp = (isset($rrdp_config_tmp) && is_array($rrdp_config_tmp));
	}
	rrd_system__system_boolean_message( 'read: RRDtool Proxy Server temporary configuration file', $system__config_tmp, false );

	$system__public_key = file_exists('./include/public.key');
	rrd_system__system_boolean_message( 'read: RSA public key', $system__public_key, false );
	$system__private_key = file_exists('./include/private.key');
	rrd_system__system_boolean_message( 'read: RSA private key', $system__private_key, false );
	$system__proxies = file_exists('./include/proxies');
	rrd_system__system_boolean_message( 'read: Server configuration', $system__proxies, false );
	$system__clients = file_exists('./include/clients');
	rrd_system__system_boolean_message( 'read: Client configuration', $system__clients, false );

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input( PHP_EOL . ANSI_BOLD . "Press ENTER to continue ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;


	#### -- DATA ENCRYPTION -- ####
	wizard_handle_title(3,'Security');
	wizard_handle_output(rrdp_get_cacti_proxy_logo(), true, true);

	$microtime_start = microtime(true);		// reset system start time

	if($system__public_key & $system__private_key) {
		$msg = 'All RRDtool Proxy Server communications between client and proxy, or proxy and proxy, '
			. 'are encrypted for security reasons. The only unencrypted connections that can be made '
			. 'are to the local CLI port as these are not transmitted over the network. ' . PHP_EOL . PHP_EOL
			. 'For more technical information, the data that is transmitted over the wider network is '
			. 'encrypted by single-use AES keys of 192Bit with 2048Bit RSA used for the key exchange. ';
		wizard_handle_output(wordwrap($msg, 75), true, true);

		$msg = 'This version of RRDtool Proxy Server does currently not have an embedded RSA key rotation '
			. 'process so the same RSA key is used for the lifetime of the process.';
		wizard_handle_output(wizard_prompt_wordwrap('Note', $msg, 75), true, true);

		$msg = ANSI_BOLD . ANSI_GREEN_FG . "**RSA key-pair detected:"
			. PHP_EOL . "  Public Key  (last updated: " . date ("F d Y H:i:s", filemtime('./include/public.key')) . ")"
			. PHP_EOL . "  Private Key (last updated: " . date ("F d Y H:i:s", filemtime('./include/private.key')) . ")" . ANSI_RESET;

		wizard_handle_output(wordwrap($msg, 75), true, true);

		$msg = ANSI_BOLD . "Would you like to reuse the existing RSA key-pair? [y/n]" . ANSI_RESET;
		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true, false, false, true) );
		$microtime_start = microtime(true);	// reset system start time
		if($input == 'Y') {
			rrd_system__system_boolean_message( 'load: RSA public key', $system__public_key, true );
			rrd_system__system_boolean_message( 'load: RSA private key', $system__private_key, true );
			$refresh_rsa_keys = false;
		} else {
			rrd_system__system_boolean_message( 'delete: Old RSA public key', unlink('./include/public.key'), true );
			rrd_system__system_boolean_message( 'delete: Old RSA private key', unlink('./include/private.key'), true );
			$refresh_rsa_keys = true;
		}
	} else {
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
	wizard_handle_input( PHP_EOL . ANSI_BOLD . "Press ENTER to continue ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;

	#### -- SYSTEM Parameters -- ####
	wizard_handle_title(4,'System Parameters');
	wizard_handle_output(rrdp_get_cacti_proxy_logo(), true, true);

	$msg = 'This section allows to modify different system and connection parameters of RRDtool Proxy Server. ' . PHP_EOL . PHP_EOL
		. 'If you are unsure whether you should modify a value, the default or current value may be shown in square brackets, eg [' . ANSI_BOLD . ANSI_YELLOW_FG . 'rrdp' . ANSI_RESET . ']' . PHP_EOL . PHP_EOL
		. 'The shown default can be accepted by pressing ';
	wizard_handle_output( wordwrap($msg, 75) . ANSI_BOLD . ANSI_YELLOW_FG . 'ENTER' . ANSI_RESET, true, true);

	if($system__config_tmp) {
		$msg = ANSI_BOLD . ANSI_GREEN_FG . "**Temporary Wizard Configuration detected:"
			. PHP_EOL . "  Temporary configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/config.tmp')) . ")" . ANSI_RESET;
		wizard_handle_output( wordwrap($msg, 75), true, true);

		$msg = ANSI_BOLD . "Would you like to reload all configuration parameters of your last wizard session? [y/n]" . ANSI_RESET;
		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
		$microtime_start = microtime(true);	// reset system start time
		if($input == 'Y') {
			$old_config = $rrdp_config_tmp;
			rrd_system__system_boolean_message( 'restore: Temporary session data', $old_config, true );
		} else {
			$status = unlink('./include/config.tmp');
			rrd_system__system_boolean_message( ' delete: Temporary session data', $status, false );
		}
		unset($rrdp_config_tmp);
		wizard_handle_output( '', true, true);
	}

	if($system__config) {
		$msg = ANSI_BOLD . ANSI_GREEN_FG . "**RRDtool Proxy Server - Configuration detected:"
			. PHP_EOL . "  Configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/config')) . ")" . ANSI_RESET;
		wizard_handle_output( wordwrap($msg, 75), true, true);

		$msg = ANSI_BOLD . "Would you like to reload all parameters of this configuration file? " . ($system__config_tmp ? '(Note: This will overwrite one or more attributes of session data being restored one step before.) ' : '' ) . "[y/n]" . ANSI_RESET;
		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
		$microtime_start = microtime(true);	// reset system start time
		if($input == 'Y') {
			$old_config = $rrdp_config;
			rrd_system__system_boolean_message( 'restore: System Configuration', $old_config, true );
		} else {
			$status = unlink('./include/config');
			rrd_system__system_boolean_message( ' delete: System Configuration', $status, false );
		}
		unset($rrdp_config);
	}

	/* neither a final nor a temporary system configuration file have been found */
	if(isset($old_config)) {
		if(array_key_exists('version', $old_config)) {
			unset($old_config['version']);
		}
		foreach($old_config as $index => $value) {
			if (isset($active_config[$index])) {
				$active_config[$index] = $value;
			}
		}
	}

	$rrdp_default_config_inputs = array(
		'name' => array(
			'msg' => "Enter the system prompt or name that RRDtool Proxy Server should display when a user connects via the CLI port.  This has a maximum of 8 characters",
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^[\s|\w]{0,8}$/',
			'help' => '% Only whitespace and wording characters including underscore with a maximum of 8 chars'
		)
	);

	if($system__ipv4_supported & $system__ipv6_supported & $network_interfaces_4 & $network_interfaces_6) {
		$rrdp_default_config_inputs += array(
			'ip_version' => array(
				'msg' => "Your system supports IPv4 as well as IPv6. Choose the protocol RRDtool Proxy Server should use for network connections",
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^(4|6)$/',
				'help' => '% Please enter 4 for IPv4 or 6 for IPv6'
			)
		);
	}

	if($system__ipv4_supported & $network_interfaces_4) {
		$rrdp_default_config_inputs += array(
			'address_4' => array(
				'msg' => "Following IPv4 addresses have been detected on your system:" . PHP_EOL . PHP_EOL . '      '
					. implode(',', $network_interfaces_4) . PHP_EOL . PHP_EOL . '    '
					. 'Using the default value \'0.0.0.0\' allows to listen to all IPv4 interfaces for incoming requests, but it is recommended to choose one of the detected IPs listed above',
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^(0.0.0.0|' . implode('|', $network_interfaces_4) . ')$/',
				'help' => '% Only valid IPv4 addresses or 0.0.0.0'
			)
		);
	}

	if($system__ipv6_supported & $network_interfaces_6) {
		$rrdp_default_config_inputs += array(
			'address_6' => array(
				'msg' => "Following IPv6 addresses have been detected on your system:" . PHP_EOL . PHP_EOL . '      '
					. implode(',', $network_interfaces_6) . PHP_EOL . PHP_EOL . '    '
					. 'Using the default value \'::\' allows to listen to all IPv6 interfaces for incoming requests, but it is recommended to choose one of the detected IPs listed above ',
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^(::|' . implode('|', $network_interfaces_6) . ')$/',
				'help' => '% Only valid IPv6 addresses or ::'
			),
		);
	}

	$rrdp_default_config_inputs += array(
		'port_client' => array(
			'msg' => 'Active clients (like Cacti servers for example) have to connect to the proxy using a dedicated TCP port',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/',
			'help' => '% Only valid port numbers between 1024 and 65535'
		),
		'port_server' => array(
			'msg' => 'Proxy to proxy connections have to run over a separate path using a different port',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/',
			'help' => '% Only valid port numbers between 1024 and 65535'
		),
		'port_admin' => array(
			'msg' => 'Administrators have to connect to the proxy interface locally using a dedicated TCP port',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/',
			'help' => '% Only valid port numbers between 1024 and 65535'
		),
		'max_admin_cnn' => array(
			'msg' => 'Maximum number of concurrent local (admin) sessions being allowed',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^([1-9]|10)$/',
			'help' => '% Range 1 - 10'
		),
		'remote_cnn_timeout' => array(
			'msg' => 'Timeout value for client to proxy connections in seconds',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^([1-9]|1[0-9]|2[0-9]|30)$/',
			'help' => '% Range 1 - 30'
		),
		'logging_size_buffered' => array(
			'msg' => 'Maximum number of log entries this system will keep in a memory buffer',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^([1-9]\d{3,4}|100000)$/',
			'help' => '% Range 1 000 - 100 000'
		),
		'logging_size_snmp' => array(
			'msg' => 'Maximum number of notifications this system will keep in memory',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|^([1-9]\d{3,4}|100000)$/',
			'help' => '% Range 1 000 - 100 000'
		),
		'path_rra' => array(
			'msg' => 'Absolute(!) path to the RRA folder containing all RRDfiles',
			'filter' => FILTER_CALLBACK,
			'filter_options' => 'wizard_verify_path'
		),
		'path_rrdtool' => array(
			'msg' => 'Absolute(!) path to your RRDtool binary',
			'filter' => FILTER_CALLBACK,
			'filter_options' => 'wizard_verify_rrdtool'
		),
		'enable_password' => array(
			'msg' => 'Enable password for CLI elevation',
			'filter' => FILTER_VALIDATE_REGEXP,
			'pattern' => '/^$|(?=.*[A-Z])(?=.*[0-9])(?=.*[a-z]).{8}$/',
			'help' => 'Password must contain 1 upper char, 1 lower char, 1 number, 8 chars minimum',
			'hide_value' => true,
			'required' => true
		),
	);

	$attribute_count = 0;
	wizard_handle_settings($rrdp_default_config_inputs, $active_config, $attribute_count);

	#### -- Archive Settings -- ####
	wizard_handle_title(5,'Archive Parameters');
	$msg = 'RRDtool Proxy Server supports to archive RRD files automatically before '
		. 'their removal. Instead of deleting the related file it will just move it '
		. 'to the archive directory keeping the original subfolder structure. ';
	wizard_handle_output( rrdp_get_cacti_proxy_logo(), true, true);
	wizard_handle_output( wordwrap($msg, 75), true, true);

	$msg = 'The proxy only stores a single instance of an RRD file. Multiple instances '
		. 'will not be supported.';
	wizard_handle_output( wizard_prompt_wordwrap('Note', $msg, 75), true, true);

	$msg = 'If you are running a proxy server cluster then this feature MUST be enabled '
		. 'or disabled on every peer, because the archive itself will be included in '
		. 'the replication process.';
	wizard_handle_output( wizard_prompt_wordwrap('Warning', $msg, 75), true, true);

	$msg = ANSI_BOLD . "Would you like to archive decomissioned RRD files automatically? [y/n]" . ANSI_RESET;

	$pattern = '/[yYnN]/';
	$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
	$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
	if($input == 'Y') {

		$rrdp_archive_config_inputs = array(
			'path_rra_archive' => array(
				'msg' => 'Absolute(!) path to the RRA ARCHIVE folder containing all archived RRDfiles',
				'filter' => FILTER_CALLBACK,
				'filter_options' => 'wizard_verify_path'
			),
		);

		wizard_handle_settings($rrdp_archive_config_inputs, $active_config, $attribute_count, 'Archive');

	} else {
		$active_config['path_rra_archive'] = '';
		file_put_contents('./include/config.tmp', '<?php $rrdp_config_tmp = ' . var_export($active_config, true) . ';');
	}

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input( ANSI_BOLD . "Press ENTER to save new system configuration ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true );
	$microtime_start = microtime(true);	// reset system start time
	rrd_system__system_boolean_message( '   save: New system configuration', file_put_contents('./include/config', '<?php $rrdp_config = ' . var_export($active_config, true) . ';'), true );
	rrd_system__system_boolean_message( ' delete: Temporary session data', unlink('./include/config.tmp'), true );

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input( PHP_EOL . ANSI_BOLD . "Press ENTER to continue ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;

	#### -- Cache Settings -- ####
	wizard_handle_title(6,'Cached Parameters');
	wizard_handle_output(rrdp_get_cacti_proxy_logo(), true, true);

	$msg = 'If you are NOT making use of any other I/O cache like Cacti\'s "Boost" process, '
		. 'you can setup the proxy to manage its own cache using a daemon called '
		. '"RRDcached" that comes with RRDtool itself. ' . PHP_EOL . PHP_EOL
		. 'Using RRDcached can dramatically reduce the I/O load of your file '
		. 'system and avoid, if configured correctly, RRD files from being '
		. 'updated with every update command that is received.';
	wizard_handle_output( wordwrap($msg, 75), true, true);

	$msg = 'RRDcached does NOT SUPPORT updates in combination with both RRDtool flags "--skip-past-updates" '
		. 'and "templates". If you are using the RRDtool Proxy Server as data backend for Cacti, '
		. 'it is strongly recommended to leave this add-on being disabled.';
	wizard_handle_output( wizard_prompt_wordwrap('Warning', $msg, 75), true, true);

	$msg = ANSI_BOLD . "Would you like to enable the use of RRDCached? [y/n]" . ANSI_RESET;

	$pattern = '/[yYnN]/';
	$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
	$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
	if($input == 'Y') {

		$rrdp_rrdcached_config_inputs = array(
			'path_rrdcached' => array(
				'msg' => 'Absolute(!) path to your RRDCached binary',
				'filter' => FILTER_CALLBACK,
				'filter_options' => 'wizard_verify_rrdcached'
			),
			'rrdcache_update_cycle' => array(
				'msg' => 'Threshold in seconds mesaurements of an active polling object will be keept in memory. If breached related cached data will be written to disk.',
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^([1-9]\d{1,3}|10000)$/',
				'help' => '% Range 10 - 10 000'
			),
			'rrdcache_update_delay' => array(
				'msg' => 'A random delay between 0 and x seconds RRDcache will delay writing of each RRD to avoid too many writes being queued simultaneously. By default, there is no delay',
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^(0|[1-9]\d{1}|10)$/',
				'help' => '% Range 0 - 10'
			),
			'rrdcache_life_cycle' => array(
				'msg' => 'Define the number of seconds RRDcached should scan the complete cache to ensure that measurements no longer being updated will be written to disk. This process is CPU intensive and should not be executed too often. Due to that reason a high value of e.g. 7200 is acceptable in most cases',
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^([1-9]\d{3}|10000)$/',
				'help' => '% Range 1 000 - 10 000'
			),
			'rrdcache_write_threads' => array(
				'msg' => 'Specify the number of write threads used for writing RRD files. Increasing this number will allow RRDCached to have more simultaneous I/O requests into the kernel. Default value is 4',
				'filter' => FILTER_VALIDATE_REGEXP,
				'pattern' => '/^$|^([1-9]\d{1}|10)$/',
				'help' => '% Range 1 - 10'
			),

		);

		wizard_handle_settings($rrdp_rrdcached_config_inputs, $active_config, $attribute_count, 'RRDcached');
	} else {
		$active_config['path_rrdcached'] = '';
		file_put_contents('./include/config.tmp', '<?php $rrdp_config_tmp = ' . var_export($active_config, true) . ';');
	}

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input( ANSI_BOLD . "Press ENTER to save new system configuration ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true );
	$microtime_start = microtime(true);	// reset system start time
	rrd_system__system_boolean_message( '   save: New system configuration', file_put_contents('./include/config', '<?php $rrdp_config = ' . var_export($active_config, true) . ';'), true );
	rrd_system__system_boolean_message( ' delete: Temporary session data', unlink('./include/config.tmp'), true );

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input( PHP_EOL . ANSI_BOLD . "Press ENTER to continue ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;

	#### -- Client Connections -- ####
	wizard_handle_title(7,'Trusted Clients');
	wizard_handle_output(rrdp_get_cacti_proxy_logo(), true, true);

	$msg = 'This version does not support the automatic registration of trusted clients, these have '
		. 'to be added manually using either this wizard or the admin CLI console.  To allow a '
		. 'client permission to access RRDs through the RRDtool Proxy Server, its IP address and '
		. 'RSA fingerprint must be registered.';
	wizard_handle_output( wordwrap($msg, 75), true, true);

	$msg = 'Cacti shows its RSA fingerprint in the web console and can be found by navigating '
		. 'to Console -> Utilities -> System Utilites, then looking for RSA Fingerprint on '
		. 'the summary tab';
	wizard_handle_output( wizard_prompt_wordwrap('Example', $msg, 75), true, true);

	$msg = 'Other RRDproxies can be registered in Step 8 and should not be included here as it '
		. 'will not be used.';
	wizard_handle_output( wizard_prompt_wordwrap('Note', $msg, 75), true, true);

	$msg = 'Within the admin CLI console, it is possible to add/remove other clients '
		. 'dynamically. For example, "set client add <IP> <Port> <Fingerprint>"';
	wizard_handle_output( wizard_prompt_wordwrap('Tip', $msg, 75), true, true);

	if($system__clients) {
		$msg = ANSI_BOLD . ANSI_GREEN_FG . "**RRDtool Proxy Server - Trusted Clients detected:"
			. PHP_EOL . "  Configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/clients')) . ")" . ANSI_RESET;
		wizard_handle_output( wordwrap($msg, 75), true, true);

		$msg = ANSI_BOLD . "Would you like to reuse all entries of this configuration file? [y/n]" . ANSI_RESET;
		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
		$microtime_start = microtime(true);	// reset system start time
		if($input == 'Y') {
			include_once('./include/clients');
			rrd_system__system_boolean_message( 'load: Trusted Client Connections', isset($rrdp_remote_clients), true );

			if (__sizeof($rrdp_remote_clients) > 0) {
				wizard_handle_output( '', true, true);
				$output = sprintf(" %-27s %-12s " . PHP_EOL, 'IP Address', 'Fingerprint');
				foreach($rrdp_remote_clients as $ip => $fingerprint) {
					$output .= sprintf(" %-27s %s \r\n", $ip, $fingerprint );
				}
				wizard_handle_output( $output, true, false);
			}

		} else {
			$status = unlink('./include/clients');
			rrd_system__system_boolean_message( ' delete: Trusted Client Connections', $status, false );
		}
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
			if(!__sizeof($rrdp_remote_clients)>0) {
				$msg = ANSI_BOLD . ANSI_YELLOW_FG . '**Warning: You haven\'t defined any trusted client connection yet. External systems will not be able to connect to the proxy.' . ANSI_RESET;
				wizard_handle_output( wordwrap($msg, 75), true, true);
			}
			break;
		} elseif ($input == 'Y') {
			$client_ip = wizard_handle_input('IP:', FILTER_VALIDATE_IP, false, '% Invalid IPv4 or IPv6 address format');
			$client_fingerprint =  wizard_handle_input('Fingerprint:', FILTER_VALIDATE_REGEXP, array("options"=>array("regexp"=>"/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/")), '% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]');
			$rrdp_remote_clients[$client_ip] = $client_fingerprint;
		}
	}

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input( ANSI_BOLD . "Press ENTER to continue ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;


	#### -- Proxy-2-Proxy Connections -- ####
	wizard_handle_title(8,'Trusted Proxies');
	wizard_handle_output(rrdp_get_cacti_proxy_logo(), true, true);

	$msg = 'This version does not support the automatic registration of new proxy cluster members - these have to be defined manually. '
		. 'To decide whether a cluster member has the correct permissions its IP address as well as the fingerprint of its current public RSA key has to be registered to the RRDtool Proxy Server.';
	wizard_handle_output( wordwrap($msg, 75), true, true);

	$msg = 'Within the admin CLI console, it is possible to add/remove other proxies '
		. 'dynamically. For example, "set proxy add <IP> <Port> <Fingerprint>"';
	wizard_handle_output( wizard_prompt_wordwrap('Tip', $msg, 75), true, true);

	if($system__proxies) {
		$msg = ANSI_BOLD . ANSI_GREEN_FG . "**RRDtool Proxy Server - Trusted Proxies detected:"
			. PHP_EOL . "  Configuration file (last updated: "  . date ("F d Y H:i:s", filemtime('./include/proxies')) . ")" . ANSI_RESET;
		wizard_handle_output( wordwrap($msg, 75), true, true);

		$msg = ANSI_BOLD . "Would you like to reuse all entries of this configuration file? [y/n]" . ANSI_RESET;
		$pattern = '/[yYnN]/';
		$filter_options = array("options"=>array("regexp"=>"/[yYnN]/"));
		$input = strtoupper( wizard_handle_input( wordwrap($msg, 75), FILTER_VALIDATE_REGEXP, $filter_options, false, true) );
		$microtime_start = microtime(true);	// reset system start time
		if($input == 'Y') {
			include_once('./include/proxies');
			rrd_system__system_boolean_message( 'load: Trusted Proxy Connections', isset($rrdp_remote_proxies), true );

			if (__sizeof($rrdp_remote_proxies) > 0) {
				wizard_handle_output( '', true, true);
				$output = sprintf(" %-27s %-12s %-12s" . PHP_EOL, 'IP Address', 'Port', 'Fingerprint');
				foreach($rrdp_remote_proxies as $ip => $params) {
					$output .= sprintf(" %-27s %-12s %-12s \r\n", $ip, $params['port'], $params['fingerprint']);
				}
				wizard_handle_output( $output, true, false);
			}

		} else {
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
			break;
		} elseif ($input == 'Y') {
			$client_ip = wizard_handle_input('IP:', FILTER_VALIDATE_IP, false, '% Invalid IPv4 or IPv6 address format');
			$client_port = wizard_handle_input('PORT:', FILTER_VALIDATE_REGEXP, array('options'=>array('regexp'=>'/^$|^(102[4-9]|10[3-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/')), '% Invalid PORT. Range: [1024-65535]');
			$client_fingerprint =  wizard_handle_input('Fingerprint:', FILTER_VALIDATE_REGEXP, array("options"=>array("regexp"=>"/^([a-z0-9]{2}:){15}([a-z0-9]{2})$/")), '% Invalid Fingerprint [expected: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx]');
			$rrdp_remote_proxies[$client_ip] = array('port' => $client_port, 'fingerprint' => $client_fingerprint);
		}
	}

	$filter_options = array('options' => array('regexp' => '/[\s]*/'));
	wizard_handle_input( PHP_EOL . ANSI_BOLD . "Press ENTER to continue ..." . ANSI_RESET, FILTER_VALIDATE_REGEXP, $filter_options, false, true ) ;

	wizard_handle_title(9, 'Finished');
	wizard_handle_output(rrdp_get_cacti_proxy_logo(), true, true);

	$msg = 'RRDtool Proxy Server v' . RRDP_VERSION . ' configuration has now been updated.' . PHP_EOL . PHP_EOL
		. 'You may now ' . (is_rrdtool_proxy_running() ? 're' : '') . 'start RRDtool Proxy Server '
		. 'to pick up the new configuration.  Once started, you may telnet to the admin CLI port via '
		. 'telnet.';
	wizard_handle_output(wordwrap($msg, 75), true, true);

	$msg = 'telnet 127.0.0.1 ' . $active_config['port_admin'] . PHP_EOL;
	wizard_handle_output(wizard_prompt_wordwrap('Example', $msg, 75), true, true);
}

function wizard_verify_rrdtool($path) {
	global $active_config;

	$valid_path = false;
	if(!$path) $path = $active_config['path_rrdtool'];

	/* Get RRDtool version */
	if (strpos( $path, '.' ) === 0) {
		$msg = "Path is not absolute.";
	} elseif (!file_exists($path)) {
		$msg = "File not found";
	} elseif (!is_executable($path)) {
		$msg = "File is not executable.";
	} else {
		$out_array = array();
		exec( escapeshellcmd($path) . ' 2>/dev/null', $out_array);
		if (__sizeof($out_array) > 0) {
			if(strpos($out_array[0], 'RRDtool') !== 0) {
				$msg = "Invalid output.";
			} else {
				if (preg_match('/^RRDtool ([1-9]\.[0-9])/', $out_array[0], $m)) {
					if (version_compare( $m[1], '1.5', '>=')) {
						$valid_path = true;
					} else {
						$msg = "RRDtool version 1.5 or above required.";
					}
				}
			}
		} else {
			$msg = "Invalid output.";
		}
	}

	if($valid_path) {
		return $path;
	} else {
		wizard_handle_output(ANSI_RESET . ANSI_RED_FG . "%$msg" . ANSI_RESET . PHP_EOL);
		return false;
	}
}

function wizard_verify_rrdcached($path) {
	global $active_config;

	$valid_path = false;
	if(!$path) $path = $active_config['path_rrdcached'];

	/* Get RRDtool version */
	if (strpos( $path, '.' ) === 0) {
		$msg = "Path is not absolute.";
	} elseif (!file_exists($path)) {
		$msg = "File not found";
	} elseif (!is_executable($path)) {
		$msg = "File is not executable.";
	} else {
		$valid_path = true;
	}

	if($valid_path) {
		return $path;
	} else {
		wizard_handle_output(ANSI_RESET . ANSI_RED_FG . "%$msg" . ANSI_RESET . PHP_EOL);
		return false;
	}
}

function wizard_verify_path($path) {
	global $active_config;

	$valid_path = false;
	if(!$path) $path = $active_config['path_rra'];

	if (strpos( $path, '.' ) === 0) {
		$msg = "Path is not absolute.";
	} elseif (!is_dir($path)) {
		$msg = "Unknown directory.";
	} elseif (!is_readable($path)) {
		$msg = "Directory is not readable.";
	} elseif (!is_writable($path)) {
		$msg = "Directory is not writeable.";
	} else {
		$valid_path = true;
	}

	if($valid_path) {
		return $path;
	} else {
		wizard_handle_output(ANSI_RESET . ANSI_RED_FG . "%$msg" . ANSI_RESET . PHP_EOL);
		return false;
	}
}

function wizard_handle_output($msg, $new_line=false, $new_line_after=false, $clear_commandline_screen=false) {
	fwrite(STDOUT, ($clear_commandline_screen ? ANSI_ERASE_SCREEN . ANSI_ERASE_BUFFER . ANSI_POS_TOP_LEFT : '' ) . ($new_line ? PHP_EOL : '') . $msg . ($new_line_after ? PHP_EOL : ''));
}

function wizard_handle_input($msg, $filter=FILTER_DEFAULT, $filter_options=false, $filter_help_msg=false, $new_line=false, $new_line_after=false, $clear_commandline_screen=false, $require_value=false) {
	while(1!=0) {

		wizard_handle_output($msg . ' ', $new_line, $new_line_after, $clear_commandline_screen);

		$input = trim(fgets(STDIN));
		$filtered_value = filter_var($input, $filter, $filter_options);
		if ($require_value && empty($filtered_value)) {
			$filtered_value = false;
		}

		if ($filtered_value !== false) {
			return $filtered_value;
		} else {
			if ($filter_help_msg) {
				wizard_handle_output(ANSI_RESET . ANSI_RED_FG . "$filter_help_msg" . ANSI_RESET . PHP_EOL);
			}
			continue;
		}
	}
}

function wizard_get_prompt(&$attribute_count) {
	$attr_part1 = $attribute_count % 26;
	$attr_part2 = ($attribute_count - $attr_part1) / 26;

	$attr_prompt['text'] = ($attr_part2 == 0 ? ' ' : chr($attr_part2 + ord('a'))) . chr($attr_part1 + ord('a')) . ') ';
	$attr_prompt['ansi'] = ANSI_BOLD . ANSI_GREEN_FG . $attr_prompt['text'] . ANSI_RESET;
	$attr_prompt['padding'] = str_repeat(' ', strlen($attr_prompt['text']));

	$attribute_count = $attribute_count + 1;
	return $attr_prompt;
}

function wizard_handle_title($page, $title = '') {
	$title_prefix = "   RRDtool Proxy Server Wizard";
	if (!empty($title)) {
		$title_prefix .= ' - ' .$title;
	}

	$title_suffix = "$page/9   ";
	$title_spaces = strlen($title_prefix) + strlen($title_suffix);
	if ($title_spaces > 75) {
		$title_prefix = substr($title_prefix, 1, 75 - $title_suffix);
		$title_spaces = 75;
	}

	wizard_handle_output(ANSI_BOLD . ANSI_YELLOW_FG . ANSI_BLUE_BG . $title_prefix .
		str_repeat(' ', 80 - $title_spaces) . $title_suffix . ANSI_RESET, false, true, true);
}
function wizard_handle_settings($inputs, &$active_config, &$attribute_count, $title = '') {
	global $rrd_config_tmp;

	if (empty($title)) {
		$title = '';
	} else {
		$title .= ' ';
	}

	wizard_handle_output( PHP_EOL . PHP_EOL . ANSI_BOLD . "RRDtool Proxy Server - ${title}Settings:" . ANSI_RESET . PHP_EOL, false, false);

	foreach( $active_config as $attribute => $value) {
		if(isset($inputs[$attribute])) {

			if(isset($inputs[$attribute]['filter_options'])) {
				$filter_options['options'] = $inputs[$attribute]['filter_options'];
			} else {
				$filter_options = array();
				if($inputs[$attribute]['filter'] == FILTER_VALIDATE_REGEXP) {
					$filter_options = array('options'=>array('regexp'=>$inputs[$attribute]['pattern']));
				}
			}

			$attr_prompt = wizard_get_prompt($attribute_count);
			$attr_suffix = !empty($inputs[$attribute]['hide_value']) ? ':' : PHP_EOL . PHP_EOL . $attr_prompt['padding'] . sprintf('[' . ANSI_BOLD . ANSI_YELLOW_FG . '%s' . ANSI_RESET . ']: ', $value);
			$input = wizard_handle_input( $attr_prompt['ansi'] . wordwrap($inputs[$attribute]['msg'], 75, PHP_EOL . $attr_prompt['padding']) . $attr_suffix, $inputs[$attribute]['filter'], $filter_options, (isset($inputs[$attribute]['help']) ? $inputs[$attribute]['help'] : false), true, false, false, !empty($inputs[$attribute]['required']));
			if($attribute == 'enable_password' && !empty($input)) {
				$input = password_hash($input, PASSWORD_DEFAULT);
			}

			if($input) {
				$active_config[$attribute] = $input;
			}

			// Is this the IP version attribute? (eg, IPv4 or IPv6)
			if($attribute == 'ip_version') {
				// Unset the address for the protocol we are not using
				unset($inputs['address_' . (($active_config[$attribute] == 4) ? 6 : 4)]);
			}

			file_put_contents('./include/config.tmp', '<?php $rrdp_config_tmp = ' . var_export($active_config, true) . ';');
		}
	}
}

function wizard_prompt_wordwrap($prompt, $msg, $length) {
	$prompt = (empty($prompt) ? '' : $prompt . ': ');
	$prompt_len = strlen($prompt);
	return ANSI_BOLD . ANSI_YELLOW_FG . $prompt . ANSI_RESET .
		wordwrap($msg, $length - $prompt_len, PHP_EOL . str_repeat(' ', $prompt_len));
}
