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

define('RRDP_VERSION', '1.0');
define('RRDP_NOTICE', 3);
define('RRDP_WARNING', 2);
define('RRDP_ERROR', 1);

$process_status = array(
	'RUNNING',
	'CLOSEDOWN_BY_SIGNAL',
	'CLOSEDOWN_BY_TIMEOUT',
	'CLOSEDOWN_BY_VIOLATION',
	'CLOSEDOWN_BY_CLIENT_CMD',
	'CLOSEDOWN_BY_CLIENT_DROP',
	'CLOSEDOWN_BY_AUTHENTICATION_FAILURE',
);

$color_theme = array(
	'prompt' => 32,				#green
	'debug_normal' => 32,		#green
	'debug_prompt' => 36,		#cyan
	'debug_notice' => 37,		#white
	'debug_warning' => 35,		#purple
	'debug_error' => 31,		#red
	'debug_critical' => 33,		#yellow
);

$rrdtool_env_vars = array(
	'RRD_DEFAULT_FONT', 
	'RRDCACHED_STRIPPATH',
);


$rrdtool_custom_cmds = array(
	'setenv',
	'getenv',
	'fc-list',
	'setcnn',
	'file_exists',
	'is_dir',
	'mkdir',
);

$rrdp_client_cnn_params = array(
	'timeout',
);

$rrdtool_cmds = array(
	'create', 
	'update', 
	'updatev', 
	'graph', 
	'graphv', 
	'dump', 
	'restore', 
	'last', 
	'lastupdate', 
	'first', 
	'info', 
	'fetch', 
	'tune', 
	'resize', 
	'xport', 
	'flushcached',
);

$rrdtool_msr_cmds = array(
	'create',
	'update',
	'updatev',
	'restore',
	'tune',
	'resize',
	'mkdir'
);

$rrdp_aliases = array('sh' => 'show', '?' => 'list', 'ena' => 'enable', 'exit' => 'quit');


$rrdp_help_messages = array(
	'?' => array(
		0 => array(
			'enable'   	=> 'Turn on privileged commands',
			'help'		=> 'Display help',
			'show'		=> 'Show running system information',
			'quit'		=> 'Close terminal session',
		),
		1 => array(
			'clear'		=> 'Reset functions',
			'debug'		=> 'Turn on/off debug mode', 
			'disable'  	=> 'Turn off privileged commands',
			'help'		=> 'Display help',
			'set'		=> 'Configure proxy settings',
			'show'		=> 'Show running system information',
			'shutdown'  => 'Close all connections and shut down proxy',
			'quit'		=> 'Close terminal session',
		),
	),
	'clear' => array(
		'?' => array(
			1 => array(
				'logging' => 'Clear logging buffer',
				'counters' => 'Clear system counters',
			)
		)
	),
	'show' => array(
		'?' => array(
			0 => array(
				'status'	=> 'Return system status',
				'threads'	=> 'Display currently open connections',
				'version'	=> 'System software status',
			),
			1 => array(
				'logging'	=> 'Show logging buffer',
				'msr'       => array(
					'info' => 'Display replication state',
					'?' => array(
						'buffer' => 'Display current replication buffer',
						'health' => 'Health status',
						'status' => 'Show current state of the MSR process',
					),
				),
				'processes' => 'Display running child processes',
				'rsa'		=> array(
					'info' => 'Show Encryption setup',
					'?' => array(	
						'publickey' => 'Display current public key and fingerprint',
						'clients'	=> 'List all trusted client connections',
					),
				),
				'status'	=> 'Return system statistics',
				'threads'	=> 'Display currently open connections',
				'variables' => 'Show Current Operating configuration',
				'version'	=> 'System software status',
			)
		)
	),
	'set' => array(
		'?' => array(
			1 => array(
				'rsa'		=> array(
					'info' => 'Administrate encryption parameters',
					'?' => array(
						'keys'		=> 'Generate new RSA key pair',
						'add'		=> 'Add trusted client connection',
						'remove'	=> 'Delete trusted client connection entry',
					),
				),
				'msr'		=> array(
					'info' => 'Administrate Master Slave replication',
					'?' => array(
						'add'		=> 'Add trusted client connection',
						'remove'	=> 'Delete trusted client connection entry',
						'heartbeat' => 'Maximum time interval in seconds between two keep-alive packets',
					),
				),
			),
			
		)
	),
	'debug' => array(
		'?' => array(
			1 => array(
				'on'			=> 'Enable debug mode',
				'off' 			=> 'Disable debug mode',
			)
		)
	),
	
);

$rrdp_status = array(
	'aborted_clients' => 0,
	'aborted_connects' => 0,
	'bytes_received' => 0,
	'bytes_sent' => 0,
	'connections' => 0,
	'max_used_connections' => 0,
	'memory_usage' => 'live',
	'memory_peak_usage' => 'live',
	'queries_rrdtool_total' => 0,
	'queries_rrdtool_valid' => 0,
	'queries_rrdtool_invalid' => 0,
	'queries_system' => 0,
	'threads_connected' => 'live',
	'uptime' => 'live',
	'connections_open' => 'live',
	'connections_closed' => 0,
	'connections_timeout' => 0,
	'connections_broken' => 0,
	'connections_aborted' => 0,
	'msr_bytes_received' => 0,
	'msr_bytes_sent' => 0,
	'msr_connection_broken' => 0,
	'rrd_pipe_broken' => 0,
	'srv_bytes_received' => 0,
	'srv_bytes_sent' => 0,
	'srv_connection_broken' => 0,
	'proc_closedown_by_signal' => 0,
	'proc_closedown_by_timeout' => 0,
	'proc_closedown_by_violation' => 0,
	'proc_closedown_by_client_cmd' => 0,
	'proc_closedown_by_client_drop' => 0,
	'proc_closedown_by_encryption' => 0,
	'proc_closedown_by_client_auth' => 0,
);

$rrdp_encryption		= array();
$rrdp_remote_clients	= array();

?>