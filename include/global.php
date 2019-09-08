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

define('RRDP_VERSION', '1.2.3');
define('COPYRIGHT_YEARS', 'Copyright (C) 2004-' . date('Y') . ' The Cacti Group');
define('COPYRIGHT_YEARS_SHORT', '(c) 2004-' . date('Y') . ' - The Cacti Group');

define('RRD_OK', 'OK u:0.00');
define('RRD_ERROR', 'ERROR:');

define('SEVERITY_LEVEL_NONE', 0);
define('SEVERITY_LEVEL_EMERGENCY', 1);
define('SEVERITY_LEVEL_ALERT', 2);
define('SEVERITY_LEVEL_CRITICAL', 3);
define('SEVERITY_LEVEL_ERROR', 4);
define('SEVERITY_LEVEL_WARNING', 5);
define('SEVERITY_LEVEL_NOTIFICATION', 6);
define('SEVERITY_LEVEL_INFORMATIONAL', 7);
define('SEVERITY_LEVEL_DEBUG', 8);

define('LOGGING_LOCATION_BUFFERED', 1);
define('LOGGING_LOCATION_SNMP', 2);

define('NOT_CONNECTED', 0);
define('INITIALISING', 1);
define('SYNCING', 2);
define('FULL_SYNCING', 3);
define('CONNECTED', 4);
define('BROKEN', 5);
define('NOT_REACHABLE', 6);

$severity_levels = array(
    0 => 'none',
    1 => 'emergency',
    2 => 'alert',
    3 => 'critical',
    4 => 'error',
    5 => 'warning',
    6 => 'notification',
    7 => 'informational',
    8 => 'debug'
);

$logging_categories = array(
    'none'	=> 'No logging',
    'all'	=> 'All categories',
    'acl'	=> 'Access control',
    'sys'	=> 'Internal system processes',
    'slv'	=> 'Replication Slave processing',
    'mstr'	=> 'Replication Master processing',
    'ipc'	=> 'Client based inter process communication'
);

$process_status = array(
    'RUNNING',
    'CLOSEDOWN_BY_SIGNAL',
    'CLOSEDOWN_BY_TIMEOUT',
    'CLOSEDOWN_BY_VIOLATION',
    'CLOSEDOWN_BY_CLIENT_CMD',
    'CLOSEDOWN_BY_CLIENT_DROP',
    'CLOSEDOWN_BY_AUTHENTICATION_FAILURE',
);

$colors = array(
    'prompt' 		=> 32,		#green
    'debug' 		=> 36,		#cyan
    'normal' 		=> 32,		#green
    'informational'	=> 34,		#blue
    'notification' 	=> 37,		#white
    'warning' 		=> 33,		#yellow
    'error' 		=> 31,		#red
    'critical' 		=> 35,		#magenta
    'alert'			=> 45,		#magenta background
    'emergency' 	=> 41,		#red background
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
    'filemtime',
    'is_dir',
    'mkdir',
    'rmdir',
    'unlink',
    'rrd-list',
    'archive',
    'removespikes',
);

$rrdp_client_cnn_params = array(
    'timeout',
    'encryption',
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
    'mkdir',
    'rmdir',
    'unlink',
    'archive',
);

$rrdp_replicator_cmds = array(
    'REQUEST_SCANDIR',
    'REQUEST_DUMP',
    'REQUEST_LASTUPDATE',
    'REQUEST_DIFF',
    'RESPONSE_SCANDIR',
    'RESPONSE_DUMP',
    'RESPONSE_LASTUPDATE',
    'RESPONSE_DIFF',
);

$rrdp_process_types = array(
    'S' => 'replication slave',
    'M' => 'replication master',
    'C' => 'client'
);

$rrdp_aliases = array('?' => 'list', 'exit' => 'quit');

$rrdp_help_messages = array(
    '?' => array(
        0 => array(
            'enable'   	=> 'Turn on privileged commands',
            'reset'		=> 'Reset terminal screen',
            'show'		=> array(
                'info' 	=> 'Show running system information',
                '?' 	=> array(
                    'status'	=> 'Return system status',
                    'threads'	=> 'Display currently open connections',
                    'version'	=> 'System software status',
                )
            ),
            'quit'		=> 'Close terminal session',
        ),
        1 => array(
            'clear'		=> array(
                'info'	=> 'Clear functions for internal buffers',
                '?' 	=> array(
                    'logging'	=> array(
                        'info'	=> 'Clear logging buffer',
                        '?' 	=> array(
                            'buffered'	=> 'Clear buffered log Cache',
                            'snmp'		=> 'Clear SNMP log Cache'
                        ),
                    ),
                    'counters' => 'Clear system counters',
                ),
            ),
            'disable'  	=> 'Turn off privileged commands',
            'reset'		=> 'Reset terminal screen',
            'set'		=> array(
                'info'	=> 'Configure proxy settings',
                '?'		=> array(
                    'rsa'	=> array(
                        'info'	=> 'Administrate encryption parameters',
                        '?'		=> array(
                            'keys'		=> 'Generate new RSA key pair'
                        ),
                    ),
                    'client'	=> array(
                        'info'	=> 'Administrate RRDproxy clients',
                        '?'		=> array(
                            'add'	=> 'Add trusted client connection',
                            'remove'=> 'Delete trusted client connection entry',
                        ),
                    ),
                    'cluster'	=> array(
                        'info'	=> 'Administrate RRDproxy Cluster Peers',
                        '?'		=> array(
                            'add'	=> 'Add a trusted peer',
                            'remove'=> 'Remove a trusted peer connection',
                            'update'=> 'Update IP address or fingerprint of a registered peer',
                        ),
                    ),
                    'logging'	=> array(
                        'info'	=> 'Administrate logging locations and levels',
                        '?'		=> array(
                            'buffered'	=> array(
                                'info' => 'Set GLOBAL buffered logging severity level (default:5)', '?' => array_slice($severity_levels,0,8)
                            ),
                            'snmp'		=> array(
                                'info' => 'Set GLOBAL SNMP logging severity level (default:5)', '?' => array_slice($severity_levels,0,8)
                            ),
                            'terminal'	=> array(
                                'info' => 'Set LOCAL terminal logging severity level (default:0) and categories (default: none)',
                                '?' => array(
                                    'level' => array(
                                        'info' 	=> 'Numerical repesentation of the severity level [0-8]',
                                        '?'		=> $severity_levels
                                    ),
                                    'category' => array(
                                        'info'	=> 'Set logging category (default: all)',
                                        '?'		=> $logging_categories
                                    ),
                                ),
                            ),
                            'console'	=> array(
                                'info' => 'Set LOCAL terminal logging severity level (default:0) and categories',
                                '?' => array(
                                    'level' => array(
                                        'info' 	=> 'Numerical repesentation of the severity level [0-8]',
                                        '?'		=> $severity_levels
                                    ),
                                    'category' => array(
                                        'info'	=> 'Select one or more (comma separated) logging categories (default: none)',
                                        '?'		=> $logging_categories
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            'show'		=> array(
                'info'	=> 'Show running system information',
                '?' 	=> array(
                    'clients'	=> 'List all trusted client connections',
                    'counters'	=> 'Return all system counters',
                    'cluster'	=> 'List all trusted cluster peers',
                    'logging'	=> array(
                        'info'	=> 'Display state of logging',
                        '?'		=> array(
                            'status'	=> 'Show logging overview',
                            'buffered'	=> 'List buffered log entries',
                            'snmp'		=> 'Display SNMP logs'
                        )
                    ),
                    'msr'		=> array(
                        'info'	=> 'Display replication state',
                        '?'		=> array(
                            'buffer' => 'Display current replication buffer',
                            'health' => 'Health status',
                            'status' => 'Show current state of the MSR process',
                        ),
                    ),
                    'processes' => 'Display running child processes',
                    'rsa'		=> array(
                        'info'	=> 'Show Encryption setup',
                        '?'		=> array(
                            'publickey' => 'Display current public key and fingerprint',
                        ),
                    ),
                    'threads'	=> 'Display currently open connections',
                    'variables' => 'Show Current Operating configuration',
                    'version'	=> 'System software status',
                )
            ),
            'shutdown'  => 'Close all connections and shut down proxy',
            'quit'		=> 'Close terminal session',
        ),
    ),
);

$rrdp_status = array(
    'aborted_clients' => 0,
    'bytes_received' => 0,
    'bytes_sent' => 0,
    'connections' => 0,
    'max_admin_connections' => 0,
    'max_client_connections' => 0,
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
    'connections_refused' => 0,
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
    'proc_closedown_by_decryption' => 0,
    'proc_closedown_by_client_auth' => 0,
    'rra_disk_size' => 0,
    'rra_disk_used' => 0,
    'rra_disk_avail' => 0,
    'msr_disk_size' => 0,
    'msr_disk_used' => 0,
    'msr_disk_avail' => 0,
);

$rrdp_validate_filters = array(
    FILTER_VALIDATE_BOOLEAN,
    FILTER_VALIDATE_EMAIL,
    FILTER_VALIDATE_FLOAT,
    FILTER_VALIDATE_INT,
    FILTER_VALIDATE_IP,
    FILTER_VALIDATE_MAC,
    FILTER_VALIDATE_REGEXP,
    FILTER_VALIDATE_URL
);