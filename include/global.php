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

define('COPYRIGHT_YEARS', 'Copyright (C) 2004-' . date('Y') . ' The Cacti Group');
define('COPYRIGHT_YEARS_SHORT', '(c) 2004-' . date('Y') . ' - The Cacti Group');

define('RRDP_VERSION', '1.2.8');
define('RRDP_VERSION_FULL', 'RRDtool Proxy Server v' . RRDP_VERSION . ', ' . COPYRIGHT_YEARS . "\r\n");

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

define('ANSI_ESCAPE', "\033[");
define('ANSI_RESET',          ANSI_ESCAPE . '0m');
define('ANSI_BOLD',           ANSI_ESCAPE . '1m');
define('ANSI_FAINT',          ANSI_ESCAPE . '2m');
define('ANSI_ITALIC',         ANSI_ESCAPE . '3m');
define('ANSI_UNDERLINE',      ANSI_ESCAPE . '4m');
define('ANSI_BLINK',          ANSI_ESCAPE . '5m');
define('ANSI_BLINK_FAST',     ANSI_ESCAPE . '6m');
define('ANSI_CONCEAL',        ANSI_ESCAPE . '7m');
define('ANSI_STRIKEOUT',      ANSI_ESCAPE . '8m');
define('ANSI_FONT_DEFAULT',   ANSI_ESCAPE . '9m');
define('ANSI_FONT_ALT1',      ANSI_ESCAPE . '10m');
define('ANSI_FONT_ALT2',      ANSI_ESCAPE . '11m');
define('ANSI_FONT_ALT3',      ANSI_ESCAPE . '12m');
define('ANSI_FONT_ALT4',      ANSI_ESCAPE . '13m');
define('ANSI_FONT_ALT5',      ANSI_ESCAPE . '14m');
define('ANSI_FONT_ALT6',      ANSI_ESCAPE . '15m');
define('ANSI_FONT_ALT7',      ANSI_ESCAPE . '16m');
define('ANSI_FONT_ALT8',      ANSI_ESCAPE . '17m');
define('ANSI_FONT_ALT9',      ANSI_ESCAPE . '18m');
define('ANSI_FONT_ALT10',     ANSI_ESCAPE . '19m');
define('ANSI_FONT_FRAKTUR',   ANSI_ESCAPE . '20m');
define('ANSI_UNDERLINE_DBL',  ANSI_ESCAPE . '21m');
define('ANSI_NORMAL',         ANSI_ESCAPE . '22m');
define('ANSI_NO_ITL_FRAK',    ANSI_ESCAPE . '23m');
define('ANSI_UNDERLINE_OFF',  ANSI_ESCAPE . '24m');
define('ANSI_BLINK_OFF',      ANSI_ESCAPE . '25m');
define('ANSI_INVERSE_OFF',    ANSI_ESCAPE . '27m');
define('ANSI_REVEAL',         ANSI_ESCAPE . '28m');
define('ANSI_STRIKEOUT_OFF',  ANSI_ESCAPE . '29m');
define('ANSI_BLACK_FG',       ANSI_ESCAPE . '30m');
define('ANSI_BLACK_BG',       ANSI_ESCAPE . '40m');
define('ANSI_RED_FG',         ANSI_ESCAPE . '31m');
define('ANSI_RED_BG',         ANSI_ESCAPE . '41m');
define('ANSI_GREEN_FG',       ANSI_ESCAPE . '32m');
define('ANSI_GREEN_BG',       ANSI_ESCAPE . '42m');
define('ANSI_YELLOW_FG',      ANSI_ESCAPE . '33m');
define('ANSI_YELLOW_BG',      ANSI_ESCAPE . '43m');
define('ANSI_BLUE_FG',        ANSI_ESCAPE . '34m');
define('ANSI_BLUE_BG',        ANSI_ESCAPE . '44m');
define('ANSI_MAGENTA_FG',     ANSI_ESCAPE . '35m');
define('ANSI_MAGENTA_BG',     ANSI_ESCAPE . '45m');
define('ANSI_CYAN_FG',        ANSI_ESCAPE . '36m');
define('ANSI_CYAN_BG',        ANSI_ESCAPE . '46m');
define('ANSI_WHITE_FG',       ANSI_ESCAPE . '37m');
define('ANSI_WHITE_BG',       ANSI_ESCAPE . '47m');
define('ANSI_ERASE_TO_END',   ANSI_ESCAPE . '0J');
define('ANSI_ERASE_TO_BEGIN', ANSI_ESCAPE . '1J');
define('ANSI_ERASE_SCREEN',   ANSI_ESCAPE . '2J');
define('ANSI_ERASE_BUFFER',   ANSI_ESCAPE . '3J');
define('ANSI_POS_TOP_LEFT',   ANSI_ESCAPE . ';H');

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
    'prompt'         => ANSI_GREEN_FG,    #green
    'debug'          => ANSI_CYAN_FG,     #cyan
    'normal'         => ANSI_GREEN_FG,    #green
    'informational'  => ANSI_BLUE_FG,     #blue
    'notification'   => ANSI_WHITE_FG,    #white
    'warning'        => ANSI_YELLOW_FG,   #yellow
    'error'          => ANSI_RED_FG,      #red
    'critical'       => ANSI_MAGENTA_FG,  #magenta
    'alert'          => ANSI_MAGENTA_BG,  #magenta background
    'emergency'      => ANSI_RED_BG,      #red background
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
    'version',
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

$rrdp_aliases = array('?' => 'list', 'help' => 'list', 'exit' => 'quit');

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
                        'info'	=> 'Administrate RRDtool Proxy Server clients',
                        '?'		=> array(
                            'add'	=> 'Add trusted client connection',
                            'remove'=> 'Delete trusted client connection entry',
                        ),
                    ),
                    'cluster'	=> array(
                        'info'	=> 'Administrate RRDtool Proxy Server Cluster Peers',
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
