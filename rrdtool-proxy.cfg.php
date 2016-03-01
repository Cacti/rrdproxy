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

/* RRDtool-Proxy Configuration */
$rrdp_config['name']                = 'rrdp';                                           # set prompt
$rrdp_config['address']             = 0;                                                # per default listen to all interfaces for incoming connections
$rrdp_config['default_port']        = 40301;                                            # port listening for RRDtool requests
$rrdp_config['service_port']        = 40303;                                            # port listening for administration
$rrdp_config['max_cnn']             = 10000;                                            # maximum number of concurrent RRDtool requests
$rrdp_config['max_srv_cnn']         = 5;                                                # maximum number of concurrent Admin sessions
$rrdp_config['backlog']             = 10000;                                            # maximum number of requests being on hold while system is out of resources
$rrdp_config['logging_buffer']      = 10000;                                            # number log messages cached in memory
$rrdp_config['remote_cnn_timeout']  = 5;                                                # default remote client connection timeout value in seconds.
                                                                                        # If set to NULL timeout would be disabled per default. 
                                                                                        # Clients can modify this parameter with 'setcnn timeout <value>'
                                                                                        # to modify this value and / or make the connection persistent
																						

/* RRDtool Binary Paths */
$rrdp_config['path_rrdtool']        = '/usr/bin/rrdtool';                               # absolute(!) path to the RRDtool binary

/* RRDtool Absolute Storage Path */
$rrdp_config['path_rra']            = '/rra/';                                          # absolute(!) path to the RRD archive folder

/* White list of administrative clients */
#  every server / client that is allowed to connect to admin interface of the RRDtool proxy needs to be listed here
$rrdp_config['srv_clients'][]       = '::ffff:127.0.0.1';
$rrdp_config['srv_clients'][]       = '127.0.0.1';

/* MSR configuration */
$rrdp_config['server_id']           = 0;                                                # A server ID higher or equal 1 has to be defined to enable the
                                                                                        # master slave replication through the service interface.
                                                                                        # As long as both proxy servers are available, the server with the lowest ID
                                                                                        # will automatically run in active mode (MASTER) while the other becomes the
                                                                                        # slave (recovery mode). To modify the server ID the proxy needs to 
                                                                                        # be restarted. If a virgin slave will be connected to an existing master 
                                                                                        # a full sync gets triggered automatically
