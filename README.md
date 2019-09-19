# rrdproxy

Cacti RRD Proxy is a standalone proxy interface to Tobi Oetiker's great RRDTool.
Main focus of this project is to allow a relocation of RRD files including data replication,
support of Cacti Boost as well as the RRDcached daemon.
RRDtool proxy allows to split Cacti into more different components without the need for NFS.

Due the fact that file transactions are having a high criticality RRDtool proxy only supports
high encrypted connections (RSA2048 + AES192) with continuously changing keys between
the proxy and registered clients / other proxies.

Over a local service port administrators are able to access a separate command line interface
that allows to configure and debug the proxy.


## Contribute

Get involved in development by participating in active development on
[GitHub](https://github.com/Cacti/rrdproxy/).


## Requirements

RRD proxy should be able to run on any Unix-based operating system with
the following requirements:

- PHP 7.1+, 7.3+ recommended, including modules for
    SOCKETS, POSIX, PCNTL, GNU GMP and ZLIB    
- RRDTool 1.5+, 1.7+ recommended

Running as data backend for Cacti requires:
- Cacti 1.2.7

## Usage
At the first go you will automatically run through a setup routine (-w).
```
 php rrdtool-proxy.php --help

 RRDtool Proxy v1.2.7
 Copyright (C) 2004-2019 The Cacti Group
 usage: rrdtool-proxy.php [--wizard] [-w] [--version] [-v]
 Optional:
 -v --version   - Display this help message
 -w --wizard    - Start Configuration Wizard
```

## Command Line Interface
Use '?' to get a list of all commands being supported by the proxy or hints about missing parameters.
```
telnet localhost 40303
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
rrdp>?
  enable          Turn on privileged commands
  help            Display help
  show            Show running system information
  quit            Close terminal session

rrdp>ena
rrdp#sh version

#     ___           _   _     __    __    ___     ___
#    / __\__ _  ___| |_(_)   /__\  /__\  /   \   / _ \_ __ _____  ___   _
#   / /  / _` |/ __| __| |  / \// / \// / /\ /  / /_)/ '__/ _ \ \/ / | | |
#  / /__| (_| | (__| |_| | / _  \/ _  \/ /_//  / ___/| | | (_) >  <| |_| |
#  \____/\__,_|\___|\__|_| \/ \_/\/ \_/___,'   \/    |_|  \___/_/\_\__, |
#                                                                   |___/

 RRDtool Proxy v1.2.7
 Copyright (C) 2004-2019 The Cacti Group
 rrdp uptime is 14 days, 0 hours, 4 minutes, 14 seconds
 Memory usage 0.18872917 % (2026464/1073741824 in bytes)
 a8:29:6a:b7:5d:be:c3:8a:be:13:7a:61:ee:0c:8b:d3
 Process ID: 13996
 Session usage (1/399)

 Server IP [192.168.10.10]
 Administration: [localhost       :40303]
 Replication:    [192.168.10.10   :40302]
 Clients:        [192.168.10.10   :40301]

rrdp#
```

## Missing features

- Data replication has been completed to 95%, but is still not ready
- NET-SNMP pass persistent daemon and MIB needs to written to make proxy stats available through SNMP


